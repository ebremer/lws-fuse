package com.ebremer.lws.fuse.auth;

import com.nimbusds.jwt.JWTParser;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The LWS authorization client (LWS core, Authorization): obtains access tokens for a storage by
 * exchanging an authentication credential at the authorization server the storage names.
 * <ol>
 *   <li>A request without a token draws a {@code 401} whose {@code WWW-Authenticate: Bearer}
 *       challenges carry {@code as_uri} (an authorization server) and {@code realm} (the scope of
 *       protection). The first challenge whose realm contains the request's URI and whose
 *       authorization server is acceptable is used.</li>
 *   <li>The authorization server's metadata is read from {@code /.well-known/lws-configuration}
 *       (RFC 8414); its {@code issuer} must be {@code as_uri}.</li>
 *   <li>A credential from the {@link CredentialSource} (an OpenID ID token, a self-issued CID JWT,
 *       a SAML assertion), addressed to that issuer, is exchanged at its token endpoint (RFC 8693:
 *       {@code grant_type=urn:ietf:params:oauth:grant-type:token-exchange}, {@code resource=}realm).
 *       A credential type the server's {@code subject_token_types_supported} leaves out is not sent.</li>
 *   <li>The {@code Bearer} access token is sent as {@code Authorization: Bearer} on every request
 *       within the realm, and exchanged again shortly before it expires or when the storage
 *       rejects it.</li>
 * </ol>
 * One token is kept per realm. A token the storage rejects within seconds of being issued is not
 * replaced (that means "not permitted", not "expired").
 *
 * <p>Servers following earlier drafts send no {@code as_uri} challenge; for them, the
 * {@code fallback} provider (if any) presents its credential directly, as before. This is decided
 * per origin, and never for an origin that has sent an LWS challenge.
 *
 * <p>An authorization server is only contacted over {@code https} (or {@code http} on a loopback
 * address); {@code pinnedAuthorizationServer}, when set, is the only one accepted.
 *
 * @author Erich Bremer
 */
public final class LwsAuthProvider implements AuthProvider {

    private static final Logger log = LoggerFactory.getLogger(LwsAuthProvider.class);
    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";
    private static final Duration EXPIRY_SKEW = Duration.ofSeconds(30);
    private static final Duration MIN_TOKEN_AGE_FOR_RENEWAL = Duration.ofSeconds(10);
    private static final Duration DEFAULT_LIFETIME = Duration.ofMinutes(5);
    /** The ID token type as the LWS metadata example spells it; RFC 8693 and the OpenID suite use {@code id_token}. */
    private static final String ID_TOKEN_HYPHENATED = "urn:ietf:params:oauth:token-type:id-token";

    /** An access token for one realm. */
    private record Grant(URI realm, URI authorizationServer, String accessToken, Instant expiresAt, Instant obtainedAt) {}

    /** What this client needs from authorization server metadata. */
    record ServerMetadata(URI issuer, URI tokenEndpoint, List<String> subjectTokenTypes, List<String> subjectIdentifierTypes) {}

    private final HttpClient http;
    private final CredentialSource source;
    private final AuthProvider fallback;
    private final Duration timeout;
    private final URI pinnedAuthorizationServer;
    private final Map<String, Grant> grants = new ConcurrentHashMap<>();
    private final Map<String, Object> locks = new ConcurrentHashMap<>();
    private final Map<String, ServerMetadata> metadata = new ConcurrentHashMap<>();
    private final Set<String> warnings = ConcurrentHashMap.newKeySet();
    /** Origins that sent a 401 without an LWS challenge (earlier drafts): they get the fallback. */
    private final Set<String> fallbackOrigins = ConcurrentHashMap.newKeySet();
    /** Origins that sent an LWS challenge: never given the fallback credential. */
    private final Set<String> lwsOrigins = ConcurrentHashMap.newKeySet();
    /** See {@link #MIN_TOKEN_AGE_FOR_RENEWAL}; adjustable for tests. */
    volatile Duration minTokenAgeForRenewal = MIN_TOKEN_AGE_FOR_RENEWAL;

    /**
     * @param source                    the authentication credentials to exchange
     * @param fallback                  presents a credential directly to servers that send no LWS
     *                                  challenge (earlier drafts); {@code null} for none
     * @param pinnedAuthorizationServer if non-null, the only authorization server to use
     */
    public LwsAuthProvider(HttpClient http, CredentialSource source, AuthProvider fallback,
                           Duration timeout, URI pinnedAuthorizationServer) {
        this.http = http;
        this.source = source;
        this.fallback = fallback;
        this.timeout = timeout;
        this.pinnedAuthorizationServer = pinnedAuthorizationServer;
    }

    @Override
    public void authorize(HttpRequest.Builder builder, String method, URI uri) {
        Grant g = grantFor(uri);
        if (g != null) {
            if (!isFresh(g)) {
                g = renew(g);
            }
            builder.setHeader("Authorization", "Bearer " + g.accessToken());
            return;
        }
        if (fallback != null && fallbackOrigins.contains(origin(uri))) {
            fallback.authorize(builder, method, uri);
        }
        // Otherwise the request goes out without credentials; a 401 names the authorization server.
    }

    @Override
    public void onResponse(HttpResponse<?> response) {
        if (fallback != null && fallbackOrigins.contains(origin(response.request().uri()))) {
            fallback.onResponse(response);
        }
    }

    @Override
    public boolean onUnauthorized(HttpResponse<?> response) {
        URI requestUri = response.request().uri();
        String origin = origin(requestUri);
        List<Challenges.Challenge> challenges = lwsChallenges(response);
        if (challenges.isEmpty()) {
            if (fallback == null) {
                return false;
            }
            if (lwsOrigins.contains(origin)) {
                warnOnce("nochallenge:" + origin, "{} answered 401 without an LWS challenge, but it uses LWS "
                        + "authorization; not presenting the credential directly", origin);
                return false;
            }
            if (fallbackOrigins.add(origin)) {
                log.info("{} sent no LWS authorization challenge (as_uri, realm); presenting the credential "
                        + "directly, as earlier LWS drafts did", requestUri.getHost());
                return true;
            }
            return fallback.onUnauthorized(response);
        }
        lwsOrigins.add(origin);   // this server speaks LWS authorization
        fallbackOrigins.remove(origin);
        Challenges.Challenge c = null;
        AuthException refused = null;
        for (Challenges.Challenge candidate : challenges) {
            try {
                acceptable(candidate, requestUri);
                c = candidate;
                break;
            } catch (AuthException e) {
                if (refused == null) {
                    refused = e;
                }
            }
        }
        if (c == null) {
            throw refused;
        }
        if ("insufficient_scope".equals(c.param("error"))) {
            return false;   // another token would carry the same permissions
        }
        URI as = parseUri(c.param("as_uri"), "as_uri");
        URI realm = parseUri(c.param("realm"), "realm");
        String sent = bearer(response.request());
        synchronized (lock(realm)) {
            Grant current = grants.get(realm.toString());
            if (current != null && !current.accessToken().equals(sent)) {
                return true;   // another request already obtained a new token: retry with it
            }
            if (current != null && Instant.now().isBefore(current.obtainedAt().plus(minTokenAgeForRenewal))) {
                return false;   // a token issued moments ago was refused: not permitted, not expired
            }
            grants.put(realm.toString(), exchange(as, realm));
            return true;
        }
    }

    // ------------------------------------------------------------------ grants

    private Grant grantFor(URI uri) {
        Grant best = null;
        for (Grant g : grants.values()) {
            if (contains(g.realm(), uri) && (best == null
                    || g.realm().toString().length() > best.realm().toString().length())) {
                best = g;
            }
        }
        return best;
    }

    private static boolean isFresh(Grant g) {
        return g.expiresAt() == null || Instant.now().plus(EXPIRY_SKEW).isBefore(g.expiresAt());
    }

    private Grant renew(Grant stale) {
        synchronized (lock(stale.realm())) {
            Grant current = grants.get(stale.realm().toString());
            if (current != null && isFresh(current)) {
                return current;
            }
            Grant fresh = exchange(stale.authorizationServer(), stale.realm());
            grants.put(stale.realm().toString(), fresh);
            return fresh;
        }
    }

    private Object lock(URI realm) {
        return locks.computeIfAbsent(realm.toString(), r -> new Object());
    }

    /** Exchange a fresh authentication credential for an access token to {@code realm}. */
    private Grant exchange(URI as, URI realm) {
        try {
            ServerMetadata md = metadata(as);
            // Addressed to the server's issuer identifier, which a self-issued JWT puts in its aud.
            CredentialSource.Credential cred = source.credential(md.issuer());
            checkTokenType(md, cred.tokenType());
            checkIdentifierType(md, cred);
            Map<String, String> form = new LinkedHashMap<>();
            form.put("grant_type", TOKEN_EXCHANGE);
            form.put("resource", realm.toString());
            form.put("subject_token", cred.token());
            form.put("subject_token_type", cred.tokenType());
            AuthorizationCodeFlow.Tokens t = TokenEndpoint.request(http, md.tokenEndpoint(), form, null, null, null, timeout);
            if (t.tokenType() != null && !"Bearer".equalsIgnoreCase(t.tokenType())) {
                // RFC 6749 §7.1: a token of a type the client does not understand must not be used.
                throw new AuthException(as + " issued a " + t.tokenType() + " token for " + realm
                        + "; LWS storage takes Bearer access tokens", null);
            }
            Instant now = Instant.now();
            if (warnings.add("obtained:" + realm)) {
                log.info("Obtained an access token for {} from {}", realm, as);
            }
            return new Grant(realm, as, t.accessToken(), expiry(t, now), now);
        } catch (TokenEndpointException e) {
            throw new AuthException("Token exchange at " + as + " for " + realm + " was refused: " + e.getMessage(), e);
        } catch (IOException e) {
            throw new AuthException("Token exchange at " + as + " for " + realm + " failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthException("Interrupted while obtaining an access token", e);
        }
    }

    /** {@code expires_in}, else the access token's own {@code exp} (it is a JWT, RFC 9068), else five minutes. */
    private static Instant expiry(AuthorizationCodeFlow.Tokens t, Instant now) {
        if (t.expiresIn() != null) {
            return now.plusSeconds(t.expiresIn());
        }
        try {
            Date exp = JWTParser.parse(t.accessToken()).getJWTClaimsSet().getExpirationTime();
            if (exp != null) {
                return exp.toInstant();
            }
        } catch (Exception notAJwt) {
            // fall through
        }
        return now.plus(DEFAULT_LIFETIME);
    }

    /**
     * Refuse to send a credential of a type the server says it does not take: it would be
     * refused, and the credential would have gone to a server that has no use for it.
     */
    private static void checkTokenType(ServerMetadata md, String tokenType) {
        if (md.subjectTokenTypes().isEmpty()) {
            return;   // not advertised
        }
        for (String listed : md.subjectTokenTypes()) {
            if (sameTokenType(listed, tokenType)) {
                return;
            }
        }
        throw new AuthException(md.issuer() + " does not accept " + tokenType + " credentials (its "
                + "subject_token_types_supported is " + md.subjectTokenTypes() + "); not sending one", null);
    }

    private static boolean sameTokenType(String listed, String tokenType) {
        return listed.equals(tokenType)
                || (CredentialSource.ID_TOKEN.equals(tokenType) && ID_TOKEN_HYPHENATED.equals(listed));
    }

    private void checkIdentifierType(ServerMetadata md, CredentialSource.Credential cred) {
        if (cred.subject() == null) {
            return;
        }
        String type = identifierType(cred.subject());
        List<String> accepted = new ArrayList<>();
        for (String listed : md.subjectIdentifierTypes()) {
            accepted.add(listed.endsWith(":") ? listed.substring(0, listed.length() - 1) : listed);   // "https:" or "https"
        }
        if (accepted.isEmpty()) {
            accepted.add("https");   // the default
        }
        if (type != null && !accepted.contains(type)) {
            warnOnce("idtype:" + md.issuer(), "{} accepts subject identifiers {}, not {} ({}); trying anyway",
                    md.issuer(), accepted, type, cred.subject());
        }
    }

    /** "https" for an https URI; "did:&lt;method&gt;" for a DID (LWS core, authorization server metadata). */
    static String identifierType(String subject) {
        String s = subject.toLowerCase(Locale.ROOT);
        if (s.startsWith("did:")) {
            int second = s.indexOf(':', 4);
            return second > 0 ? s.substring(0, second) : s;
        }
        int colon = s.indexOf(':');
        return colon > 0 ? s.substring(0, colon) : null;
    }

    // ------------------------------------------------------------------ authorization server metadata

    ServerMetadata metadata(URI as) throws IOException, InterruptedException {
        ServerMetadata cached = metadata.get(as.toString());
        if (cached != null) {
            return cached;
        }
        IOException last = null;
        for (URI url : metadataUrls(as)) {
            HttpResponse<byte[]> r = http.send(HttpRequest.newBuilder(url).timeout(timeout)
                    .header("Accept", "application/json").GET().build(), HttpResponse.BodyHandlers.ofByteArray());
            if (r.statusCode() == 404) {
                last = new IOException("No authorization server metadata at " + url);
                continue;
            }
            if (r.statusCode() / 100 != 2) {
                throw new IOException("Authorization server metadata " + url + ": HTTP " + r.statusCode());
            }
            ServerMetadata md = parseMetadata(r.body(), url);
            if (!OpenIdDiscovery.sameIssuer(md.issuer().toString(), as.toString())) {
                throw new IOException("Authorization server metadata at " + url + " is for issuer " + md.issuer()
                        + ", not " + as + "; refusing to use it");
            }
            if (!BrowserLauncher.isSafeToLaunch(md.tokenEndpoint())) {
                throw new IOException("Token endpoint " + md.tokenEndpoint() + " must be https (or http on loopback)");
            }
            metadata.put(as.toString(), md);
            return md;
        }
        throw last;
    }

    /**
     * {@code /.well-known/lws-configuration} for the server: inserted before the path of an
     * issuer that has one (RFC 8414 §3.1), then appended to it, then at the origin's root (LWS
     * names only the path). Whichever answers, its {@code issuer} must be the server's.
     */
    static List<URI> metadataUrls(URI as) {
        String origin = as.getScheme() + "://" + as.getRawAuthority();
        String path = as.getRawPath() == null ? "" : as.getRawPath();
        if (path.endsWith("/")) {
            path = path.substring(0, path.length() - 1);
        }
        List<URI> urls = new ArrayList<>();
        urls.add(URI.create(origin + "/.well-known/lws-configuration" + path));
        if (!path.isEmpty()) {
            urls.add(URI.create(origin + path + "/.well-known/lws-configuration"));
            urls.add(URI.create(origin + "/.well-known/lws-configuration"));
        }
        return urls;
    }

    private static ServerMetadata parseMetadata(byte[] body, URI url) throws IOException {
        try (JsonReader r = Json.createReader(new ByteArrayInputStream(body))) {
            JsonObject o = r.readObject();
            if (!(o.get("issuer") instanceof JsonString issuer) || !(o.get("token_endpoint") instanceof JsonString te)) {
                throw new IOException("Authorization server metadata at " + url + " lacks issuer or token_endpoint");
            }
            return new ServerMetadata(URI.create(issuer.getString()), URI.create(te.getString()),
                    strings(o.get("subject_token_types_supported")), strings(o.get("subject_identifier_types_supported")));
        } catch (RuntimeException e) {
            throw new IOException("Malformed authorization server metadata at " + url + ": " + e.getMessage(), e);
        }
    }

    private static List<String> strings(JsonValue v) {
        List<String> out = new ArrayList<>();
        if (v instanceof JsonArray a) {
            for (JsonValue x : a) {
                if (x instanceof JsonString s) {
                    out.add(s.getString());
                }
            }
        }
        return out;
    }

    // ------------------------------------------------------------------ challenge checks

    /** The {@code Bearer} challenges carrying {@code as_uri} and {@code realm}, in order (a 401 may offer several). */
    private static List<Challenges.Challenge> lwsChallenges(HttpResponse<?> response) {
        List<Challenges.Challenge> out = new ArrayList<>();
        for (Challenges.Challenge c : Challenges.parse(response.headers().allValues("WWW-Authenticate"))) {
            if ("Bearer".equalsIgnoreCase(c.scheme()) && c.param("as_uri") != null && c.param("realm") != null) {
                out.add(c);
            }
        }
        return out;
    }

    /** Whether a challenge may be acted on for {@code requestUri}; throws why not. */
    private void acceptable(Challenges.Challenge c, URI requestUri) {
        URI as = parseUri(c.param("as_uri"), "as_uri");
        URI realm = parseUri(c.param("realm"), "realm");
        if (!contains(realm, requestUri)) {
            throw new AuthException("The storage named realm " + realm + " for " + requestUri
                    + ", which does not contain it; refusing to obtain a token for it", null);
        }
        checkAuthorizationServer(as);
    }

    private static String origin(URI uri) {
        String scheme = uri.getScheme() == null ? "" : uri.getScheme().toLowerCase(Locale.ROOT);
        String host = uri.getHost() == null ? "" : uri.getHost().toLowerCase(Locale.ROOT);
        return scheme + "://" + host + ":" + port(uri);
    }

    private void checkAuthorizationServer(URI as) {
        if (pinnedAuthorizationServer != null
                && !OpenIdDiscovery.sameIssuer(as.toString(), pinnedAuthorizationServer.toString())) {
            throw new AuthException("The storage named authorization server " + as + ", but only "
                    + pinnedAuthorizationServer + " is accepted (-Dlws.authServer)", null);
        }
        if (!BrowserLauncher.isSafeToLaunch(as)) {
            throw new AuthException("Refusing authorization server " + as
                    + ": it must be an https URL (or http on a loopback address)", null);
        }
    }

    /**
     * Whether {@code uri} is logically contained in {@code realm}: same origin, and the realm's
     * path is a prefix of the URI's path at a segment boundary.
     */
    static boolean contains(URI realm, URI uri) {
        if (realm.getScheme() == null || uri.getScheme() == null || realm.getHost() == null || uri.getHost() == null
                || !realm.getScheme().equalsIgnoreCase(uri.getScheme())
                || !realm.getHost().equalsIgnoreCase(uri.getHost())
                || port(realm) != port(uri)) {
            return false;
        }
        String rp = realm.getRawPath() == null || realm.getRawPath().isEmpty() ? "/" : realm.getRawPath();
        String up = uri.getRawPath() == null || uri.getRawPath().isEmpty() ? "/" : uri.getRawPath();
        if (rp.endsWith("/")) {
            return up.startsWith(rp) || up.equals(rp.substring(0, rp.length() - 1));
        }
        return up.equals(rp) || up.startsWith(rp + "/");
    }

    private static int port(URI u) {
        return u.getPort() >= 0 ? u.getPort() : ("https".equalsIgnoreCase(u.getScheme()) ? 443 : 80);
    }

    private static URI parseUri(String value, String name) {
        try {
            URI u = URI.create(value);
            if (!u.isAbsolute()) {
                throw new IllegalArgumentException("not absolute");
            }
            return u;
        } catch (IllegalArgumentException e) {
            throw new AuthException("The storage sent an invalid " + name + " in its challenge: " + value, e);
        }
    }

    private static String bearer(HttpRequest request) {
        String h = request.headers().firstValue("Authorization").orElse("");
        return h.regionMatches(true, 0, "Bearer ", 0, 7) ? h.substring(7) : null;
    }

    private void warnOnce(String key, String format, Object... args) {
        if (warnings.add(key)) {
            log.warn(format, args);
        }
    }
}
