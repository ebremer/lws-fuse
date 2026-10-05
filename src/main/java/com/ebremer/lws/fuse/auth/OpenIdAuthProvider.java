package com.ebremer.lws.fuse.auth;

import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.PlainJWT;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * OpenID Connect for LWS: the {@link CredentialSource} of the OpenID authentication suite, and an
 * {@link AuthProvider} for servers following earlier drafts.
 *
 * <p>Under LWS authorization the credential is the <b>ID token</b> (token type
 * {@code urn:ietf:params:oauth:token-type:id_token}), which {@link LwsAuthProvider} exchanges for an
 * access token at the storage's authorization server. The latest ID token from the token endpoint
 * is kept; when it is about to expire, a refresh obtains a new one (most providers return one on
 * a refresh with the {@code openid} scope). The client-credentials grant issues no ID token, so it
 * can only be used directly.
 *
 * <p>Used directly, it obtains OAuth 2.0 access tokens and attaches them as {@code Bearer} — or,
 * when a {@link DPoP} signer is configured, {@code DPoP} — credentials.
 *
 * <p>It implements the two grants that suit a headless FUSE daemon: {@code client_credentials}
 * and {@code refresh_token}. The token endpoint is taken from configuration or, failing that,
 * discovered from the issuer's {@code .well-known/openid-configuration}. The interactive
 * authorization-code login lives in {@link AuthorizationCodeFlow} and {@link InteractiveLogin},
 * which hand this class the resulting tokens and continue with {@code refresh_token}. The LWS
 * Client ID Metadata Document / OpenID Federation client-identity mechanisms are out of scope.
 *
 * <p>Tokens are cached and refreshed by {@link TokenCache}. A {@code 401} triggers one refresh and
 * retry via {@link #onUnauthorized} — unless the rejected token was obtained only moments ago,
 * which signals a permission problem rather than an expired token. A refresh token the server
 * rotates is handed to {@link Config#refreshTokenListener} so it can be persisted.
 *
 * <p>With DPoP, nonces demanded by the token endpoint or the resource server
 * ({@code use_dpop_nonce}) are picked up and the request retried, and a server that answers with
 * a plain {@code Bearer} token is used but reported once. Thread-safe.
 *
 * @author Erich Bremer
 */
public final class OpenIdAuthProvider implements AuthProvider, CredentialSource {

    /** Supported OAuth 2.0 grant types for headless clients. */
    public enum Grant {CLIENT_CREDENTIALS, REFRESH_TOKEN}

    /** Mutable configuration holder. */
    public static final class Config {
        /** OpenID issuer, used for discovery when {@link #tokenEndpoint} is not set. */
        public URI issuer;
        /** Explicit token endpoint; when set, discovery is skipped. */
        public URI tokenEndpoint;
        public String clientId;
        /** Client secret for {@code client_secret_basic}; {@code null} for a public client. */
        public String clientSecret;
        public Grant grant = Grant.CLIENT_CREDENTIALS;
        /** Optional space-delimited scopes. */
        public String scope;
        /** Required for {@link Grant#REFRESH_TOKEN}; updated in place if the server rotates it. */
        public String refreshToken;
        /**
         * Called with each new refresh token the server issues (e.g. a rotated one), so it can be
         * persisted; with rotation the previous token is spent. Runs under the token lock.
         */
        public Consumer<String> refreshTokenListener;
        /** When non-null, request and prove DPoP-bound tokens (RFC 9449); otherwise Bearer. */
        public DPoP dpop;
    }

    private static final Logger log = LoggerFactory.getLogger(OpenIdAuthProvider.class);

    /** A 401 on a token younger than this is not answered with a refresh (see {@link #onUnauthorized}). */
    private static final Duration MIN_TOKEN_AGE_FOR_REFRESH = Duration.ofSeconds(10);

    private final HttpClient http;
    private final Config config;
    private final Duration timeout;
    private final TokenCache cache;
    private volatile URI resolvedTokenEndpoint;
    private volatile String idToken;   // the latest ID token issued, or null
    private final AtomicBoolean downgradeWarned = new AtomicBoolean();
    private final Set<String> warned = ConcurrentHashMap.newKeySet();

    public OpenIdAuthProvider(HttpClient http, Config config, Duration timeout) {
        this.http = http;
        this.config = config;
        this.timeout = timeout;
        this.cache = new TokenCache(this::fetchToken);
    }

    @Override
    public void authorize(HttpRequest.Builder builder, String method, URI uri) {
        TokenCache.Token token = cache.get(Instant.now());
        if (config.dpop != null && "DPoP".equalsIgnoreCase(token.tokenType())) {
            builder.setHeader("Authorization", "DPoP " + token.accessToken());
            builder.setHeader("DPoP", config.dpop.proof(method, uri, token.accessToken()));
        } else {
            if (config.dpop != null && downgradeWarned.compareAndSet(false, true)) {
                log.warn("DPoP was requested, but the token endpoint issued a {} token; "
                        + "sending it as a plain bearer token", token.tokenType());
            }
            builder.setHeader("Authorization", "Bearer " + token.accessToken());
        }
    }

    @Override
    public void onResponse(HttpResponse<?> response) {
        if (config.dpop != null) {
            config.dpop.rememberNonce(response.request().uri(), response.headers());
        }
    }

    @Override
    public boolean onUnauthorized(HttpResponse<?> response) {
        String challenge = String.join(", ", response.headers().allValues("WWW-Authenticate"));
        if (config.dpop != null && challenge.contains("use_dpop_nonce")
                && response.headers().firstValue("DPoP-Nonce").isPresent()) {
            return true;   // the resource server wants its nonce in the proof; the token is fine
        }
        if (challenge.contains("insufficient_scope")) {
            return false;   // a refreshed token carries the same scopes
        }
        String sent = response.request().headers().firstValue("Authorization").orElse("");
        String token = sent.substring(sent.indexOf(' ') + 1);   // strip the "Bearer "/"DPoP " scheme
        return cache.invalidate(token, Instant.now(), MIN_TOKEN_AGE_FOR_REFRESH);
    }

    /**
     * The OpenID suite's credential: the current ID token, refreshed first if it is missing or
     * about to expire.
     *
     * @throws AuthException if the provider issues no (unexpired) ID token
     */
    @Override
    public Credential credential(URI authorizationServer) {
        String token = idToken;
        if (token == null || expiresWithin(token, Duration.ofSeconds(30))) {
            if (config.grant == Grant.CLIENT_CREDENTIALS) {
                throw new AuthException("The client-credentials grant yields no ID token, which LWS authorization "
                        + "exchanges for access; use the browser login (-Dlws.login=true) or a refresh token", null);
            }
            cache.refresh(Instant.now());
            token = idToken;
        }
        if (token == null) {
            throw new AuthException("The OpenID provider issued no ID token, which LWS authorization exchanges "
                    + "for access; request the 'openid' scope", null);
        }
        if (expiresWithin(token, Duration.ZERO)) {
            throw new AuthException("The ID token has expired and the OpenID provider issued no new one on "
                    + "refresh; log in again (-Dlws.login=true -Dlws.forceLogin=true)", null);
        }
        checkIdToken(token);
        return new Credential(token, ID_TOKEN, claim(token, "sub"));
    }

    /**
     * What the LWS OpenID suite asks of the ID token: it must be signed, and it carries the LWS
     * subject in {@code sub} (a URI) and the client identifier (a URI) in {@code azp}. An unsigned
     * token is refused; anything else is only reported, since the authorization server decides.
     */
    private void checkIdToken(String token) {
        JWT jwt;
        try {
            jwt = JWTParser.parse(token);
        } catch (ParseException unparseable) {
            return;   // leave judging it to the authorization server
        }
        if (jwt instanceof PlainJWT) {
            throw new AuthException("The OpenID provider issued an unsigned ID token (alg \"none\"), which LWS "
                    + "authorization does not accept", null);
        }
        if (claim(token, "azp") == null) {
            warnOnce("azp", "The ID token has no azp claim, where the LWS OpenID suite carries the client "
                    + "identifier; the authorization server may refuse it");
        }
        String sub = claim(token, "sub");
        if (sub != null && !isAbsoluteUri(sub)) {
            warnOnce("sub", "The ID token's subject {} is not a URI, as LWS requires; the authorization "
                    + "server may refuse it", sub);
        }
        if (config.clientId != null && !isAbsoluteUri(config.clientId)) {
            warnOnce("client", "The client id {} is not a URI, as LWS expects (for example a Client ID "
                    + "Metadata Document URL); the authorization server may refuse it", config.clientId);
        }
    }

    private static boolean isAbsoluteUri(String s) {
        try {
            return URI.create(s).isAbsolute();
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    private void warnOnce(String key, String format, Object... args) {
        if (warned.add(key)) {
            log.warn(format, args);
        }
    }

    /** Use tokens obtained elsewhere (a browser login) as the current access and ID token. */
    public void seed(AuthorizationCodeFlow.Tokens tokens) {
        if (tokens.idToken() != null) {
            idToken = tokens.idToken();
        }
        Instant now = Instant.now();
        cache.put(new TokenCache.Token(tokens.accessToken(), tokens.tokenType(),
                tokens.expiresIn() != null ? now.plusSeconds(tokens.expiresIn()) : null), now);
    }

    private static boolean expiresWithin(String jwt, Duration margin) {
        try {
            JWTClaimsSet claims = JWTParser.parse(jwt).getJWTClaimsSet();
            return claims.getExpirationTime() != null
                    && !Instant.now().plus(margin).isBefore(claims.getExpirationTime().toInstant());
        } catch (Exception unparseable) {
            return false;   // leave judging it to the authorization server
        }
    }

    private static String claim(String jwt, String name) {
        try {
            Object v = JWTParser.parse(jwt).getJWTClaimsSet().getClaim(name);
            return v == null ? null : v.toString();
        } catch (Exception unparseable) {
            return null;
        }
    }

    /**
     * Obtain a token now instead of on the first request, so a bad configuration or a revoked
     * refresh token is reported before mounting rather than as I/O errors afterwards.
     *
     * @throws TokenEndpointException if the token endpoint refused the request (see
     *                                {@link TokenEndpointException#isInvalidGrant()})
     * @throws IOException            if no token could be obtained for another reason
     */
    public void prefetch() throws IOException {
        try {
            cache.get(Instant.now());
        } catch (AuthException e) {
            if (e.getCause() instanceof IOException io) {
                throw io;
            }
            throw e;
        }
    }

    // ------------------------------------------------------------------ token endpoint

    private TokenCache.Token fetchToken() throws IOException, InterruptedException {
        Map<String, String> form = new LinkedHashMap<>();
        switch (config.grant) {
            case CLIENT_CREDENTIALS -> form.put("grant_type", "client_credentials");
            case REFRESH_TOKEN -> {
                if (config.refreshToken == null) {
                    throw new IOException("The session has expired and there is no refresh token; log in again");
                }
                form.put("grant_type", "refresh_token");
                form.put("refresh_token", config.refreshToken);
            }
        }
        if (config.scope != null && !config.scope.isBlank()) {
            form.put("scope", config.scope);
        }
        AuthorizationCodeFlow.Tokens t = TokenEndpoint.request(http, tokenEndpoint(), form,
                config.clientId, config.clientSecret, config.dpop, timeout);
        if (t.idToken() != null) {
            idToken = t.idToken();   // a refresh may omit it; then the previous one is kept
        }
        Instant expiresAt = t.expiresIn() != null ? Instant.now().plusSeconds(t.expiresIn()) : null;
        String issued = t.refreshToken();
        if (issued != null && !issued.equals(config.refreshToken)) {
            config.refreshToken = issued;   // with rotation, the previous one is now spent
            if (config.refreshTokenListener != null) {
                config.refreshTokenListener.accept(issued);
            }
        }
        return new TokenCache.Token(t.accessToken(), t.tokenType(), expiresAt);
    }

    private URI tokenEndpoint() throws IOException, InterruptedException {
        if (config.tokenEndpoint != null) {
            return config.tokenEndpoint;
        }
        URI cached = resolvedTokenEndpoint;
        if (cached != null) {
            return cached;
        }
        if (config.issuer == null) {
            throw new IllegalStateException("OpenIdAuthProvider needs a tokenEndpoint or an issuer");
        }
        resolvedTokenEndpoint = OpenIdDiscovery.discover(http, config.issuer, timeout).tokenEndpoint();
        return resolvedTokenEndpoint;
    }
}
