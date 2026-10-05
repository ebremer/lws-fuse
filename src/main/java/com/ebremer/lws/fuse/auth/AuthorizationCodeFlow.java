package com.ebremer.lws.fuse.auth;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Interactive OpenID Connect login for a native app: the RFC 8252 pattern of the system browser
 * plus a loopback redirect, with RFC 7636 PKCE.
 *
 * <p>The flow discovers the authorization and token endpoints (if not given), starts a one-shot
 * HTTP listener on {@code 127.0.0.1:<ephemeral>}, opens the authorization URL in the user's real
 * browser, catches the redirect carrying the authorization code, and exchanges that code (with the
 * PKCE verifier) for tokens. No embedded web-view, so the user's existing SSO session, password
 * manager, passkeys and MFA all work, and the app never sees the user's credentials.
 *
 * <p>The loopback listener answers only {@code GET /callback} carrying this login's {@code state};
 * anything else is ignored, so a stray or forged request cannot end the login. When the provider
 * sends an RFC 9207 {@code iss} parameter (or promises to, in its metadata) it must name the
 * configured issuer. Only an {@code https} authorization endpoint (or {@code http} on loopback)
 * is opened.
 *
 * <p>The browser step is injectable ({@link #browserOpener}) so the flow can be driven headlessly
 * in tests. Pure OAuth 2.0 / OIDC — no Solid.
 *
 * @author Erich Bremer
 */
public final class AuthorizationCodeFlow {

    /**
     * Tokens returned by the token endpoint. {@code refreshToken} and {@code idToken} are null if
     * none was issued; the ID token is the LWS authentication credential of the OpenID suite.
     */
    public record Tokens(String accessToken, String refreshToken, String tokenType, Long expiresIn, String idToken) {}

    private static final Logger log = LoggerFactory.getLogger(AuthorizationCodeFlow.class);
    private static final SecureRandom RNG = new SecureRandom();

    private final HttpClient http;
    private final Duration exchangeTimeout;
    private Duration loginTimeout = Duration.ofMinutes(5);
    private Consumer<URI> browserOpener = BrowserLauncher::open;

    public AuthorizationCodeFlow(HttpClient http, Duration exchangeTimeout) {
        this.http = http;
        this.exchangeTimeout = exchangeTimeout;
    }

    /** Override how the authorization URL is opened (tests inject a simulated user here). */
    public AuthorizationCodeFlow browserOpener(Consumer<URI> opener) {
        this.browserOpener = opener;
        return this;
    }

    /** How long to wait for the user to complete the browser login (default 5 minutes). */
    public AuthorizationCodeFlow loginTimeout(Duration timeout) {
        this.loginTimeout = timeout;
        return this;
    }

    /**
     * Run the login. Endpoints not supplied are resolved from the issuer's discovery document.
     *
     * @param clientSecret null for a public (PKCE-only) client
     * @param scope        requested scopes; defaults to {@code "openid offline_access"} (the latter
     *                     asks for a refresh token) when null
     */
    public Tokens login(URI issuer, URI authorizationEndpoint, URI tokenEndpoint,
                        String clientId, String clientSecret, String scope)
            throws IOException, InterruptedException {
        return login(issuer, authorizationEndpoint, tokenEndpoint, clientId, clientSecret, scope, null);
    }

    /**
     * Run the login, binding the authorization code and the issued tokens to {@code dpop}'s key
     * (RFC 9449 {@code dpop_jkt} and a DPoP-proved code exchange) when it is non-null. A refresh
     * token bound this way can only be used with the same key.
     */
    public Tokens login(URI issuer, URI authorizationEndpoint, URI tokenEndpoint,
                        String clientId, String clientSecret, String scope, DPoP dpop)
            throws IOException, InterruptedException {

        boolean issRequired = false;
        if (authorizationEndpoint == null || tokenEndpoint == null) {
            OpenIdDiscovery.ProviderMetadata md = OpenIdDiscovery.discover(http, issuer, exchangeTimeout);
            issRequired = md.issParameterSupported();
            if (authorizationEndpoint == null) {
                authorizationEndpoint = md.authorizationEndpoint();
            }
            if (tokenEndpoint == null) {
                tokenEndpoint = md.tokenEndpoint();
            }
        }
        if (authorizationEndpoint == null || tokenEndpoint == null) {
            throw new IOException("Issuer did not advertise authorization/token endpoints");
        }
        if (!BrowserLauncher.isSafeToLaunch(authorizationEndpoint)) {
            throw new IOException("Refusing to open the authorization endpoint " + authorizationEndpoint
                    + ": it must be an https URL (or http to a loopback address)");
        }

        Pkce pkce = new Pkce();
        String state = randomToken();
        String effectiveScope = (scope == null || scope.isBlank()) ? "openid offline_access" : scope;
        String expectedIssuer = issuer.toString();
        boolean issMandatory = issRequired;

        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        int port = server.getAddress().getPort();
        String redirectUri = "http://127.0.0.1:" + port + "/callback";
        CompletableFuture<Map<String, String>> callback = new CompletableFuture<>();

        server.createContext("/callback", ex -> {
            try {
                if (!"GET".equals(ex.getRequestMethod()) || !"/callback".equals(ex.getRequestURI().getPath())) {
                    respond(ex, 404, "Not found.");
                    return;
                }
                Map<String, String> params = parseQuery(ex.getRequestURI().getRawQuery());
                if (!state.equals(params.get("state"))) {
                    // Not the redirect for this login (a stray or forged request): ignore it and
                    // keep waiting, rather than letting anyone who can reach the port abort the login.
                    respond(ex, 400, "This request does not belong to the login in progress and was ignored.");
                    return;
                }
                String message;
                if (params.containsKey("error")) {
                    message = "Login failed: " + describeError(params);
                } else if (!issuerMatches(params.get("iss"), expectedIssuer, issMandatory)) {
                    message = "Login failed: the response did not come from the expected identity provider.";
                } else {
                    message = "Login complete. You can close this tab and return to the terminal.";
                }
                respond(ex, 200, message);
                callback.complete(params);
            } finally {
                ex.close();
            }
        });
        server.start();

        try {
            URI authUrl = URI.create(authorizationEndpoint
                    + (authorizationEndpoint.toString().contains("?") ? "&" : "?")
                    + "response_type=code"
                    + "&client_id=" + enc(clientId)
                    + "&redirect_uri=" + enc(redirectUri)
                    + "&scope=" + enc(effectiveScope)
                    + "&state=" + enc(state)
                    + "&code_challenge=" + enc(pkce.challenge())
                    + "&code_challenge_method=" + pkce.method()
                    + (dpop != null ? "&dpop_jkt=" + enc(dpop.thumbprint()) : ""));
            browserOpener.accept(authUrl);

            Map<String, String> params;
            try {
                params = callback.get(loginTimeout.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                throw new IOException("Timed out waiting for the browser login to complete");
            } catch (ExecutionException e) {
                throw new IOException("Login callback failed", e);
            }
            if (params.containsKey("error")) {
                throw new IOException("Authorization server returned error: " + describeError(params));
            }
            if (!issuerMatches(params.get("iss"), expectedIssuer, issMandatory)) {
                throw new IOException("Authorization response issuer " + params.get("iss")
                        + " does not match " + expectedIssuer + " (RFC 9207 mix-up protection)");
            }
            String code = params.get("code");
            if (code == null) {
                throw new IOException("Authorization response carried no code");
            }
            Tokens tokens = exchangeCode(tokenEndpoint, code, redirectUri, clientId, clientSecret, pkce.verifier(), dpop);
            if (dpop != null && !"DPoP".equalsIgnoreCase(tokens.tokenType())) {
                log.warn("DPoP was requested, but {} issued a {} token; it will be sent as a plain bearer token",
                        issuer, tokens.tokenType());
            }
            return tokens;
        } finally {
            server.stop(0);
        }
    }

    private Tokens exchangeCode(URI tokenEndpoint, String code, String redirectUri,
                                String clientId, String clientSecret, String codeVerifier, DPoP dpop)
            throws IOException, InterruptedException {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("grant_type", "authorization_code");
        form.put("code", code);
        form.put("redirect_uri", redirectUri);
        form.put("code_verifier", codeVerifier);
        return TokenEndpoint.request(http, tokenEndpoint, form, clientId, clientSecret, dpop, exchangeTimeout);
    }

    /**
     * RFC 9207: an {@code iss} in the authorization response must name our issuer; it may be
     * absent only if the provider did not promise to send it.
     */
    private static boolean issuerMatches(String iss, String expectedIssuer, boolean required) {
        return iss == null ? !required : OpenIdDiscovery.sameIssuer(iss, expectedIssuer);
    }

    private static String describeError(Map<String, String> params) {
        String description = params.get("error_description");
        return params.get("error") + (description != null && !description.isBlank() ? " (" + description + ")" : "");
    }

    // ------------------------------------------------------------------ helpers

    private static Map<String, String> parseQuery(String rawQuery) {
        Map<String, String> map = new HashMap<>();
        if (rawQuery == null || rawQuery.isEmpty()) {
            return map;
        }
        for (String pair : rawQuery.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            String key = URLDecoder.decode(pair.substring(0, eq), StandardCharsets.UTF_8);
            String value = URLDecoder.decode(pair.substring(eq + 1), StandardCharsets.UTF_8);
            map.putIfAbsent(key, value);
        }
        return map;
    }

    private static String enc(String s) {
        return TokenEndpoint.enc(s);
    }

    private static String randomToken() {
        byte[] raw = new byte[16];
        RNG.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);
    }

    private static void respond(HttpExchange ex, int status, String message) throws IOException {
        byte[] body = htmlPage(message).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "text/html; charset=utf-8");
        ex.getResponseHeaders().set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'");
        ex.sendResponseHeaders(status, body.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(body);
        }
    }

    private static String htmlPage(String message) {
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>LWS login</title></head>"
                + "<body style=\"font-family:system-ui,sans-serif;margin:4rem;text-align:center\">"
                + "<h2>" + escapeHtml(message) + "</h2></body></html>";
    }

    /** The message may echo parameters from the redirect, which anyone can craft. */
    static String escapeHtml(String s) {
        StringBuilder sb = new StringBuilder(s.length());
        for (char c : s.toCharArray()) {
            switch (c) {
                case '&' -> sb.append("&amp;");
                case '<' -> sb.append("&lt;");
                case '>' -> sb.append("&gt;");
                case '"' -> sb.append("&quot;");
                case '\'' -> sb.append("&#39;");
                default -> sb.append(c);
            }
        }
        return sb.toString();
    }
}
