package com.ebremer.lws.fuse.auth;

import static com.ebremer.lws.fuse.auth.AuthorizationCodeFlowTest.nonceOf;
import static com.ebremer.lws.fuse.auth.MockOpenIdServer.tokens;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.MockOpenIdServer.Reply;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OpenIdAuthProviderTest {

    private static final URI RESOURCE = URI.create("http://lws.example/alice/x");

    private MockOpenIdServer idp;

    @BeforeEach
    void start() throws IOException {
        idp = new MockOpenIdServer();
    }

    @AfterEach
    void stop() {
        idp.close();
    }

    @Test
    void clientCredentialsTokenIsDiscoveredCachedAndSentAsBearer() {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600));
        OpenIdAuthProvider.Config cfg = config();
        cfg.clientSecret = "s3cret";
        OpenIdAuthProvider provider = provider(cfg);

        assertEquals("Bearer at1", authorize(provider));
        assertEquals("Bearer at1", authorize(provider));
        assertEquals(1, idp.tokenRequests.size());
        MockOpenIdServer.TokenRequest request = idp.tokenRequests.get(0);
        assertEquals("client_credentials", request.form().get("grant_type"));
        assertEquals("Basic " + Base64.getEncoder().encodeToString("app:s3cret".getBytes(UTF_8)),
                request.authorization());
    }

    @Test
    void rotatedRefreshTokensReachTheListener() {
        AtomicInteger issued = new AtomicInteger();
        idp.tokenHandler = req -> {
            int n = issued.incrementAndGet();
            return req.form().get("refresh_token").equals("rt" + (n - 1))
                    ? Reply.ok(tokens("at" + n, "rt" + n, 1))   // expires inside the refresh skew
                    : Reply.error(400, "invalid_grant");
        };
        List<String> saved = new CopyOnWriteArrayList<>();
        OpenIdAuthProvider.Config cfg = config();
        cfg.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
        cfg.refreshToken = "rt0";
        cfg.refreshTokenListener = saved::add;
        OpenIdAuthProvider provider = provider(cfg);

        assertEquals("Bearer at1", authorize(provider));
        assertEquals("Bearer at2", authorize(provider));
        assertEquals(List.of("rt1", "rt2"), saved);
        assertEquals("rt2", cfg.refreshToken);
        assertEquals("rt1", idp.tokenRequests.get(1).form().get("refresh_token"));
    }

    @Test
    void anUnchangedRefreshTokenIsNotReported() throws IOException {
        idp.tokenHandler = req -> Reply.ok(tokens("at", "same", 3600));
        List<String> saved = new CopyOnWriteArrayList<>();
        OpenIdAuthProvider.Config cfg = config();
        cfg.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
        cfg.refreshToken = "same";
        cfg.refreshTokenListener = saved::add;

        provider(cfg).prefetch();
        assertTrue(saved.isEmpty());
    }

    @Test
    void a401OnAFreshTokenIsNotRetried() throws IOException {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600));
        OpenIdAuthProvider provider = provider(config());
        provider.prefetch();

        assertFalse(provider.onUnauthorized(rejected("Bearer at1", Map.of("WWW-Authenticate", "Bearer"))));
        assertEquals(1, idp.tokenRequests.size());
    }

    @Test
    void a401OnAnAlreadyReplacedTokenIsRetriedWithoutRefreshing() throws IOException {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600));
        OpenIdAuthProvider provider = provider(config());
        provider.prefetch();

        assertTrue(provider.onUnauthorized(rejected("Bearer older", Map.of())));
        assertEquals("Bearer at1", authorize(provider));
        assertEquals(1, idp.tokenRequests.size());
    }

    @Test
    void insufficientScopeIsNotRetried() throws IOException {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600));
        OpenIdAuthProvider provider = provider(config());
        provider.prefetch();

        assertFalse(provider.onUnauthorized(rejected("Bearer older",
                Map.of("WWW-Authenticate", "Bearer error=\"insufficient_scope\", scope=\"write\""))));
    }

    @Test
    void prefetchReportsARejectedRefreshToken() {
        idp.tokenHandler = req -> Reply.error(400, "invalid_grant");
        OpenIdAuthProvider.Config cfg = config();
        cfg.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
        cfg.refreshToken = "revoked";

        TokenEndpointException e = assertThrows(TokenEndpointException.class, provider(cfg)::prefetch);
        assertTrue(e.isInvalidGrant());
        assertEquals(400, e.status());
    }

    @Test
    void nonOAuthErrorBodiesCarryNoErrorCode() {
        idp.tokenHandler = req -> new Reply(502, "<html>bad gateway</html>");

        TokenEndpointException e = assertThrows(TokenEndpointException.class, provider(config())::prefetch);
        assertNull(e.error());
        assertFalse(e.isInvalidGrant());
        assertEquals(502, e.status());
    }

    @Test
    void anUnreachableTokenEndpointIsAnAuthFailure() {
        OpenIdAuthProvider.Config cfg = config();
        cfg.tokenEndpoint = URI.create("http://127.0.0.1:1/token");   // nothing listens on port 1

        assertThrows(AuthException.class, () -> authorize(provider(cfg)));
    }

    // ------------------------------------------------------------------ DPoP (P2-S7)

    @Test
    void dpopTokensAreSentWithAProofForTheRawRequestUri() throws Exception {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600, "DPoP"));
        OpenIdAuthProvider.Config cfg = config();
        cfg.dpop = new DPoP();
        OpenIdAuthProvider provider = provider(cfg);
        URI encoded = URI.create("http://lws.example/alice/a%41b.txt");

        HttpRequest.Builder b = HttpRequest.newBuilder(encoded);
        provider.authorize(b, "GET", encoded);
        HttpRequest r = b.build();
        assertEquals("DPoP at1", r.headers().firstValue("Authorization").orElseThrow());
        String proof = r.headers().firstValue("DPoP").orElseThrow();
        assertEquals("http://lws.example/alice/a%41b.txt",
                com.nimbusds.jwt.SignedJWT.parse(proof).getJWTClaimsSet().getStringClaim("htu"));
    }

    @Test
    void aResourceServerNonceChallengeIsRetriedWithTheNonce() throws Exception {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600, "DPoP"));
        OpenIdAuthProvider.Config cfg = config();
        cfg.dpop = new DPoP();
        OpenIdAuthProvider provider = provider(cfg);
        provider.prefetch();

        FakeResponse challenge = FakeResponse.of(401, request("DPoP at1"), Map.of(
                "WWW-Authenticate", "DPoP error=\"use_dpop_nonce\"", "DPoP-Nonce", "rs-nonce"));
        provider.onResponse(challenge);
        assertTrue(provider.onUnauthorized(challenge));

        HttpRequest.Builder b = HttpRequest.newBuilder(RESOURCE);
        provider.authorize(b, "GET", RESOURCE);
        assertEquals("rs-nonce", nonceOf(b.build().headers().firstValue("DPoP").orElseThrow()));
        assertEquals(1, idp.tokenRequests.size(), "the token itself was fine");
    }

    @Test
    void aTokenEndpointNonceChallengeIsRetriedOnce() throws Exception {
        idp.tokenHandler = req -> nonceOf(req.dpop()) == null
                ? Reply.error(400, "use_dpop_nonce").withHeader("DPoP-Nonce", "as-nonce")
                : Reply.ok(tokens("at1", null, 3600, "DPoP"));
        OpenIdAuthProvider.Config cfg = config();
        cfg.dpop = new DPoP();

        provider(cfg).prefetch();
        assertEquals(2, idp.tokenRequests.size());
        assertEquals("as-nonce", nonceOf(idp.tokenRequests.get(1).dpop()));
    }

    @Test
    void aBearerTokenIssuedDespiteDpopIsStillUsable() {
        idp.tokenHandler = req -> Reply.ok(tokens("at1", null, 3600, "Bearer"));
        OpenIdAuthProvider.Config cfg = config();
        cfg.dpop = new DPoP();

        assertEquals("Bearer at1", authorize(provider(cfg)));
    }

    private OpenIdAuthProvider.Config config() {
        OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
        cfg.issuer = idp.issuer();
        cfg.clientId = "app";
        return cfg;
    }

    private static OpenIdAuthProvider provider(OpenIdAuthProvider.Config cfg) {
        return new OpenIdAuthProvider(HttpClient.newHttpClient(), cfg, Duration.ofSeconds(10));
    }

    static String authorize(AuthProvider provider) {
        HttpRequest.Builder b = HttpRequest.newBuilder(RESOURCE);
        provider.authorize(b, "GET", RESOURCE);
        return b.build().headers().firstValue("Authorization").orElse(null);
    }

    private static HttpRequest request(String authorization) {
        return HttpRequest.newBuilder(RESOURCE).header("Authorization", authorization).build();
    }

    private static FakeResponse rejected(String authorization, Map<String, String> headers) {
        return FakeResponse.of(401, request(authorization), headers);
    }
}
