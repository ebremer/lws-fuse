package com.ebremer.lws.fuse.auth;

import static com.ebremer.lws.fuse.auth.MockOpenIdServer.tokens;
import static java.nio.charset.StandardCharsets.US_ASCII;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.MockOpenIdServer.Reply;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.http.HttpClient;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class AuthorizationCodeFlowTest {

    private MockOpenIdServer idp;

    @BeforeEach
    void start() throws IOException {
        idp = new MockOpenIdServer();
        idp.tokenHandler = req -> "the-code".equals(req.form().get("code"))
                ? Reply.ok(tokens("at", "rt", 60))
                : Reply.error(400, "invalid_grant");
    }

    @AfterEach
    void stop() {
        idp.close();
    }

    @Test
    void exchangesTheCodeWithThePkceVerifier() throws Exception {
        SimulatedBrowser browser = SimulatedBrowser.approving("the-code");

        AuthorizationCodeFlow.Tokens t = flow(browser).login(idp.issuer(), null, null, "app", null, null);

        assertEquals("at", t.accessToken());
        assertEquals("rt", t.refreshToken());
        Map<String, String> authorization = browser.requests.get(0);
        assertEquals("code", authorization.get("response_type"));
        assertEquals("openid offline_access", authorization.get("scope"));
        assertEquals("S256", authorization.get("code_challenge_method"));
        assertTrue(authorization.get("redirect_uri").startsWith("http://127.0.0.1:"));
        assertNull(authorization.get("dpop_jkt"));

        Map<String, String> exchange = idp.tokenRequests.get(0).form();
        assertEquals("authorization_code", exchange.get("grant_type"));
        assertEquals("app", exchange.get("client_id"));
        assertEquals(authorization.get("redirect_uri"), exchange.get("redirect_uri"));
        assertEquals(authorization.get("code_challenge"), s256(exchange.get("code_verifier")));
        assertNull(idp.tokenRequests.get(0).dpop());
    }

    @Test
    void anErrorFromTheAuthorizationServerFailsTheLogin() {
        SimulatedBrowser browser = SimulatedBrowser.denying("access_denied");

        IOException e = assertThrows(IOException.class,
                () -> flow(browser).login(idp.issuer(), null, null, "app", null, null));
        assertTrue(e.getMessage().contains("access_denied"), e.getMessage());
        assertTrue(idp.tokenRequests.isEmpty());
    }

    // ------------------------------------------------------------------ loopback hardening (P2-S5)

    @Test
    void aForgedCallbackDoesNotEndTheLogin() throws Exception {
        SimulatedBrowser browser = SimulatedBrowser.approving("the-code");
        browser.forgedRequestFirst = true;

        AuthorizationCodeFlow.Tokens t = flow(browser).login(idp.issuer(), null, null, "app", null, null);

        assertEquals("at", t.accessToken());
        assertEquals(400, browser.callbackResponses.get(0).statusCode(), "the forged request was ignored");
        assertEquals(200, browser.callbackResponses.get(1).statusCode());
    }

    @Test
    void theErrorDescriptionIsReportedAndEscaped() {
        SimulatedBrowser browser = SimulatedBrowser.denying("access_denied", "<script>alert(1)</script>");

        IOException e = assertThrows(IOException.class,
                () -> flow(browser).login(idp.issuer(), null, null, "app", null, null));
        assertTrue(e.getMessage().contains("<script>alert(1)</script>"), e.getMessage());
        String page = browser.callbackResponses.get(0).body();
        assertFalse(page.contains("<script>"), page);
        assertTrue(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), page);
    }

    @Test
    void aResponseNamingAnotherIssuerIsRejected() {
        SimulatedBrowser browser = SimulatedBrowser.approving("the-code");
        browser.iss = "https://other-idp.example";

        IOException e = assertThrows(IOException.class,
                () -> flow(browser).login(idp.issuer(), null, null, "app", null, null));
        assertTrue(e.getMessage().contains("RFC 9207"), e.getMessage());
        assertTrue(idp.tokenRequests.isEmpty(), "the code is not sent anywhere");
    }

    @Test
    void aMissingIssIsRejectedWhenTheProviderPromisedIt() {
        idp.issParameterSupported = true;
        SimulatedBrowser browser = SimulatedBrowser.approving("the-code");

        assertThrows(IOException.class, () -> flow(browser).login(idp.issuer(), null, null, "app", null, null));
        assertTrue(idp.tokenRequests.isEmpty());
    }

    @Test
    void theRightIssIsAccepted() throws Exception {
        idp.issParameterSupported = true;
        SimulatedBrowser browser = SimulatedBrowser.approving("the-code");
        browser.iss = idp.issuer().toString();

        assertEquals("at", flow(browser).login(idp.issuer(), null, null, "app", null, null).accessToken());
    }

    // ------------------------------------------------------------------ endpoint checks (P2-S2, P2-S6)

    @Test
    void anAuthorizationEndpointThatIsNotAWebUrlIsNeverOpened() {
        for (String endpoint : List.of("file:///etc/passwd", "ms-settings:privacy", "http://idp.example/authorize")) {
            idp.authorizationEndpoint = endpoint;
            SimulatedBrowser browser = SimulatedBrowser.approving("the-code");

            IOException e = assertThrows(IOException.class,
                    () -> flow(browser).login(idp.issuer(), null, null, "app", null, null), endpoint);
            assertTrue(e.getMessage().contains("Refusing to open"), e.getMessage());
            assertTrue(browser.requests.isEmpty(), endpoint);
        }
    }

    @Test
    void discoveryRejectsMetadataForAnotherIssuer() {
        idp.advertisedIssuer = "https://evil.example";

        IOException e = assertThrows(IOException.class,
                () -> OpenIdDiscovery.discover(HttpClient.newHttpClient(), idp.issuer(), Duration.ofSeconds(5)));
        assertTrue(e.getMessage().contains("https://evil.example"), e.getMessage());
    }

    @Test
    void discoveryToleratesATrailingSlash() throws Exception {
        idp.advertisedIssuer = idp.issuer() + "/";

        assertEquals(idp.advertisedIssuer,
                OpenIdDiscovery.discover(HttpClient.newHttpClient(), idp.issuer(), Duration.ofSeconds(5)).issuer().toString());
    }

    // ------------------------------------------------------------------ DPoP (P2-S7)

    @Test
    void dpopBindsTheCodeAndTheExchangeToTheKey() throws Exception {
        idp.tokenHandler = req -> Reply.ok(tokens("at", "rt", 60, "DPoP"));
        DPoP dpop = new DPoP();
        SimulatedBrowser browser = SimulatedBrowser.approving("the-code");

        AuthorizationCodeFlow.Tokens t = flow(browser).login(idp.issuer(), null, null, "app", null, null, dpop);

        assertEquals("DPoP", t.tokenType());
        assertEquals(dpop.thumbprint(), browser.requests.get(0).get("dpop_jkt"));
        JWTClaimsSet proof = SignedJWT.parse(idp.tokenRequests.get(0).dpop()).getJWTClaimsSet();
        assertEquals("POST", proof.getStringClaim("htm"));
        assertEquals(idp.issuer() + "/token", proof.getStringClaim("htu"));
    }

    @Test
    void aNonceDemandedByTheTokenEndpointIsSentOnTheRetry() throws Exception {
        idp.tokenHandler = req -> nonceOf(req.dpop()) == null
                ? Reply.error(400, "use_dpop_nonce").withHeader("DPoP-Nonce", "n-1")
                : Reply.ok(tokens("at", "rt", 60, "DPoP"));
        DPoP dpop = new DPoP();

        flow(SimulatedBrowser.approving("the-code")).login(idp.issuer(), null, null, "app", null, null, dpop);

        assertEquals(2, idp.tokenRequests.size());
        assertEquals("n-1", nonceOf(idp.tokenRequests.get(1).dpop()));
    }

    static String nonceOf(String proof) {
        if (proof == null) {
            return null;
        }
        try {
            return SignedJWT.parse(proof).getJWTClaimsSet().getStringClaim("nonce");
        } catch (java.text.ParseException e) {
            throw new IllegalStateException(e);
        }
    }

    private static AuthorizationCodeFlow flow(SimulatedBrowser browser) {
        return new AuthorizationCodeFlow(HttpClient.newHttpClient(), Duration.ofSeconds(10))
                .browserOpener(browser)
                .loginTimeout(Duration.ofSeconds(10));
    }

    private static String s256(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }
}
