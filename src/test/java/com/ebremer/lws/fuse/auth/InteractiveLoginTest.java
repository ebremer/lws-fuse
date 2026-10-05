package com.ebremer.lws.fuse.auth;

import static com.ebremer.lws.fuse.auth.MockOpenIdServer.tokens;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.MockOpenIdServer.Reply;
import java.io.IOException;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.time.Duration;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class InteractiveLoginTest {

    @TempDir
    Path dir;

    private MockOpenIdServer idp;
    private CredentialStore store;
    /** Refresh tokens the IdP currently accepts; each use rotates a token to {@code token + "+"}. */
    private final Set<String> live = ConcurrentHashMap.newKeySet();

    @BeforeEach
    void start() throws IOException {
        idp = new MockOpenIdServer();
        store = new CredentialStore(dir.resolve("credentials.properties"));
        idp.tokenHandler = req -> switch (req.form().get("grant_type")) {
            case "authorization_code" -> {
                live.add("rt-login");
                yield Reply.ok(tokens("at-login", "rt-login", 3600));
            }
            case "refresh_token" -> {
                String used = req.form().get("refresh_token");
                if (!live.remove(used)) {
                    yield Reply.error(400, "invalid_grant");
                }
                live.add(used + "+");
                yield Reply.ok(tokens("at-" + used + "+", used + "+", 3600));
            }
            default -> Reply.error(400, "unsupported_grant_type");
        };
    }

    @AfterEach
    void stop() {
        idp.close();
    }

    @Test
    void usesTheSavedTokenAndSavesItsRotation() throws Exception {
        live.add("rt0");
        save("rt0");
        SimulatedBrowser browser = SimulatedBrowser.approving("c");

        AuthProvider provider = login(browser, false);

        assertTrue(browser.requests.isEmpty(), "no browser login needed");
        assertEquals("rt0+", saved(), "the rotated token replaced the spent one");
        assertEquals("Bearer at-rt0+", OpenIdAuthProviderTest.authorize(provider));
    }

    @Test
    void logsInAgainWhenTheSavedTokenIsRejected() throws Exception {
        save("revoked");
        SimulatedBrowser browser = SimulatedBrowser.approving("c");

        AuthProvider provider = login(browser, false);

        assertEquals(1, browser.requests.size());
        assertEquals("rt-login", saved());
        assertEquals("Bearer at-login", OpenIdAuthProviderTest.authorize(provider),
                "the login's own access token is used; nothing is refreshed yet");
    }

    @Test
    void logsInWhenNothingIsSaved() throws Exception {
        SimulatedBrowser browser = SimulatedBrowser.approving("c");

        login(browser, false);

        assertEquals(1, browser.requests.size());
        assertEquals("rt-login", saved());
    }

    @Test
    void forceLoginIgnoresTheSavedToken() throws Exception {
        live.add("rt0");
        save("rt0");
        SimulatedBrowser browser = SimulatedBrowser.approving("c");

        login(browser, true);

        assertEquals(1, browser.requests.size());
        assertEquals("rt-login", saved());
    }

    @Test
    void otherTokenEndpointFailuresAreReportedNotMaskedByALogin() throws Exception {
        idp.tokenHandler = req -> Reply.error(500, "server_error");
        save("rt0");
        SimulatedBrowser browser = SimulatedBrowser.approving("c");

        TokenEndpointException e = assertThrows(TokenEndpointException.class, () -> login(browser, false));
        assertEquals(500, e.status());
        assertTrue(browser.requests.isEmpty());
        assertEquals("rt0", saved());
    }

    private AuthProvider login(SimulatedBrowser browser, boolean force) throws Exception {
        HttpClient http = HttpClient.newHttpClient();
        AuthorizationCodeFlow flow = new AuthorizationCodeFlow(http, Duration.ofSeconds(10))
                .browserOpener(browser)
                .loginTimeout(Duration.ofSeconds(10));
        OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
        cfg.issuer = idp.issuer();
        cfg.clientId = "app";
        return new InteractiveLogin(http, store, flow, Duration.ofSeconds(10)).authenticate(cfg, force);
    }

    private void save(String refreshToken) throws IOException {
        store.saveRefreshToken(idp.issuer().toString(), "app", refreshToken);
    }

    private String saved() {
        return store.loadRefreshToken(idp.issuer().toString(), "app");
    }
}
