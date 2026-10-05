package com.ebremer.lws.fuse.auth;

import static com.ebremer.lws.fuse.auth.MockOpenIdServer.tokens;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.LWSClient;
import com.ebremer.lws.fuse.LWSException;
import com.ebremer.lws.fuse.MockLwsServer;
import com.ebremer.lws.fuse.auth.MockOpenIdServer.Reply;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** LWS authorization: 401 challenge → authorization server metadata → token exchange (LWS core §Authorization). */
class LwsAuthProviderTest {

    private static final String TOKEN_EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange";

    private MockLwsServer storage;
    private MockOpenIdServer as;
    private final AtomicInteger issued = new AtomicInteger();
    /** A fixed credential, so the tests can see what was exchanged. */
    private final CredentialSource credential =
            server -> new CredentialSource.Credential("the-credential", CredentialSource.JWT, "https://id.example/agent");

    @BeforeEach
    void start() throws IOException {
        storage = new MockLwsServer();
        as = new MockOpenIdServer();
        storage.authorizationServer = as.issuer();
        storage.requiredToken = "AT-1";
        storage.putFile("/alice/a.txt", "secret");
        as.tokenHandler = req -> TOKEN_EXCHANGE.equals(req.form().get("grant_type"))
                ? Reply.ok(tokens("AT-" + issued.incrementAndGet(), null, 3600))
                : Reply.error(400, "unsupported_grant_type");
    }

    @AfterEach
    void stop() {
        storage.close();
        as.close();
    }

    @Test
    void theCredentialIsExchangedAtTheAuthorizationServerTheStorageNames() {
        LWSClient client = client(provider(null, null));

        assertEquals("secret", new String(client.readAll("/a.txt"), UTF_8));
        assertEquals(1, as.tokenRequests.size());
        Map<String, String> form = as.tokenRequests.get(0).form();
        assertEquals(TOKEN_EXCHANGE, form.get("grant_type"));
        assertEquals(storage.base().toString(), form.get("resource"), "resource is the challenge's realm");
        assertEquals("the-credential", form.get("subject_token"));
        assertEquals(CredentialSource.JWT, form.get("subject_token_type"));

        client.readAll("/a.txt");
        client.stat("/a.txt");
        assertEquals(1, as.tokenRequests.size(), "the access token is reused within the realm");
    }

    @Test
    void anExpiringTokenIsExchangedAgainBeforeUse() {
        as.tokenHandler = req -> Reply.ok(tokens("AT-1", null, 1));   // inside the 30 s renewal margin
        LWSClient client = client(provider(null, null));

        client.readAll("/a.txt");
        client.readAll("/a.txt");
        assertTrue(as.tokenRequests.size() >= 2, "renewed: " + as.tokenRequests.size());
    }

    @Test
    void aTokenTheStorageRejectsIsReplaced() {
        LwsAuthProvider provider = provider(null, null);
        provider.minTokenAgeForRenewal = Duration.ZERO;
        LWSClient client = client(provider);
        client.readAll("/a.txt");

        storage.requiredToken = "AT-2";   // AT-1 revoked
        assertEquals("secret", new String(client.readAll("/a.txt"), UTF_8));
        assertEquals(2, as.tokenRequests.size());
    }

    @Test
    void aBrandNewTokenThatIsRefusedMeansNotPermitted() {
        LWSClient client = client(provider(null, null));
        client.readAll("/a.txt");

        storage.requiredToken = "AT-2";
        LWSException e = assertThrows(LWSException.class, () -> client.readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        assertEquals(1, as.tokenRequests.size(), "no second exchange for a token issued seconds ago");
    }

    @Test
    void aRealmThatDoesNotContainTheRequestIsRefused() {
        storage.realm = URI.create(storage.base().resolve("/bob/").toString());
        LWSException e = assertThrows(LWSException.class, () -> client(provider(null, null)).readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        assertTrue(as.tokenRequests.isEmpty());
    }

    @Test
    void metadataNamingAnotherIssuerIsRejected() {
        as.lwsIssuer = "https://impostor.example";
        LWSException e = assertThrows(LWSException.class, () -> client(provider(null, null)).readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        assertTrue(as.tokenRequests.isEmpty(), "no credential is sent to it");
    }

    @Test
    void onlyThePinnedAuthorizationServerIsUsed() {
        LwsAuthProvider pinned = new LwsAuthProvider(HttpClient.newHttpClient(), credential, null,
                Duration.ofSeconds(5), URI.create("https://as.example"));
        LWSException e = assertThrows(LWSException.class, () -> client(pinned).readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        assertTrue(as.tokenRequests.isEmpty());
    }

    @Test
    void serversWithoutAnLwsChallengeGetTheCredentialDirectly() {
        storage.authorizationServer = null;   // a bare "WWW-Authenticate: Bearer" (earlier drafts)
        storage.requiredToken = "direct";
        LWSClient client = client(provider(AuthProvider.bearer("direct"), null));

        assertEquals("secret", new String(client.readAll("/a.txt"), UTF_8));
        assertTrue(as.tokenRequests.isEmpty());
    }

    @Test
    void anOriginThatUsesLwsAuthorizationIsNeverGivenTheCredentialDirectly() {
        storage.putFile("/alice/sub/b.txt", "b");
        storage.realm = storage.base().resolve("sub/");
        LwsAuthProvider provider = provider(AuthProvider.bearer("direct"), null);
        LWSClient inRealm = new LWSClient(storage.base().resolve("sub/"), provider);
        assertEquals("b", new String(inRealm.readAll("/b.txt"), UTF_8));   // through the LWS challenge

        storage.authorizationServer = null;   // now a bare challenge, as if to downgrade the client
        storage.requiredToken = "direct";
        LWSException e = assertThrows(LWSException.class, () -> client(provider).readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind(),
                "outside the realm, the credential is still not presented directly on this origin");
    }

    @Test
    void aLaterChallengeIsUsedWhenAnEarlierOneIsNotAcceptable() {
        storage.extraChallenge = "Bearer as_uri=\"https://elsewhere.example\", realm=\"" + storage.base() + "\"";
        LwsAuthProvider pinned = new LwsAuthProvider(HttpClient.newHttpClient(), credential, null,
                Duration.ofSeconds(5), as.issuer());

        assertEquals("secret", new String(client(pinned).readAll("/a.txt"), UTF_8));
        assertEquals(1, as.tokenRequests.size());
    }

    @Test
    void theCredentialIsAddressedToTheAuthorizationServersIssuerIdentifier() {
        storage.authorizationServer = URI.create(as.issuer() + "/");   // the challenge spells it with a '/'
        AtomicReference<URI> addressedTo = new AtomicReference<>();
        CredentialSource recording = server -> {
            addressedTo.set(server);
            return new CredentialSource.Credential("the-credential", CredentialSource.JWT, "https://id.example/agent");
        };
        client(new LwsAuthProvider(HttpClient.newHttpClient(), recording, null, Duration.ofSeconds(5), null))
                .readAll("/a.txt");

        assertEquals(as.issuer(), addressedTo.get(), "the metadata's issuer, which a self-issued JWT puts in aud");
    }

    @Test
    void aCredentialTypeTheServerDoesNotTakeIsNotSent() {
        as.subjectTokenTypes = "[\"urn:ietf:params:oauth:token-type:saml2\"]";
        LWSException e = assertThrows(LWSException.class, () -> client(provider(null, null)).readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        assertTrue(as.tokenRequests.isEmpty(), "the credential was not sent");
    }

    @Test
    void theHyphenatedIdTokenTypeIsUnderstood() {
        as.subjectTokenTypes = "[\"urn:ietf:params:oauth:token-type:id-token\"]";   // as in the LWS example
        CredentialSource idToken = server -> new CredentialSource.Credential(
                "an-id-token", CredentialSource.ID_TOKEN, "https://id.example/alice");
        LWSClient client = client(new LwsAuthProvider(HttpClient.newHttpClient(), idToken, null, Duration.ofSeconds(5), null));

        assertEquals("secret", new String(client.readAll("/a.txt"), UTF_8));
        assertEquals(CredentialSource.ID_TOKEN, as.tokenRequests.get(0).form().get("subject_token_type"));
    }

    @Test
    void anAccessTokenOfAnotherTypeIsNotUsed() {
        as.tokenHandler = req -> Reply.ok(tokens("AT-1", null, 3600, "N_A"));
        LWSException e = assertThrows(LWSException.class, () -> client(provider(null, null)).readAll("/a.txt"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
    }

    // ------------------------------------------------------------------ credentials per suite

    @Test
    void aSelfIssuedCredentialNamesTheAuthorizationServerAsItsAudience() throws Exception {
        ECKey key = Keys.loadOrGenerateP256(null);
        SelfIssuedJwtAuthProvider cid = SelfIssuedJwtAuthProvider.controlledIdentifier(
                "https://id.example/agent", key, "https://id.example/agent#key-0", "https://storage.example/", Duration.ofMinutes(5));

        CredentialSource.Credential c = cid.credential(URI.create("https://as.example"));
        assertEquals(CredentialSource.JWT, c.tokenType());
        SignedJWT jwt = SignedJWT.parse(c.token());
        JWTClaimsSet claims = jwt.getJWTClaimsSet();
        assertEquals(List.of("https://as.example"), claims.getAudience());
        assertEquals("https://id.example/agent", claims.getSubject());
        assertEquals(claims.getSubject(), claims.getIssuer());
        assertEquals(claims.getSubject(), claims.getStringClaim("client_id"));
        assertTrue(claims.getExpirationTime() != null && claims.getIssueTime() != null);
        assertEquals("https://id.example/agent#key-0", jwt.getHeader().getKeyID());
    }

    @Test
    void eachExchangeGetsAFreshSelfIssuedJwt() throws Exception {
        SelfIssuedJwtAuthProvider cid = SelfIssuedJwtAuthProvider.controlledIdentifier("https://id.example/agent",
                Keys.loadOrGenerateP256(null), "https://id.example/agent#key-0", null, Duration.ofMinutes(5));
        URI server = URI.create("https://as.example");

        String first = cid.credential(server).token();
        String second = cid.credential(server).token();
        assertFalse(SignedJWT.parse(first).getJWTClaimsSet().getJWTID()
                .equals(SignedJWT.parse(second).getJWTClaimsSet().getJWTID()), "no jti is replayed");
    }

    @Test
    void anUnsignedIdTokenIsRefused() {
        String unsigned = new PlainJWT(new JWTClaimsSet.Builder().subject("https://id.example/alice")
                .issuer("https://op.example").claim("azp", "https://app.example/id")
                .expirationTime(Date.from(Instant.now().plusSeconds(600))).build()).serialize();
        as.tokenHandler = req -> Reply.ok("{\"access_token\":\"op-at\",\"token_type\":\"Bearer\",\"expires_in\":600,"
                + "\"id_token\":\"" + unsigned + "\"}");
        OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
        cfg.issuer = as.issuer();
        cfg.clientId = "https://app.example/id";
        cfg.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
        cfg.refreshToken = "rt";
        OpenIdAuthProvider openId = new OpenIdAuthProvider(HttpClient.newHttpClient(), cfg, Duration.ofSeconds(5));

        AuthException e = assertThrows(AuthException.class, () -> openId.credential(URI.create("https://as.example")));
        assertTrue(e.getMessage().contains("unsigned"), e.getMessage());
    }

    @Test
    void theOpenIdCredentialIsTheIdToken() throws Exception {
        String idToken = idToken("https://id.example/alice", Instant.now().plusSeconds(600));
        as.tokenHandler = req -> Reply.ok("{\"access_token\":\"op-at\",\"token_type\":\"Bearer\",\"expires_in\":600,"
                + "\"refresh_token\":\"rt\",\"id_token\":\"" + idToken + "\"}");
        OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
        cfg.issuer = as.issuer();
        cfg.clientId = "https://app.example/id";
        cfg.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
        cfg.refreshToken = "rt";
        OpenIdAuthProvider openId = new OpenIdAuthProvider(HttpClient.newHttpClient(), cfg, Duration.ofSeconds(5));

        CredentialSource.Credential c = openId.credential(URI.create("https://as.example"));
        assertEquals(idToken, c.token());
        assertEquals(CredentialSource.ID_TOKEN, c.tokenType());
        assertEquals("https://id.example/alice", c.subject());
    }

    @Test
    void clientCredentialsYieldNoLwsCredential() {
        OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
        cfg.issuer = as.issuer();
        cfg.clientId = "app";
        OpenIdAuthProvider openId = new OpenIdAuthProvider(HttpClient.newHttpClient(), cfg, Duration.ofSeconds(5));

        AuthException e = assertThrows(AuthException.class, () -> openId.credential(URI.create("https://as.example")));
        assertTrue(e.getMessage().contains("client-credentials"), e.getMessage());
    }

    @Test
    void theSamlCredentialIsTheBase64UrlAssertion() {
        byte[] xml = "<saml:Assertion/>".getBytes(UTF_8);
        CredentialSource.Credential c = new SamlAuthProvider(xml).credential(URI.create("https://as.example"));
        assertEquals(CredentialSource.SAML2, c.tokenType());
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(xml), c.token());
    }

    // ------------------------------------------------------------------ helpers under test

    @Test
    void realmContainment() {
        URI realm = URI.create("https://storage.example/storage_1");
        assertTrue(LwsAuthProvider.contains(realm, URI.create("https://storage.example/storage_1/a/b")));
        assertTrue(LwsAuthProvider.contains(realm, URI.create("https://storage.example/storage_1")));
        assertFalse(LwsAuthProvider.contains(realm, URI.create("https://storage.example/storage_10/a")));
        assertFalse(LwsAuthProvider.contains(realm, URI.create("http://storage.example/storage_1/a")));
        assertFalse(LwsAuthProvider.contains(realm, URI.create("https://other.example/storage_1/a")));
        assertTrue(LwsAuthProvider.contains(URI.create("https://storage.example"), URI.create("https://storage.example/x")));
    }

    @Test
    void metadataLivesUnderWellKnown() {
        assertEquals(List.of(URI.create("https://as.example/.well-known/lws-configuration")),
                LwsAuthProvider.metadataUrls(URI.create("https://as.example")));
        assertEquals(List.of(URI.create("https://as.example/.well-known/lws-configuration/tenant1"),
                        URI.create("https://as.example/tenant1/.well-known/lws-configuration"),
                        URI.create("https://as.example/.well-known/lws-configuration")),
                LwsAuthProvider.metadataUrls(URI.create("https://as.example/tenant1/")));
    }

    @Test
    void subjectIdentifierTypes() {
        assertEquals("https", LwsAuthProvider.identifierType("https://id.example/agent"));
        assertEquals("did:key", LwsAuthProvider.identifierType("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169"));
        assertEquals("did:web", LwsAuthProvider.identifierType("did:web:example.com"));
    }

    @Test
    void challengesAreParsed() {
        List<Challenges.Challenge> cs = Challenges.parse(List.of(
                "Bearer as_uri=\"https://as.example\", realm=\"https://storage.example/s1\", error=\"invalid_token\", "
                        + "DPoP algs=\"ES256 PS256\"",
                "Basic dXNlcjpwYXNz=="));
        assertEquals(3, cs.size());
        assertEquals("https://as.example", cs.get(0).param("as_uri"));
        assertEquals("https://storage.example/s1", cs.get(0).param("realm"));
        assertEquals("invalid_token", cs.get(0).param("error"));
        assertEquals("DPoP", cs.get(1).scheme());
        assertEquals("ES256 PS256", cs.get(1).param("algs"));
        assertEquals("Basic", cs.get(2).scheme());
        assertNull(cs.get(2).param("realm"));
    }

    private LwsAuthProvider provider(AuthProvider fallback, URI pinned) {
        return new LwsAuthProvider(HttpClient.newHttpClient(), credential, fallback, Duration.ofSeconds(5), pinned);
    }

    private LWSClient client(AuthProvider auth) {
        return new LWSClient(storage.base(), auth).retryPolicy(1, Duration.ofMillis(10), Duration.ofSeconds(1));
    }

    private static String idToken(String sub, Instant exp) throws Exception {
        ECKey key = Keys.loadOrGenerateP256(null);
        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.ES256).build(),
                new JWTClaimsSet.Builder().subject(sub).issuer("https://op.example").claim("azp", "https://app.example/id")
                        .audience("https://app.example/id").expirationTime(Date.from(exp)).issueTime(new Date()).build());
        jwt.sign(new ECDSASigner(key));
        return jwt.serialize();
    }
}
