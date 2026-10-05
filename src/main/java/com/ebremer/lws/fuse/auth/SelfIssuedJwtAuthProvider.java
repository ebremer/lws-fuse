package com.ebremer.lws.fuse.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpRequest;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

/**
 * Presents a <em>self-issued</em> authentication credential — a signed JWT whose {@code iss},
 * {@code sub}, and {@code client_id} are all the same identifier — as an OAuth 2.0 Bearer token.
 *
 * <p>This is the credential of the LWS
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/">SSI controlled-identifier</a>
 * authentication suite, whose identifier is either
 * <ul>
 *   <li>an HTTPS URI resolving to a Controlled Identifier Document whose verification method holds
 *       the public key, or</li>
 *   <li>a DID: here a {@code did:key:…} URI derived from the signing key (see {@link DidKey}).</li>
 * </ul>
 * Either way the resource server resolves the identifier to the public key that verifies the JWT.
 * The credential is signed with ES256 (P-256) and carries {@code aud}/{@code iat}/{@code exp} and a
 * unique {@code jti}.
 *
 * <p>Under LWS authorization it is a {@link CredentialSource}: {@link LwsAuthProvider} exchanges a
 * JWT whose {@code aud} is the authorization server (as the suite requires) for an access token
 * (token type {@code urn:ietf:params:oauth:token-type:jwt}). Each exchange gets a freshly minted
 * JWT, so an authorization server that rejects replayed {@code jti}s accepts every one. For servers
 * following earlier drafts it is also presented directly as {@code Authorization: Bearer <jwt>},
 * with {@code aud} set to the configured audience (by default the storage); that one is cached and
 * re-minted shortly before expiry.
 *
 * @author Erich Bremer
 */
public final class SelfIssuedJwtAuthProvider implements AuthProvider, CredentialSource {

    private final String identifier;
    private final ECKey signingKey;
    private final Duration ttl;
    private final String kid;
    private final TokenCache cache;   // for direct presentation, audience = the configured one

    public SelfIssuedJwtAuthProvider(String identifier, ECKey signingKey, String audience,
                                     Duration ttl, String kid) {
        this.identifier = identifier;
        this.signingKey = signingKey;
        this.ttl = ttl;
        this.kid = kid;
        this.cache = new TokenCache(() -> mint(identifier, signingKey, audience, ttl, kid));
    }

    /** The subject (= issuer = client) identifier this provider asserts. */
    public String identifier() {
        return identifier;
    }

    /** Controlled-identifier suite with a did:key subject: the key's {@code did:key:…} URI. */
    public static SelfIssuedJwtAuthProvider didKey(ECKey key, String audience, Duration ttl) {
        String did = DidKey.fromP256(key);
        return new SelfIssuedJwtAuthProvider(did, key, audience, ttl, DidKey.verificationMethodId(did));
    }

    /** SSI controlled-identifier (CID) suite: the identifier is an HTTPS controlled-identifier URI. */
    public static SelfIssuedJwtAuthProvider controlledIdentifier(String cid, ECKey key, String kid,
                                                                 String audience, Duration ttl) {
        return new SelfIssuedJwtAuthProvider(cid, key, audience, ttl, kid);
    }

    @Override
    public void authorize(HttpRequest.Builder builder, String method, URI uri) {
        builder.setHeader("Authorization", "Bearer " + cache.get(Instant.now()).accessToken());
    }

    /** A newly minted JWT whose audience is {@code authorizationServer}. */
    @Override
    public Credential credential(URI authorizationServer) {
        try {
            return new Credential(mint(identifier, signingKey, authorizationServer.toString(), ttl, kid).accessToken(),
                    JWT, identifier);
        } catch (JOSEException e) {
            throw new AuthException("Cannot sign the self-issued credential: " + e.getMessage(), e);
        }
    }

    private static TokenCache.Token mint(String identifier, ECKey key, String audience,
                                         Duration ttl, String kid) throws JOSEException {
        Instant now = Instant.now();
        Instant exp = now.plus(ttl);
        JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                .issuer(identifier)
                .subject(identifier)
                .claim("client_id", identifier)
                .issueTime(Date.from(now))
                .expirationTime(Date.from(exp))
                .jwtID(UUID.randomUUID().toString());
        if (audience != null && !audience.isBlank()) {
            claims.audience(audience);
        }
        JWSHeader.Builder header = new JWSHeader.Builder(JWSAlgorithm.ES256)
                .type(JOSEObjectType.JWT)
                .jwk(key.toPublicJWK());
        if (kid != null) {
            header.keyID(kid);
        }
        SignedJWT jwt = new SignedJWT(header.build(), claims.build());
        jwt.sign(new ECDSASigner(key));
        return new TokenCache.Token(jwt.serialize(), "Bearer", exp);
    }
}
