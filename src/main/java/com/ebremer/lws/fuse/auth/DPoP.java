package com.ebremer.lws.fuse.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.net.http.HttpHeaders;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * RFC 9449 DPoP proof generator. Holds one EC (P-256 / ES256) key and mints a per-request proof
 * JWT ({@code typ=dpop+jwt}) binding the HTTP method and URI, plus the access-token hash
 * ({@code ath}) when proving a request to a resource server.
 *
 * <p>The key is ephemeral by default. A refresh token that is kept across runs must be used with
 * the key it was bound to, so the interactive login passes a persisted key instead.
 *
 * <p>Servers may demand a nonce (RFC 9449 §8–9): the latest {@code DPoP-Nonce} each server sent is
 * remembered per origin ({@link #rememberNonce}) and included in later proofs to that origin.
 *
 * <p>Optional: an {@link OpenIdAuthProvider} only uses this when its {@code Config.dpop} is set,
 * i.e. when DPoP-bound tokens are wanted. The default LWS flow uses plain Bearer tokens and never
 * touches this class.
 *
 * @author Erich Bremer
 */
public final class DPoP {

    private static final JWSAlgorithm ALG = JWSAlgorithm.ES256;

    private final ECKey publicJwk;
    private final JWSSigner signer;
    private final Map<String, String> nonces = new ConcurrentHashMap<>();   // origin -> latest nonce

    /** A DPoP signer with a fresh, ephemeral key. */
    public DPoP() {
        this(generate());
    }

    /** A DPoP signer with the given private P-256 key (e.g. one persisted with {@link Keys}). */
    public DPoP(ECKey keyPair) {
        try {
            this.publicJwk = keyPair.toPublicJWK();
            this.signer = new ECDSASigner(keyPair);
        } catch (JOSEException e) {
            throw new IllegalStateException("Unusable DPoP key", e);
        }
    }

    private static ECKey generate() {
        try {
            return new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate DPoP key", e);
        }
    }

    /**
     * Build a DPoP proof JWT for an HTTP {@code method} request to {@code uri}, carrying the
     * server's latest nonce if it has sent one.
     *
     * @param accessToken the access token to bind via {@code ath}, or {@code null} for a token-
     *                    endpoint request (which has no access token yet)
     */
    public String proof(String method, URI uri, String accessToken) {
        try {
            JWTClaimsSet.Builder claims = new JWTClaimsSet.Builder()
                    .jwtID(UUID.randomUUID().toString())
                    .claim("htm", method)
                    .claim("htu", htu(uri))
                    .issueTime(Date.from(Instant.now()));
            if (accessToken != null) {
                claims.claim("ath", base64Url(sha256(accessToken)));
            }
            String nonce = nonces.get(origin(uri));
            if (nonce != null) {
                claims.claim("nonce", nonce);
            }
            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(ALG)
                            .type(new JOSEObjectType("dpop+jwt"))
                            .jwk(publicJwk)
                            .build(),
                    claims.build());
            jwt.sign(signer);
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot create DPoP proof", e);
        }
    }

    /**
     * Remember the {@code DPoP-Nonce} a response from {@code uri}'s server carried, if any.
     *
     * @return true if the response carried a nonce
     */
    public boolean rememberNonce(URI uri, HttpHeaders headers) {
        String nonce = headers.firstValue("DPoP-Nonce").orElse(null);
        if (nonce == null || nonce.isBlank()) {
            return false;
        }
        nonces.put(origin(uri), nonce.trim());
        return true;
    }

    /** The RFC 7638 SHA-256 thumbprint of the public key, as sent in {@code dpop_jkt}. */
    public String thumbprint() {
        try {
            return publicJwk.computeThumbprint().toString();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot compute the DPoP key thumbprint", e);
        }
    }

    /**
     * The {@code htu} claim: the request URI without query and fragment, exactly as sent on the
     * wire — the raw (still percent-encoded) path, so names containing {@code %XX} match.
     */
    static String htu(URI uri) {
        String path = uri.getRawPath();
        return uri.getScheme() + "://" + uri.getRawAuthority() + (path == null ? "" : path);
    }

    private static String origin(URI uri) {
        int port = uri.getPort() >= 0 ? uri.getPort() : ("https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80);
        return (uri.getScheme() + "://" + uri.getHost() + ":" + port).toLowerCase(Locale.ROOT);
    }

    private static byte[] sha256(String value) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.US_ASCII));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static String base64Url(byte[] bytes) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
