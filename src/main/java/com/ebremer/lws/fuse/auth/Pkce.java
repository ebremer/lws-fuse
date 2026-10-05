package com.ebremer.lws.fuse.auth;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * A PKCE (RFC 7636) {@code code_verifier}/{@code code_challenge} pair using the {@code S256}
 * method — proof-of-possession for the authorization-code flow so the code cannot be replayed by
 * an interceptor. One instance per login attempt.
 *
 * @author Erich Bremer
 */
public final class Pkce {

    private static final SecureRandom RNG = new SecureRandom();

    private final String verifier;
    private final String challenge;

    public Pkce() {
        byte[] raw = new byte[32];
        RNG.nextBytes(raw);
        this.verifier = base64Url(raw);                       // 43-char high-entropy verifier
        this.challenge = base64Url(sha256(this.verifier));    // S256 challenge
    }

    public String verifier() {
        return verifier;
    }

    public String challenge() {
        return challenge;
    }

    public String method() {
        return "S256";
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
