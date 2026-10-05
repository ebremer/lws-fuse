package com.ebremer.lws.fuse.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import java.math.BigInteger;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;

/**
 * Derives a {@code did:key} identifier for a P-256 key, per the did:key method (multicodec
 * {@code p256-pub} + multibase base58btc), used as a DID subject in the LWS controlled-identifier
 * authentication suite.
 *
 * @see <a href="https://w3c-ccg.github.io/did-method-key/">did:key method</a>
 * @author Erich Bremer
 */
public final class DidKey {

    // multicodec p256-pub (0x1200) as an unsigned LEB128 varint
    private static final byte[] P256_MULTICODEC = {(byte) 0x80, (byte) 0x24};

    private DidKey() {
    }

    /** The {@code did:key:…} URI for the public part of a P-256 key. */
    public static String fromP256(ECKey key) {
        return "did:key:" + multibase(key);
    }

    /** The multibase (z…) suffix that follows {@code did:key:}. */
    public static String multibase(ECKey key) {
        try {
            byte[] compressed = compress(key.toECPublicKey());
            byte[] prefixed = new byte[P256_MULTICODEC.length + compressed.length];
            System.arraycopy(P256_MULTICODEC, 0, prefixed, 0, P256_MULTICODEC.length);
            System.arraycopy(compressed, 0, prefixed, P256_MULTICODEC.length, compressed.length);
            return "z" + Base58.encode(prefixed);
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot derive did:key from key", e);
        }
    }

    /** The verification-method id ({@code did#z…}) used as the JWT {@code kid}. */
    public static String verificationMethodId(String did) {
        return did + "#" + did.substring("did:key:".length());
    }

    /** SEC1 compressed point: 0x02/0x03 parity byte + 32-byte big-endian X. */
    private static byte[] compress(ECPublicKey pub) {
        ECPoint w = pub.getW();
        byte[] out = new byte[33];
        out[0] = w.getAffineY().testBit(0) ? (byte) 0x03 : (byte) 0x02;
        byte[] x = to32(w.getAffineX());
        System.arraycopy(x, 0, out, 1, 32);
        return out;
    }

    private static byte[] to32(BigInteger v) {
        byte[] b = v.toByteArray();
        if (b.length == 32) {
            return b;
        }
        byte[] r = new byte[32];
        if (b.length > 32) {
            System.arraycopy(b, b.length - 32, r, 0, 32);   // strip sign byte
        } else {
            System.arraycopy(b, 0, r, 32 - b.length, b.length);   // left-pad
        }
        return r;
    }
}
