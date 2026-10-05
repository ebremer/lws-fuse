package com.ebremer.lws.fuse.auth;

import java.math.BigInteger;

/**
 * Base58 (Bitcoin/base58btc alphabet) encoder — the multibase {@code z} encoding used by
 * {@code did:key}.
 *
 * @author Erich Bremer
 */
final class Base58 {

    private static final String ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    private static final BigInteger BASE = BigInteger.valueOf(58);

    private Base58() {
    }

    static String encode(byte[] input) {
        if (input.length == 0) {
            return "";
        }
        int leadingZeros = 0;
        while (leadingZeros < input.length && input[leadingZeros] == 0) {
            leadingZeros++;
        }
        BigInteger value = new BigInteger(1, input);
        StringBuilder sb = new StringBuilder();
        while (value.signum() > 0) {
            BigInteger[] qr = value.divideAndRemainder(BASE);
            sb.append(ALPHABET.charAt(qr[1].intValue()));
            value = qr[0];
        }
        for (int i = 0; i < leadingZeros; i++) {
            sb.append(ALPHABET.charAt(0));   // '1' per leading zero byte
        }
        return sb.reverse().toString();
    }
}
