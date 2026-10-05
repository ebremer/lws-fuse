package com.ebremer.lws.fuse.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.util.Base64URL;
import org.junit.jupiter.api.Test;

class DidKeyTest {

    /**
     * The P-256 vector from the did:key method's NIST-curve test vectors
     * (w3c-ccg/did-method-key, {@code test-vectors/nist-curves.json}).
     */
    @Test
    void matchesTheSpecP256TestVector() {
        ECKey key = new ECKey.Builder(Curve.P_256,
                new Base64URL("fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI"),
                new Base64URL("hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU")).build();

        assertEquals("did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", DidKey.fromP256(key));
    }

    @Test
    void verificationMethodIdRepeatsTheMultibaseKey() {
        assertEquals("did:key:zDnabc#zDnabc", DidKey.verificationMethodId("did:key:zDnabc"));
    }

    /** Random keys exercise the 32-byte padding of X coordinates with leading zero bytes. */
    @Test
    void everyP256KeyHasTheP256PrefixAndLength() {
        for (int i = 0; i < 300; i++) {
            String did = DidKey.fromP256(Keys.loadOrGenerateP256(null));   // a fresh ephemeral key
            assertTrue(did.startsWith("did:key:zDn"), did);
            assertEquals(57, did.length(), did);
        }
    }
}
