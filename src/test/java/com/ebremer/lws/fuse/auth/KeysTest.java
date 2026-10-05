package com.ebremer.lws.fuse.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class KeysTest {

    @TempDir
    Path dir;

    @Test
    void generatesOnceThenReloadsTheSameKey() throws Exception {
        Path file = dir.resolve("lws/did-key.jwk");
        ECKey first = Keys.loadOrGenerateP256(file);
        assertTrue(Files.exists(file));

        ECKey again = Keys.loadOrGenerateP256(file);
        assertTrue(again.isPrivate());
        assertEquals(first.computeThumbprint(), again.computeThumbprint());
    }

    @Test
    void aCorruptKeyFileIsReportedAndLeftUntouched() throws Exception {
        Path file = Files.writeString(dir.resolve("did-key.jwk"), "{ not a key");

        assertThrows(IllegalStateException.class, () -> Keys.loadOrGenerateP256(file));
        assertEquals("{ not a key", Files.readString(file));
    }

    @Test
    void aPublicOnlyKeyIsRejected() throws Exception {
        String publicJwk = new ECKeyGenerator(Curve.P_256).generate().toPublicJWK().toJSONString();
        Path file = Files.writeString(dir.resolve("did-key.jwk"), publicJwk);

        assertThrows(IllegalStateException.class, () -> Keys.loadOrGenerateP256(file));
        assertEquals(publicJwk, Files.readString(file));
    }

    @Test
    void aKeyOnAnotherCurveIsRejected() throws Exception {
        String p384 = new ECKeyGenerator(Curve.P_384).generate().toJSONString();
        Path file = Files.writeString(dir.resolve("did-key.jwk"), p384);

        assertThrows(IllegalStateException.class, () -> Keys.loadOrGenerateP256(file));
        assertEquals(p384, Files.readString(file));
    }

    @Test
    void withoutAFileEveryKeyIsEphemeral() throws Exception {
        assertNotEquals(Keys.loadOrGenerateP256(null).computeThumbprint(),
                Keys.loadOrGenerateP256(null).computeThumbprint());
    }
}
