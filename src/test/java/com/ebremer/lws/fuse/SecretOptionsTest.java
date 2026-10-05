package com.ebremer.lws.fuse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** Secrets given as {@code -D<name>File}, {@code -D<name>}, or an environment variable (P2-S3). */
class SecretOptionsTest {

    private static final String PROPERTY = "lws.testSecret";
    private static final String ENV = "LWS_TEST_SECRET_THAT_IS_NOT_SET";

    @TempDir
    Path dir;

    @AfterEach
    void clear() {
        System.clearProperty(PROPERTY);
        System.clearProperty(PROPERTY + "File");
    }

    @Test
    void aSecretFileIsReadAndTrimmed() throws IOException {
        Path file = Files.writeString(dir.resolve("secret.txt"), "  s3cret\r\n");
        System.setProperty(PROPERTY + "File", file.toString());
        System.setProperty(PROPERTY, "ignored when a file is given");

        assertEquals("s3cret", LWSFileSystem.secret(PROPERTY, ENV));
    }

    @Test
    void anInlineValueStillWorks() {
        System.setProperty(PROPERTY, "inline");
        assertEquals("inline", LWSFileSystem.secret(PROPERTY, ENV));
    }

    @Test
    void nothingGivenIsNull() {
        assertNull(LWSFileSystem.secret(PROPERTY, ENV));
    }

    @Test
    void anUnreadableFileIsAnError() {
        System.setProperty(PROPERTY + "File", dir.resolve("missing").toString());
        assertThrows(IllegalArgumentException.class, () -> LWSFileSystem.secret(PROPERTY, ENV));
    }
}
