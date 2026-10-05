package com.ebremer.lws.fuse.auth;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.IOException;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class PrivateFilesTest {

    @TempDir
    Path dir;

    @Test
    void writeAtomicallyReplacesTheFileAndLeavesNoTemporaries() throws IOException {
        Path file = dir.resolve("lws/credentials.properties");
        PrivateFiles.writeAtomically(file, "one".getBytes(UTF_8));
        PrivateFiles.writeAtomically(file, "two".getBytes(UTF_8));

        assertEquals("two", Files.readString(file));
        try (Stream<Path> files = Files.list(file.getParent())) {
            assertEquals(List.of(file), files.toList());
        }
    }

    @Test
    void createNewNeverOverwrites() throws IOException {
        Path file = dir.resolve("key.jwk");
        PrivateFiles.createNew(file, "first".getBytes(UTF_8));

        assertThrows(FileAlreadyExistsException.class, () -> PrivateFiles.createNew(file, "second".getBytes(UTF_8)));
        assertEquals("first", Files.readString(file));
    }

    @Test
    void filesAndDirectoriesAreOwnerOnlyFromTheStart() throws IOException {
        Path sub = dir.resolve("private");
        Path file = sub.resolve("secret");
        PrivateFiles.writeAtomically(file, "s".getBytes(UTF_8));

        if (Files.getFileStore(file).supportsFileAttributeView("posix")) {
            assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)));
            assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(sub)));
        } else if (Files.getFileStore(file).supportsFileAttributeView("acl")) {
            // Windows: the current user is the only account granted anything.
            UserPrincipal me = file.getFileSystem().getUserPrincipalLookupService()
                    .lookupPrincipalByName(System.getProperty("user.name"));
            for (Path p : List.of(file, sub)) {
                for (AclEntry e : Files.getFileAttributeView(p, AclFileAttributeView.class).getAcl()) {
                    if (e.type() == AclEntryType.ALLOW) {
                        assertEquals(me, e.principal(), p + " grants " + e.principal().getName());
                    }
                }
            }
        }
    }
}
