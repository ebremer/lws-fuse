package com.ebremer.lws.fuse.auth;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.SeekableByteChannel;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystem;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclEntry;
import java.nio.file.attribute.AclEntryFlag;
import java.nio.file.attribute.AclEntryPermission;
import java.nio.file.attribute.AclEntryType;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.nio.file.attribute.UserPrincipal;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

/**
 * Writes secrets — refresh tokens, private keys, unsaved user data — to files that only their
 * owner can read, from the moment they exist: permissions are applied when the file or directory
 * is created, never with a {@code chmod} afterwards.
 * <ul>
 *   <li>POSIX: files {@code rw-------}, directories {@code rwx------}.</li>
 *   <li>Windows (ACL file systems): an access-control list granting only the current user. It
 *       replaces what the file would otherwise inherit from its directory (checked with
 *       {@code icacls}: a file created this way in a directory readable by {@code BUILTIN\Users}
 *       lists only its owner).</li>
 *   <li>Elsewhere, the file system's defaults.</li>
 * </ul>
 * Existing directories are left as they are.
 *
 * @author Erich Bremer
 */
public final class PrivateFiles {

    private static final FileAttribute<?>[] NONE = new FileAttribute<?>[0];

    private PrivateFiles() {
    }

    /** Create {@code dir} and any missing parents, owner-only. */
    public static void createDirectories(Path dir) throws IOException {
        Files.createDirectories(dir, ownerOnly(dir, true));
    }

    /**
     * Replace {@code file} with {@code data} atomically: write an owner-only temporary file next to
     * it, then move it into place, so readers see the old content or the new, never a mix.
     */
    public static void writeAtomically(Path file, byte[] data) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        createDirectories(dir);
        Path tmp = Files.createTempFile(dir, "." + file.getFileName(), ".tmp", ownerOnly(dir, false));
        try {
            Files.write(tmp, data, StandardOpenOption.TRUNCATE_EXISTING);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    /**
     * Create {@code file}, which must not exist yet, owner-only, holding {@code data}.
     *
     * @throws java.nio.file.FileAlreadyExistsException if it already exists
     */
    public static void createNew(Path file, byte[] data) throws IOException {
        Path dir = file.toAbsolutePath().getParent();
        createDirectories(dir);
        try (SeekableByteChannel ch = Files.newByteChannel(file,
                Set.of(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE), ownerOnly(dir, false))) {
            ByteBuffer bb = ByteBuffer.wrap(data);
            while (bb.hasRemaining()) {
                ch.write(bb);
            }
        }
    }

    /** Creation-time attributes that restrict a new file or directory under {@code near} to its owner. */
    static FileAttribute<?>[] ownerOnly(Path near, boolean directory) {
        FileSystem fs = near.getFileSystem();
        Set<String> views = fs.supportedFileAttributeViews();
        if (views.contains("posix")) {
            return new FileAttribute<?>[] {
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(directory ? "rwx------" : "rw-------"))};
        }
        if (views.contains("acl")) {
            try {
                UserPrincipal me = fs.getUserPrincipalLookupService()
                        .lookupPrincipalByName(System.getProperty("user.name"));
                AclEntry.Builder entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(me)
                        .setPermissions(EnumSet.allOf(AclEntryPermission.class));
                if (directory) {
                    entry.setFlags(AclEntryFlag.FILE_INHERIT, AclEntryFlag.DIRECTORY_INHERIT);
                }
                List<AclEntry> acl = List.of(entry.build());
                return new FileAttribute<?>[] {new FileAttribute<List<AclEntry>>() {
                    @Override
                    public String name() {
                        return "acl:acl";
                    }

                    @Override
                    public List<AclEntry> value() {
                        return acl;
                    }
                }};
            } catch (IOException | RuntimeException cannotResolveUser) {
                return NONE;   // fall back to the inherited ACL
            }
        }
        return NONE;
    }
}
