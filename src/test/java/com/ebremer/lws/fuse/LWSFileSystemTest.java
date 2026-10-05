package com.ebremer.lws.fuse;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.AuthProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.stream.Stream;
import jnr.ffi.Memory;
import jnr.ffi.Pointer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import ru.serce.jnrfuse.ErrorCodes;
import ru.serce.jnrfuse.struct.FuseFileInfo;

/**
 * The FUSE callbacks of {@link LWSFileSystem}, driven directly (no mount) against an in-memory LWS
 * server. Skipped where no FUSE library is installed, because jnr-fuse loads it when the
 * filesystem object is constructed.
 */
class LWSFileSystemTest {

    @TempDir
    Path recoveryDir;

    private MockLwsServer server;
    private LWSFileSystem fs;

    @BeforeEach
    void start() throws IOException {
        server = new MockLwsServer();
        LWSClient client = new LWSClient(server.base(), AuthProvider.anonymous())
                .retryPolicy(3, Duration.ofMillis(10), Duration.ofSeconds(1));
        try {
            fs = new LWSFileSystem(client, recoveryDir);
        } catch (Throwable t) {
            server.close();
            Assumptions.abort("No FUSE library (WinFsp / libfuse / macFUSE) available: " + t);
        }
    }

    @AfterEach
    void stop() {
        fs.shutdown();
        server.close();
    }

    // ------------------------------------------------------------------ upload on close (P0-4)

    @Test
    void failedUploadIsKeptForRetryAndSavedToRecovery() throws IOException {
        server.putStatus = 503;
        FuseFileInfo h = handle();
        assertEquals(0, fs.create("/doc.txt", 0644, h));
        assertEquals(17, write("/doc.txt", h, "important edits!!", 0));
        assertEquals(-ErrorCodes.EAGAIN(), fs.release("/doc.txt", h));

        assertNull(server.content("/alice/doc.txt"));
        assertEquals("important edits!!", read("/doc.txt", null), "edits stay readable through the mount");
        List<Path> copies = recoveryCopies();
        assertEquals(1, copies.size());
        assertTrue(copies.get(0).getFileName().toString().endsWith("-doc.txt"), copies.get(0)::toString);
        assertEquals("important edits!!", Files.readString(copies.get(0)));

        // The server recovers: the next open/close of the path retries the upload.
        server.putStatus = 0;
        FuseFileInfo again = handle();
        assertEquals(0, fs.open("/doc.txt", again));
        assertEquals(0, fs.release("/doc.txt", again));
        assertEquals("important edits!!", server.content("/alice/doc.txt"));
    }

    @Test
    void successfulUploadLeavesNoRecoveryCopyAndNoSpoolFile() throws IOException {
        FuseFileInfo h = handle();
        fs.create("/hi.txt", 0644, h);
        write("/hi.txt", h, "hello", 0);
        assertEquals(0, fs.release("/hi.txt", h));

        assertEquals("hello", server.content("/alice/hi.txt"));
        assertTrue(recoveryCopies().isEmpty());
        try (Stream<Path> spooled = Files.list(fs.spoolDir())) {
            assertEquals(0, spooled.count(), "the buffer is deleted once the file is closed");
        }
    }

    // ------------------------------------------------------------------ handles (P1-4)

    @Test
    void handlesOnOnePathShareABufferAndUploadOnLastClose() {
        FuseFileInfo writer = handle();
        FuseFileInfo reader = handle();
        fs.create("/shared.txt", 0644, writer);
        fs.open("/shared.txt", reader);
        write("/shared.txt", writer, "shared", 0);

        assertEquals(0, fs.release("/shared.txt", writer));
        assertEquals(0, server.uploads("/alice/shared.txt"), "another handle is still open");
        assertEquals("shared", read("/shared.txt", reader));

        assertEquals(0, fs.release("/shared.txt", reader));
        assertEquals("shared", server.content("/alice/shared.txt"));
        assertEquals(1, server.uploads("/alice/shared.txt"));
    }

    @Test
    void unlinkingAnOpenFileDoesNotResurrectItOnClose() {
        server.putFile("/alice/f.txt", "old");
        FuseFileInfo h = handle();
        fs.open("/f.txt", h);
        write("/f.txt", h, "new", 0);

        assertEquals(0, fs.unlink("/f.txt"));
        assertEquals("new", read("/f.txt", h), "the open handle keeps its data");
        assertEquals(0, fs.release("/f.txt", h));

        assertFalse(server.exists("/alice/f.txt"));
        assertEquals(0, server.uploads("/alice/f.txt"));
    }

    @Test
    void closingAHandleThatDidNotWriteUploadsNothing() {
        FuseFileInfo writer = handle();
        fs.create("/w.txt", 0644, writer);
        write("/w.txt", writer, "pending", 0);

        FuseFileInfo deleter = handle();   // Windows opens a handle just to delete a file
        fs.open("/w.txt", deleter);
        assertEquals(0, fs.flush("/w.txt", deleter));
        assertEquals(0, server.uploads("/alice/w.txt"));
        assertEquals(0, fs.unlink("/w.txt"));
        fs.release("/w.txt", deleter);
        fs.release("/w.txt", writer);

        assertEquals(0, server.uploads("/alice/w.txt"));
        assertFalse(server.exists("/alice/w.txt"));
    }

    @Test
    void closingAHandleThatWroteUploads() {
        FuseFileInfo writer = handle();
        FuseFileInfo reader = handle();
        fs.create("/w.txt", 0644, writer);
        fs.open("/w.txt", reader);
        write("/w.txt", writer, "saved", 0);

        assertEquals(0, fs.flush("/w.txt", writer));
        assertEquals("saved", server.content("/alice/w.txt"), "close-to-open: visible once the writer closes");
        fs.release("/w.txt", writer);
        fs.release("/w.txt", reader);
    }

    @Test
    void unlinkingACreatedButNotYetUploadedFileSucceeds() {
        FuseFileInfo h = handle();
        fs.create("/scratch.tmp", 0644, h);

        assertEquals(0, fs.unlink("/scratch.tmp"));
        assertEquals(0, fs.release("/scratch.tmp", h));
        assertFalse(server.exists("/alice/scratch.tmp"));
    }

    @Test
    void anOpenFileFollowsItsRename() {
        FuseFileInfo h = handle();
        fs.create("/a.txt", 0644, h);
        write("/a.txt", h, "draft", 0);

        assertEquals(0, fs.rename("/a.txt", "/b.txt"));
        assertEquals("draft", server.content("/alice/b.txt"));
        assertFalse(server.exists("/alice/a.txt"));

        write("/b.txt", h, "final", 0);   // the kernel now reports the new name for this handle
        assertEquals(0, fs.release("/b.txt", h));
        assertEquals("final", server.content("/alice/b.txt"));
        assertFalse(server.exists("/alice/a.txt"), "the old name is not recreated");
    }

    @Test
    void renamingOntoAnOpenDirtyFileIsNotClobberedLater() {
        server.putFile("/alice/target.txt", "old");
        FuseFileInfo stale = handle();
        fs.open("/target.txt", stale);
        write("/target.txt", stale, "stale edits", 0);

        FuseFileInfo tmp = handle();
        fs.create("/target.txt.tmp", 0644, tmp);
        write("/target.txt.tmp", tmp, "new version", 0);
        assertEquals(0, fs.release("/target.txt.tmp", tmp));
        assertEquals(0, fs.rename("/target.txt.tmp", "/target.txt"));

        assertEquals(0, fs.release("/target.txt", stale));
        assertEquals("new version", server.content("/alice/target.txt"));
    }

    @Test
    void writeWithoutAnOpenHandleFails() {
        FuseFileInfo unknown = handle();
        unknown.fh.set(424242);
        assertEquals(-ErrorCodes.EBADF(), write("/nothing.txt", unknown, "x", 0));
    }

    @Test
    void reopeningAfterCloseStartsFromTheServerCopy() {
        FuseFileInfo first = handle();
        fs.create("/r.txt", 0644, first);
        write("/r.txt", first, "v1", 0);
        fs.release("/r.txt", first);

        server.putFile("/alice/r.txt", "changed elsewhere");
        FuseFileInfo second = handle();
        fs.open("/r.txt", second);
        assertEquals("changed elsewhere", read("/r.txt", second));
        fs.release("/r.txt", second);
    }

    // ------------------------------------------------------------------ reading (P2-R1, P2-R2)

    @Test
    void sequentialSmallReadsAreServedByReadAhead() {
        byte[] data = pattern(3 * 1024 * 1024);
        server.putFile("/alice/big.bin", data, "application/octet-stream");
        FuseFileInfo h = handle();
        fs.open("/big.bin", h);

        assertArrayEquals(data, readAll("/big.bin", h, data.length, 4096));
        assertTrue(server.count("GET", "/alice/big.bin") <= 6,
                "GETs: " + server.count("GET", "/alice/big.bin") + " (one per 4 KiB read would be 768)");
        fs.release("/big.bin", h);
    }

    @Test
    void aServerThatIgnoresRangeIsDownloadedOnlyOnce() {
        server.ignoreRange = true;
        byte[] data = pattern(1024 * 1024);
        server.putFile("/alice/big.bin", data, "application/octet-stream");
        FuseFileInfo h = handle();
        fs.open("/big.bin", h);

        assertArrayEquals(data, readAll("/big.bin", h, data.length, 4096));
        assertTrue(server.count("GET", "/alice/big.bin") <= 2, "GETs: " + server.count("GET", "/alice/big.bin"));
        fs.release("/big.bin", h);
    }

    // ------------------------------------------------------------------ attributes (P2-R3, P2-R11, P2-R15)

    @Test
    void aListingSeedsAttributesAndAnswersForMissingNames() {
        server.putFile("/alice/a.txt", "abc");
        server.mkdir("/alice/sub/");

        fs.listDirectory("/");
        ResourceInfo a = fs.attributes("/a.txt");
        assertEquals(3, a.size());
        assertEquals(1735689600L, a.mtimeSeconds());
        assertTrue(fs.attributes("/sub").directory());
        assertNull(fs.attributes("/desktop.ini"));
        assertEquals(0, server.count("HEAD"), "answered from the listing");
    }

    @Test
    void aFileCreatedHereIsListedBeforeItIsUploaded() {
        FuseFileInfo h = handle();
        fs.create("/fresh.txt", 0644, h);

        assertTrue(fs.listDirectory("/").contains("fresh.txt"));
        assertTrue(fs.attributes("/fresh.txt") != null);
        fs.release("/fresh.txt", h);
    }

    @Test
    void aChangedFileKeepsTheTimeOfItsLastChange() throws InterruptedException {
        FuseFileInfo h = handle();
        fs.create("/t.txt", 0644, h);
        write("/t.txt", h, "x", 0);
        long changed = fs.attributes("/t.txt").mtimeSeconds();

        Thread.sleep(1100);
        assertEquals(changed, fs.attributes("/t.txt").mtimeSeconds(), "not 'now' on every getattr");
        fs.release("/t.txt", h);
    }

    @Test
    void expiredAttributesAreSwept() throws InterruptedException {
        for (int i = 0; i < 5000; i++) {
            server.putFile("/alice/f" + i, "x");
        }
        fs.listDirectory("/");
        assertEquals(5000, fs.cachedAttributes());

        Thread.sleep(1600);        // past the attribute TTL, within the listing's
        fs.attributes("/f0");      // caching a fresh entry sweeps out the expired ones
        assertTrue(fs.cachedAttributes() < 100, "cached: " + fs.cachedAttributes());
    }

    // ------------------------------------------------------------------ lost updates and media types (P2-R4, P2-R5)

    @Test
    void aConcurrentChangeOnTheServerIsNotOverwritten() throws IOException {
        server.putFile("/alice/doc.txt", "base");
        FuseFileInfo h = handle();
        fs.open("/doc.txt", h);
        write("/doc.txt", h, "mine", 0);

        server.putFile("/alice/doc.txt", "theirs");
        assertEquals(-ErrorCodes.ESTALE(), fs.release("/doc.txt", h));

        assertEquals("theirs", server.content("/alice/doc.txt"));
        assertEquals("theirs", read("/doc.txt", null), "the mount shows the server's version");
        List<Path> copies = recoveryCopies();
        assertEquals(1, copies.size());
        assertEquals("mine", Files.readString(copies.get(0)));
    }

    @Test
    void savingKeepsTheServersMediaType() {
        server.putFile("/alice/README", "x".getBytes(UTF_8), "text/markdown");
        FuseFileInfo h = handle();
        fs.open("/README", h);
        write("/README", h, "# Title", 0);
        fs.release("/README", h);

        assertEquals("text/markdown", server.contentType("/alice/README"));
    }

    @Test
    void renamingRederivesAGuessedMediaTypeButKeepsAnExplicitOne() {
        FuseFileInfo h = handle();
        fs.create("/img.tmp", 0644, h);
        write("/img.tmp", h, "png bytes", 0);
        fs.release("/img.tmp", h);
        assertEquals(0, fs.rename("/img.tmp", "/img.png"));
        assertEquals("image/png", server.contentType("/alice/img.png"));

        server.putFile("/alice/notes", "x".getBytes(UTF_8), "text/markdown");
        assertEquals(0, fs.rename("/notes", "/notes.txt"));
        assertEquals("text/markdown", server.contentType("/alice/notes.txt"));
    }

    // ------------------------------------------------------------------ truncation (P2-R7)

    @Test
    void truncateThenWriteUploadsOnceWithoutDownloading() {
        server.putFile("/alice/t.txt", "old content");

        assertEquals(0, fs.truncate("/t.txt", 0));
        assertEquals(0, server.uploads("/alice/t.txt"), "held back for the write that follows");
        assertEquals(0, fs.attributes("/t.txt").size());

        FuseFileInfo h = handle();
        fs.open("/t.txt", h);
        write("/t.txt", h, "new", 0);
        assertEquals(0, fs.release("/t.txt", h));

        assertEquals("new", server.content("/alice/t.txt"));
        assertEquals(1, server.uploads("/alice/t.txt"));
        assertEquals(0, server.count("GET", "/alice/t.txt"));
    }

    @Test
    void aTruncateOnItsOwnIsUploadedShortlyAfter() throws InterruptedException {
        fs.deferredTruncateMs = 50;
        server.putFile("/alice/t.txt", "old content");

        assertEquals(0, fs.truncate("/t.txt", 0));
        for (int i = 0; i < 100 && !"".equals(server.content("/alice/t.txt")); i++) {
            Thread.sleep(20);
        }
        assertEquals("", server.content("/alice/t.txt"));
    }

    @Test
    void truncatingAnUnopenedFileToANonZeroSizeRewritesIt() {
        server.putFile("/alice/t.txt", "0123456789");

        assertEquals(0, fs.truncate("/t.txt", 4));
        assertEquals("0123", server.content("/alice/t.txt"));
        assertEquals(0, fs.truncate("/t.txt", 6));
        assertArrayEquals(new byte[] {'0', '1', '2', '3', 0, 0}, server.bytes("/alice/t.txt"));
    }

    // ------------------------------------------------------------------ unmount (P2-R12)

    @Test
    void shutdownUploadsChangesStillOpen() {
        FuseFileInfo h = handle();
        fs.create("/open.txt", 0644, h);
        write("/open.txt", h, "unsaved", 0);

        fs.shutdown();
        assertEquals("unsaved", server.content("/alice/open.txt"));
    }

    // ------------------------------------------------------------------ directory rename (P2-R14)

    @Test
    void renamingADirectoryMovesItsWholeTree() {
        server.mkdir("/alice/d/");
        server.mkdir("/alice/d/sub/");
        server.putFile("/alice/d/a.txt", "a");
        server.putFile("/alice/d/sub/b.txt", "b");
        FuseFileInfo h = handle();
        fs.open("/d/sub/b.txt", h);
        write("/d/sub/b.txt", h, "B", 0);

        assertEquals(0, fs.rename("/d", "/e"));
        assertEquals("a", server.content("/alice/e/a.txt"));
        assertEquals("B", server.content("/alice/e/sub/b.txt"), "pending edits were copied");
        assertFalse(server.exists("/alice/d/"));
        assertFalse(server.exists("/alice/d/a.txt"));
        assertEquals(0, server.recursiveDeletes.get(),
                "the original is deleted entry by entry: a recursive DELETE could remove members never listed");

        write("/e/sub/b.txt", h, "BB", 0);
        assertEquals(0, fs.release("/e/sub/b.txt", h));
        assertEquals("BB", server.content("/alice/e/sub/b.txt"), "the open file followed its directory");
        assertFalse(server.exists("/alice/d/sub/b.txt"));
    }

    @Test
    void aDirectoryCannotBeRenamedIntoItselfOrOntoANonEmptyOne() {
        server.mkdir("/alice/d/");
        server.mkdir("/alice/full/");
        server.putFile("/alice/full/x", "x");

        assertEquals(-ErrorCodes.EINVAL(), fs.rename("/d", "/d/inner"));
        assertEquals(-ErrorCodes.ENOTEMPTY(), fs.rename("/d", "/full"));
        assertTrue(server.exists("/alice/d/"));
    }

    @Test
    void aVeryLargeDirectoryIsLeftToTheCaller() {
        server.mkdir("/alice/huge/");
        for (int i = 0; i <= LWSFileSystem.MAX_DIRECTORY_RENAME_ENTRIES; i++) {
            server.putFile("/alice/huge/f" + i, "x");
        }
        assertEquals(-ErrorCodes.EXDEV(), fs.rename("/huge", "/moved"));
        assertEquals(0, server.count("PUT") + server.count("POST"));
    }

    // ------------------------------------------------------------------ servers of different kinds

    @Test
    void worksWhenUrisDoNotMirrorTheHierarchy() {
        server.flatIds = true;
        everydayOperations();
        assertTrue(server.created.stream().allMatch(p -> p.startsWith("/alice/o")), server.created::toString);
    }

    @Test
    void worksWithAnEarlierDraftServer() {
        server.legacy = true;   // no POST, PUT creates, Turtle listings
        everydayOperations();
        assertEquals(1, server.count("POST"), "POST was tried once");
    }

    /** mkdir, create + write, list, read back, rename, delete — the usual life of a file. */
    private void everydayOperations() {
        assertEquals(0, fs.mkdir("/docs", 0755));
        FuseFileInfo h = handle();
        assertEquals(0, fs.create("/docs/a.txt", 0644, h));
        write("/docs/a.txt", h, "alpha", 0);
        assertEquals(0, fs.release("/docs/a.txt", h));

        assertTrue(fs.listDirectory("/docs").contains("a.txt"));
        FuseFileInfo r = handle();
        fs.open("/docs/a.txt", r);
        assertEquals("alpha", read("/docs/a.txt", r));
        fs.release("/docs/a.txt", r);

        assertEquals(0, fs.rename("/docs/a.txt", "/docs/b.txt"));
        assertEquals(List.of("b.txt"), fs.listDirectory("/docs"));
        assertEquals(0, fs.unlink("/docs/b.txt"));
        assertEquals(0, fs.rmdir("/docs"));
        assertTrue(fs.listDirectory("/").isEmpty());
    }

    @Test
    void aNewFileTheServerNamesDifferentlyFollowsTheServersName() throws IOException {
        server.renameOnCreate = true;
        FuseFileInfo h = handle();
        fs.create("/x.txt", 0644, h);
        write("/x.txt", h, "x", 0);
        assertEquals(0, fs.release("/x.txt", h));

        assertEquals("x", server.content("/alice/x.txt-srv"));
        assertEquals(List.of("x.txt-srv"), fs.listDirectory("/"));
        assertNull(fs.attributes("/x.txt"), "nothing lingers under the requested name");
        try (Stream<Path> spooled = Files.list(fs.spoolDir())) {
            assertEquals(0, spooled.count());
        }
    }

    // ------------------------------------------------------------------ helpers

    private static FuseFileInfo handle() {
        return FuseFileInfo.of(Memory.allocateDirect(jnr.ffi.Runtime.getSystemRuntime(), 128, true));
    }

    private int write(String path, FuseFileInfo fi, String text, long offset) {
        byte[] data = text.getBytes(UTF_8);
        Pointer buf = Memory.allocateDirect(jnr.ffi.Runtime.getSystemRuntime(), data.length);
        buf.put(0, data, 0, data.length);
        return fs.write(path, buf, data.length, offset, fi);
    }

    private String read(String path, FuseFileInfo fi) {
        Pointer buf = Memory.allocateDirect(jnr.ffi.Runtime.getSystemRuntime(), 4096);
        int n = fs.read(path, buf, 4096, 0, fi);
        assertTrue(n >= 0, "read failed with errno " + n);
        byte[] out = new byte[n];
        buf.get(0, out, 0, n);
        return new String(out, UTF_8);
    }

    /** Read a whole file in {@code chunk}-sized pieces, as the OS does. */
    private byte[] readAll(String path, FuseFileInfo fi, int size, int chunk) {
        byte[] out = new byte[size];
        Pointer buf = Memory.allocateDirect(jnr.ffi.Runtime.getSystemRuntime(), chunk);
        for (int off = 0; off < size; off += chunk) {
            int n = fs.read(path, buf, chunk, off, fi);
            assertTrue(n > 0, "read at " + off + " returned " + n);
            buf.get(0, out, off, n);
        }
        return out;
    }

    private static byte[] pattern(int size) {
        byte[] b = new byte[size];
        for (int i = 0; i < size; i++) {
            b[i] = (byte) (i * 131 + (i >> 9));
        }
        return b;
    }

    private List<Path> recoveryCopies() throws IOException {
        if (!Files.exists(recoveryDir)) {
            return List.of();
        }
        try (Stream<Path> files = Files.list(recoveryDir)) {
            return files.toList();
        }
    }
}
