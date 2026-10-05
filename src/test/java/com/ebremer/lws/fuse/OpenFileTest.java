package com.ebremer.lws.fuse;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.AuthProvider;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** The spooled write buffer behind open files. */
class OpenFileTest {

    @TempDir
    Path spool;

    private MockLwsServer server;
    private LWSClient client;

    @BeforeEach
    void start() throws IOException {
        server = new MockLwsServer();
        client = new LWSClient(server.base(), AuthProvider.anonymous());
    }

    @AfterEach
    void stop() {
        server.close();
    }

    @Test
    void writingPastTheEndZeroFillsTheGap() {
        OpenFile f = newFile();
        f.write(null, bytes("abc"), 5);

        assertArrayEquals(new byte[] {0, 0, 0, 0, 0, 'a', 'b', 'c'}, f.read(null, 0, 100));
    }

    @Test
    void growingAfterAShrinkDoesNotResurrectStaleBytes() {
        OpenFile f = newFile();
        f.write(null, bytes("abcdef"), 0);
        f.truncate(null, 2);
        f.truncate(null, 5);
        assertArrayEquals(new byte[] {'a', 'b', 0, 0, 0}, f.read(null, 0, 100));

        OpenFile g = newFile();
        g.write(null, bytes("abcdef"), 0);
        g.truncate(null, 2);
        g.write(null, bytes("Z"), 4);
        assertArrayEquals(new byte[] {'a', 'b', 0, 0, 'Z'}, g.read(null, 0, 100));
    }

    @Test
    void readsAreBoundedByTheFileLength() {
        OpenFile f = newFile();
        f.write(null, bytes("hello"), 0);

        assertEquals("ell", new String(f.read(null, 1, 3), UTF_8));
        assertEquals("lo", new String(f.read(null, 3, 100), UTF_8));
        assertEquals(0, f.read(null, 5, 10).length);
        assertEquals(5, f.length());
    }

    @Test
    void theBufferLivesInASpoolFileThatCloseDeletes() throws IOException {
        OpenFile f = newFile();
        f.write(null, new byte[3 * 1024 * 1024], 0);
        assertEquals(1, spoolFiles());
        assertEquals(3 * 1024 * 1024, f.length());

        f.close();
        assertEquals(0, spoolFiles());
        assertThrows(LWSException.class, () -> f.read(null, 0, 1));
    }

    @Test
    void loadsServerContentBeforeTheFirstModification() {
        server.putFile("/alice/h.txt", "hello world");
        OpenFile f = new OpenFile("/h.txt", spool);

        f.write(client, bytes("J"), 0);
        assertTrue(f.flush(client));
        assertEquals("Jello world", server.content("/alice/h.txt"));
        assertEquals(1, server.count("GET", "/alice/h.txt"));
    }

    @Test
    void truncatingToZeroDoesNotDownload() {
        server.putFile("/alice/big.txt", "old content");
        OpenFile f = new OpenFile("/big.txt", spool);

        f.truncate(client, 0);
        f.write(client, bytes("new"), 0);
        assertTrue(f.flush(client));

        assertEquals("new", server.content("/alice/big.txt"));
        assertEquals(0, server.count("GET", "/alice/big.txt"));
    }

    @Test
    void flushUploadsOnlyWhenDirtyAndNeverOnceDetached() {
        OpenFile f = new OpenFile("/a.txt", spool);
        f.initNew();
        f.write(client, bytes("one"), 0);

        assertTrue(f.flush(client));
        assertFalse(f.flush(client));   // clean
        assertEquals(1, server.uploads("/alice/a.txt"));
        assertEquals(1, server.count("POST", "/alice/"), "a new file is created with POST");

        f.write(client, bytes("two"), 0);
        f.detach();
        assertFalse(f.flush(client));
        assertEquals("one", server.content("/alice/a.txt"));
    }

    @Test
    void anUploadDoesNotOverwriteAConcurrentChange() {
        server.putFile("/alice/doc.txt", "base");
        OpenFile f = new OpenFile("/doc.txt", spool);
        f.write(client, bytes("mine"), 0);   // loads "base" with its ETag

        server.putFile("/alice/doc.txt", "theirs");
        LWSException e = assertThrows(LWSException.class, () -> f.flush(client));
        assertEquals(LWSException.Kind.CHANGED, e.kind());
        assertEquals("theirs", server.content("/alice/doc.txt"));
        assertTrue(f.dirty(), "the local change is kept");
    }

    @Test
    void aNewFileDoesNotReplaceOneCreatedMeanwhile() {
        OpenFile f = new OpenFile("/new.txt", spool);
        f.initNew();
        f.write(client, bytes("mine"), 0);

        server.putFile("/alice/new.txt", "theirs");
        LWSException e = assertThrows(LWSException.class, () -> f.flush(client));
        assertEquals(LWSException.Kind.EXISTS, e.kind());
        assertEquals("theirs", server.content("/alice/new.txt"));
    }

    @Test
    void successiveSavesUseTheETagOfTheLastUpload() {
        OpenFile f = new OpenFile("/s.txt", spool);
        f.initNew();
        f.write(client, bytes("v1"), 0);
        assertTrue(f.flush(client));
        f.write(client, bytes("v2"), 0);
        assertTrue(f.flush(client));

        assertEquals("v2", server.content("/alice/s.txt"));
    }

    @Test
    void laterSavesStayConditionalWhenWriteResponsesCarryNoETag() {
        server.etagOnWrites = false;   // LWS requires an ETag only on GET and HEAD responses
        OpenFile f = new OpenFile("/s.txt", spool);
        f.initNew();
        f.write(client, bytes("v1"), 0);
        assertTrue(f.flush(client));
        f.write(client, bytes("v2"), 0);
        assertTrue(f.flush(client));
        assertEquals("v2", server.content("/alice/s.txt"));

        server.putFile("/alice/s.txt", "theirs");
        f.write(client, bytes("v3"), 0);
        LWSException e = assertThrows(LWSException.class, () -> f.flush(client));
        assertEquals(LWSException.Kind.CHANGED, e.kind());
        assertEquals("theirs", server.content("/alice/s.txt"));
    }

    @Test
    void theServersMediaTypeIsKept() {
        server.putFile("/alice/notes", "x".getBytes(UTF_8), "text/markdown");
        OpenFile f = new OpenFile("/notes", spool);
        f.write(client, bytes("y"), 1);
        f.flush(client);

        assertEquals("text/markdown", server.contentType("/alice/notes"));
    }

    @Test
    void aNewFilesMediaTypeIsGuessedFromItsName() {
        OpenFile f = new OpenFile("/data.ttl", spool);
        f.initNew();
        f.write(client, bytes("<a> <b> <c> ."), 0);
        f.flush(client);

        assertEquals("text/turtle", server.contentType("/alice/data.ttl"));
    }

    @Test
    void moveToRetargetsTheUpload() {
        OpenFile f = new OpenFile("/old.txt", spool);
        f.initNew();
        f.write(client, bytes("x"), 0);
        f.moveTo("/new.txt", null, null);

        assertTrue(f.flush(client));
        assertEquals("x", server.content("/alice/new.txt"));
        assertNull(server.content("/alice/old.txt"));
    }

    @Test
    void aChangeDuringAnUploadKeepsTheFileDirty() throws Exception {
        OpenFile f = newFile();
        f.write(null, bytes("first"), 0);
        // Simulate a write landing while the PUT is in flight: the upload sends the snapshot it
        // took, and the newer change must still be pending afterwards.
        LWSClient slow = new LWSClient(server.base(), (builder, method, uri) -> {
            if (method.equals("POST")) {   // the upload creating the file
                f.write(null, bytes("second"), 0);
            }
        });
        assertTrue(f.flush(slow));
        assertEquals("first", server.content("/alice/f"));
        assertTrue(f.dirty());
        assertTrue(f.flush(client));
        assertEquals("second", server.content("/alice/f"));
    }

    @Test
    void referenceCountingReportsTheLastRelease() {
        OpenFile f = newFile();
        f.retain();
        f.retain();
        assertFalse(f.release());
        assertTrue(f.release());
        assertEquals(0, f.refs());
    }

    /** A new, empty file: already "loaded", so no server is needed until it is flushed. */
    private OpenFile newFile() {
        OpenFile f = new OpenFile("/f", spool);
        f.initNew();
        return f;
    }

    private long spoolFiles() throws IOException {
        try (Stream<Path> files = Files.list(spool)) {
            return files.count();
        }
    }

    private static byte[] bytes(String s) {
        return s.getBytes(UTF_8);
    }
}
