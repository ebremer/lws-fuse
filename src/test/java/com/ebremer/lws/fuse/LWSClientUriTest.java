package com.ebremer.lws.fuse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.AuthProvider;
import java.net.URI;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/** FUSE path → LWS URL mapping in {@link LWSClient}. */
class LWSClientUriTest {

    private static final String BASE = "https://lws.example/alice/";

    private final LWSClient client = new LWSClient(URI.create(BASE), AuthProvider.anonymous());

    @Test
    void mapsOrdinaryPathsUnderTheBase() {
        assertEquals(URI.create(BASE), client.resourceUri("/"));
        assertEquals(URI.create(BASE), client.containerUri("/"));
        assertEquals(URI.create(BASE + "notes.txt"), client.resourceUri("/notes.txt"));
        assertEquals(URI.create(BASE + "dir/sub/file.ttl"), client.resourceUri("/dir/sub/file.ttl"));
        assertEquals(URI.create(BASE + "dir/sub/"), client.containerUri("/dir/sub"));
    }

    @Test
    void aBaseWithoutATrailingSlashIsKeptAndGetsASeparator() {
        LWSClient opaque = new LWSClient(URI.create("https://lws.example/c/7f3a"), AuthProvider.anonymous());
        assertEquals(URI.create("https://lws.example/c/7f3a"), opaque.base());
        assertEquals(URI.create("https://lws.example/c/7f3a"), opaque.resourceUri("/"));
        assertEquals(URI.create("https://lws.example/c/7f3a/notes.txt"), opaque.resourceUri("/notes.txt"));
        assertEquals(URI.create("https://lws.example/c/7f3a/dir/"), opaque.containerUri("/dir"));
    }

    @Test
    void percentEncodesEachSegment() {
        assertEquals(BASE + "my%20file%20%C3%A9.txt", client.resourceUri("/my file é.txt").toString());
        assertEquals(BASE + "q%3F%23.txt", client.resourceUri("/q?#.txt").toString());
        assertEquals(BASE + "100%25.txt", client.resourceUri("/100%.txt").toString());
        // A literal "%41" in a name must not go out as the escape for 'A'.
        assertEquals(BASE + "a%2541.txt", client.resourceUri("/a%41.txt").toString());
    }

    @Test
    void colonInFirstSegmentIsNotAScheme() {
        assertEquals(BASE + "a:b.txt", client.resourceUri("/a:b.txt").toString());
        assertEquals(BASE + "x:/etc/passwd", client.resourceUri("/x:/etc/passwd").toString());
        assertEquals(BASE + "http:/other/secret", client.resourceUri("/http:/other/secret").toString());
        assertEquals(BASE + "x:/", client.containerUri("/x:").toString());
    }

    @ParameterizedTest
    @ValueSource(strings = {"/a:b", "/x:/etc/passwd", "/http:/evil.example/x", "/mailto:a@b",
            "/c:/Windows", "/@host/x", "/;x", "/~user", "/%2e%2e/x"})
    void neverEscapesTheBase(String path) {
        for (URI u : new URI[] {client.resourceUri(path), client.containerUri(path)}) {
            assertEquals("https", u.getScheme(), u::toString);
            assertEquals("lws.example", u.getHost(), u::toString);
            assertTrue(u.getRawPath().startsWith("/alice/"), u::toString);
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"/..", "/a/../b", "/.", "/a/./b", "/a//b"})
    void rejectsDotAndEmptySegments(String path) {
        LWSException e = assertThrows(LWSException.class, () -> client.resourceUri(path));
        assertEquals(LWSException.Kind.INVALID, e.kind());
    }
}
