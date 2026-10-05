package com.ebremer.lws.fuse;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.ebremer.lws.fuse.auth.AuthException;
import com.ebremer.lws.fuse.auth.AuthProvider;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

/** {@link LWSClient} against an in-memory LWS 1.0 server (and its earlier-draft mode). */
class LWSClientTest {

    @TempDir
    Path dir;

    private MockLwsServer server;
    private LWSClient client;

    @BeforeEach
    void start() throws IOException {
        server = new MockLwsServer();
        client = newClient();
    }

    @AfterEach
    void stop() {
        server.close();
    }

    private LWSClient newClient() {
        return new LWSClient(server.base(), AuthProvider.anonymous())
                .retryPolicy(3, Duration.ofMillis(10), Duration.ofSeconds(2));
    }

    // ------------------------------------------------------------------ stat

    @Test
    void aSizeNeitherListedNorInHeadComesFromARangeRequest() {
        server.minimalListing = true;
        server.contentLengthOnHead = false;   // HTTP lets HEAD omit Content-Length
        server.putFile("/alice/s.txt", "12345");
        server.putFile("/alice/empty.txt", "");

        assertEquals(5, client.stat("/s.txt").size());
        assertEquals(0, client.stat("/empty.txt").size());
    }

    @Test
    void statIsAnsweredFromTheParentListing() {
        server.putFile("/alice/notes.txt", "hello");
        server.mkdir("/alice/docs/");

        ResourceInfo file = client.stat("/notes.txt");
        assertFalse(file.directory());
        assertEquals(5, file.size());
        assertEquals(1735689600L, file.mtimeSeconds());   // modified: 2025-01-01T00:00:00Z
        assertEquals("text/plain", file.contentType());
        assertTrue(client.stat("/docs").directory());
        assertNull(client.stat("/nope"));
        assertNull(client.stat("/nope/deeper"));
        assertEquals(0, server.count("HEAD"), "the listing stated everything");
        assertEquals(1, server.count("GET", "/alice/"), "one listing for all lookups");

        assertTrue(client.stat("/").directory());
    }

    @Test
    void aListingWithoutSizesFallsBackToHead() {
        server.minimalListing = true;
        server.putFile("/alice/notes.txt", "hello");

        assertEquals(5, client.stat("/notes.txt").size());
        assertEquals(1, server.count("HEAD", "/alice/notes.txt"));
    }

    // ------------------------------------------------------------------ listing

    @Test
    void listReadsTheLwsJsonRepresentation() {
        server.putFile("/alice/a.ttl", "<s> <p> <o> .".getBytes(UTF_8), "text/turtle");
        server.mkdir("/alice/sub/");
        server.putFile("/alice/sub/inner.txt", "not a direct member");

        Map<String, LWSClient.Member> members = byName(client.list("/"));
        assertEquals(Map.of("a.ttl", false, "sub", true), kinds(members));
        LWSClient.Member a = members.get("a.ttl");
        assertEquals(13, a.size());
        assertEquals(1735689600L, a.mtimeSeconds());
        assertEquals("text/turtle", a.contentType());
        assertEquals(server.base().resolve("a.ttl"), a.uri());
        assertTrue(server.requests.contains("GET /alice/"));
    }

    @Test
    void listAcceptsTypeArraysFullIrisAndAbsoluteIds() {
        String base = server.base().toString();
        server.overrideListing("/alice/", """
                {"@context": "https://www.w3.org/ns/lws/v1", "id": "%s", "type": "Container", "totalItems": 4,
                 "items": [
                   {"id": "%sx.json", "type": ["DataResource", "http://example.org/Custom"], "format": "application/json", "size": 2},
                   {"id": "/alice/dir/", "type": "https://www.w3.org/ns/lws#Container"},
                   {"id": "untyped/"},
                   {"id": "http://evil.example/alice/stolen.txt", "type": "DataResource", "format": "text/plain"},
                   {"id": "%s", "type": "Container"}
                 ]}
                """.formatted(base, base, base));

        assertEquals(Map.of("x.json", false, "dir", true, "untyped", true), kinds(byName(client.list("/"))),
                "other origins and the container itself are skipped; untyped members fall back to the trailing slash");
    }

    @Test
    void listFollowsLinkHeaderPages() {
        server.pageSize = 2;
        for (int i = 0; i < 5; i++) {
            server.putFile("/alice/f" + i + ".txt", "x");
        }

        assertEquals(5, client.list("/").size());
        assertTrue(server.requests.contains("GET /alice/?page=2"));
        assertEquals(1, server.count("GET", "/alice/"));
    }

    @Test
    void earlierDraftTurtleListingsStillWork() {
        server.legacy = true;
        server.pageSize = 2;
        server.putFile("/alice/a.txt", "abc");
        server.putFile("/alice/b.txt", "b");
        server.mkdir("/alice/sub/");

        Map<String, LWSClient.Member> members = byName(client.list("/"));
        assertEquals(Map.of("a.txt", false, "b.txt", false, "sub", true), kinds(members));
        assertEquals(3, members.get("a.txt").size());
        assertTrue(server.requests.contains("GET /alice/?page=1"), "in-body lws:first/lws:next were followed");
    }

    @Test
    void listRefusesPagesOnAnotherOrigin() {
        int port = server.base().getPort();
        for (String elsewhere : List.of("http://evil.example/alice/?page=1", "https://127.0.0.1:" + port + "/alice/?page=1")) {
            server.legacy = true;
            server.overrideListing("/alice/", "@prefix lws: <https://www.w3.org/ns/lws#> .\n"
                    + "</alice/> a lws:Container ; lws:first <" + elsewhere + "> .\n");

            LWSException e = assertThrows(LWSException.class, () -> newClient().list("/"), elsewhere);
            assertTrue(e.getMessage().contains("outside the storage's origin"), e.getMessage());
        }
    }

    @Test
    void listOfMissingContainerIsNotFound() {
        LWSException e = assertThrows(LWSException.class, () -> client.list("/missing"));
        assertEquals(LWSException.Kind.NOT_FOUND, e.kind());
    }

    // ------------------------------------------------------------------ navigation by containment

    @Test
    void pathsAreResolvedThroughListingsWhenUrisDoNotMirrorTheHierarchy() throws IOException {
        server.flatIds = true;
        client.putContainer("/docs");
        client.putContainer("/docs/deep");
        client.putResource("/docs/deep/note.txt", "flat".getBytes(UTF_8), "text/plain");

        String docs = server.memberNamed("/alice/", "docs");
        String deep = server.memberNamed(docs, "deep");
        String note = server.memberNamed(deep, "note.txt");
        assertTrue(note.startsWith("/alice/o") && !note.startsWith("/alice/docs/"), note);
        assertEquals("flat", server.content(note));

        LWSClient fresh = newClient();   // nothing cached: resolve from the root
        assertEquals("flat", new String(fresh.readAll("/docs/deep/note.txt"), UTF_8));
        assertEquals(4, fresh.stat("/docs/deep/note.txt").size());
        fresh.putResource("/docs/deep/note.txt", "changed".getBytes(UTF_8), "text/plain");
        assertEquals("changed", server.content(note));
        fresh.delete("/docs/deep/note.txt", false);
        assertFalse(server.exists(note));
    }

    // ------------------------------------------------------------------ reading

    @Test
    void readUsesRangeRequests() {
        server.putFile("/alice/digits.txt", "0123456789");

        LWSClient.ReadResult r = client.readRange("/digits.txt", 2, 3);
        assertEquals("234", new String(r.data(), UTF_8));
        assertFalse(r.rangeIgnored());
        assertEquals("89", new String(client.read("/digits.txt", 8, 100), UTF_8));
        assertEquals(0, client.read("/digits.txt", 10, 5).length);   // 416: past the end
        assertEquals("0123456789", new String(client.readAll("/digits.txt"), UTF_8));
    }

    @Test
    void readSlicesTheBodyWhenServerIgnoresRangeAndSaysSo() {
        server.ignoreRange = true;
        server.putFile("/alice/digits.txt", "0123456789");

        LWSClient.ReadResult r = client.readRange("/digits.txt", 2, 3);
        assertEquals("234", new String(r.data(), UTF_8));
        assertTrue(r.rangeIgnored());
        assertEquals(0, client.read("/digits.txt", 20, 3).length);
    }

    @Test
    void readOfMissingResourceIsNotFound() {
        assertNull(client.readAll("/nope"));
        LWSException e = assertThrows(LWSException.class, () -> client.read("/nope", 0, 10));
        assertEquals(LWSException.Kind.NOT_FOUND, e.kind());
    }

    @Test
    void downloadStreamsToAFileWithItsMetadata() throws IOException {
        server.putFile("/alice/d.bin", new byte[] {1, 2, 3}, "application/x-thing");
        Path target = dir.resolve("d.bin");

        LWSClient.Download d = client.download("/d.bin", target);
        assertEquals(3, d.length());
        assertEquals("application/x-thing", d.contentType());
        assertNotNull(d.etag());
        assertEquals(3, Files.size(target));
        assertNull(client.download("/missing", dir.resolve("m")));
    }

    // ------------------------------------------------------------------ creating and updating

    @Test
    void newResourcesArePostedToTheirContainerWithASlug() {
        client.putContainer("/my docs");
        client.putResource("/my docs/a b:c%.txt", "data".getBytes(UTF_8), "text/plain");

        assertEquals(2, server.count("POST"));
        assertEquals(1, server.count("POST", "/alice/"));
        assertEquals(1, server.count("POST", "/alice/my%20docs/"));
        assertEquals(0, server.count("PUT"), "PUT only updates in LWS");
        assertEquals("data", server.content("/alice/my%20docs/a%20b:c%25.txt"));
        assertEquals(Map.of("a b:c%.txt", false), kinds(byName(client.list("/my docs"))));

        client.putResource("/my docs/a b:c%.txt", "more".getBytes(UTF_8), "text/plain");
        assertEquals(1, server.count("PUT", "/alice/my%20docs/a%20b:c%25.txt"), "an existing resource is updated");
        assertEquals("more", server.content("/alice/my%20docs/a%20b:c%25.txt"));
    }

    @Test
    void aServerChosenNameIsReported() throws IOException {
        server.renameOnCreate = true;
        Path body = Files.writeString(dir.resolve("b"), "x");

        LWSClient.Stored s = client.putResource("/wanted.txt", body, "text/plain", LWSClient.Precondition.CREATE_ONLY);
        assertEquals("/wanted.txt-srv", s.path());
        assertEquals("x", server.content("/alice/wanted.txt-srv"));
    }

    @Test
    void creatingInAMissingContainerIsNotFound() {
        LWSException e = assertThrows(LWSException.class,
                () -> client.putResource("/no/such/dir.txt", new byte[1], "text/plain"));
        assertEquals(LWSException.Kind.NOT_FOUND, e.kind());
    }

    @Test
    void conditionalUploadsDetectConcurrentChanges() throws IOException {
        Path body = Files.writeString(dir.resolve("body"), "mine");
        LWSClient.Stored first = client.putResource("/c.txt", body, "text/plain", LWSClient.Precondition.CREATE_ONLY);
        assertNotNull(first.etag());

        LWSException exists = assertThrows(LWSException.class,
                () -> client.putResource("/c.txt", body, "text/plain", LWSClient.Precondition.CREATE_ONLY));
        assertEquals(LWSException.Kind.EXISTS, exists.kind());

        server.putFile("/alice/c.txt", "theirs");   // a concurrent writer
        LWSException changed = assertThrows(LWSException.class,
                () -> client.putResource("/c.txt", body, "text/plain", LWSClient.Precondition.ifMatch(first.etag())));
        assertEquals(LWSException.Kind.CHANGED, changed.kind());
        assertEquals("theirs", server.content("/alice/c.txt"));

        assertEquals(LWSClient.Precondition.NONE, LWSClient.Precondition.ifMatch("W/\"weak\""),
                "a weak ETag can never satisfy If-Match, so it is not sent");
    }

    @Test
    void aResourceDeletedSinceItWasReadIsAConflictNotARecreation() throws IOException {
        server.putFile("/alice/gone.txt", "v1");
        Path body = Files.writeString(dir.resolve("body"), "mine");
        String etag = client.download("/gone.txt", dir.resolve("dl")).etag();
        server.overrideListing("/alice/", "{\"id\":\"/alice/\",\"type\":\"Container\",\"items\":[]}");

        LWSException e = assertThrows(LWSException.class,
                () -> newClient().putResource("/gone.txt", body, "text/plain", LWSClient.Precondition.ifMatch(etag)));
        assertEquals(LWSException.Kind.CHANGED, e.kind());
    }

    @Test
    void creatingAnExistingContainerIsReportedAsExisting() {
        server.mkdir("/alice/d/");
        LWSException e = assertThrows(LWSException.class, () -> client.putContainer("/d"));
        assertEquals(LWSException.Kind.EXISTS, e.kind());
    }

    @Test
    void anEarlierDraftServerWithoutPostGetsPutCreates() {
        server.legacy = true;
        client.putContainer("/d");
        client.putResource("/d/a.txt", "a".getBytes(UTF_8), "text/plain");
        client.putResource("/d/b.txt", "b".getBytes(UTF_8), "text/plain");

        assertEquals(1, server.count("POST"), "POST is tried once, then remembered as unsupported");
        assertEquals("a", server.content("/alice/d/a.txt"));
        assertEquals("b", server.content("/alice/d/b.txt"));
    }

    @Test
    void oneContainerRefusingPostDoesNotSwitchCreationToPut() {
        server.mkdir("/alice/ro/");
        server.refusePostTo.add("/alice/ro/");
        client.putResource("/ok.txt", "ok".getBytes(UTF_8), "text/plain");

        LWSException e = assertThrows(LWSException.class,
                () -> client.putResource("/ro/x.txt", "x".getBytes(UTF_8), "text/plain"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind(), "the POST's 405 is reported");
        client.putResource("/ok2.txt", "ok".getBytes(UTF_8), "text/plain");

        assertEquals(0, server.count("PUT"), "a server that creates with POST is never sent a PUT create");
        assertEquals("ok", server.content("/alice/ok2.txt"));
    }

    @Test
    void aRefusedPostIsReportedWhenPutCannotCreateEither() {
        server.mkdir("/alice/ro/");
        server.refusePostTo.add("/alice/ro/");

        LWSException e = assertThrows(LWSException.class,
                () -> client.putResource("/ro/x.txt", "x".getBytes(UTF_8), "text/plain"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        client.putResource("/ok.txt", "ok".getBytes(UTF_8), "text/plain");

        assertEquals(2, server.count("POST"), "still creating with POST");
        assertEquals("ok", server.content("/alice/ok.txt"));
    }

    @Test
    void aConflictOnCreateMeansTheNameIsTaken() {
        server.putStatus = 409;
        LWSException e = assertThrows(LWSException.class,
                () -> client.putResource("/taken.txt", "x".getBytes(UTF_8), "text/plain"));
        assertEquals(LWSException.Kind.EXISTS, e.kind());
    }

    @Test
    void anETagMissingFromAWriteResponseIsReadWithHead() throws IOException {
        server.etagOnWrites = false;   // LWS requires an ETag only on GET and HEAD responses
        Path body = Files.writeString(dir.resolve("body"), "one");
        LWSClient.Stored created = client.putResource("/e.txt", body, "text/plain", LWSClient.Precondition.CREATE_ONLY);
        assertNotNull(created.etag(), "taken from a HEAD after the POST");

        Files.writeString(body, "two");
        LWSClient.Stored updated = client.putResource("/e.txt", body, "text/plain",
                LWSClient.Precondition.ifMatch(created.etag()));
        assertNotNull(updated.etag(), "taken from a HEAD after the PUT");

        server.putFile("/alice/e.txt", "theirs");
        LWSException e = assertThrows(LWSException.class, () -> client.putResource("/e.txt", body, "text/plain",
                LWSClient.Precondition.ifMatch(updated.etag())));
        assertEquals(LWSException.Kind.CHANGED, e.kind());
        assertEquals("theirs", server.content("/alice/e.txt"));
    }

    @Test
    void aNewResourcePlacedOnAnotherOriginIsNotFollowed() throws IOException {
        server.locationOrigin = "http://elsewhere.invalid";
        Path body = Files.writeString(dir.resolve("body"), "n");
        LWSClient.Stored s = client.putResource("/n.txt", body, "text/plain", LWSClient.Precondition.CREATE_ONLY);

        assertEquals("/n.txt", s.path());
        assertEquals("n", new String(client.readAll("/n.txt"), UTF_8),
                "found through the listing, on the storage's origin, not at the Location");
    }

    // ------------------------------------------------------------------ deleting

    @Test
    void deleteRefusesANonEmptyContainerUnlessRecursive() {
        server.putFile("/alice/d/x.txt", "x");

        LWSException e = assertThrows(LWSException.class, () -> client.delete("/d", true));
        assertEquals(LWSException.Kind.NOT_EMPTY, e.kind());
        assertTrue(client.deleteRecursively("/d"));
        assertFalse(server.exists("/alice/d/"));
        assertFalse(server.exists("/alice/d/x.txt"));
        assertTrue(server.requests.contains("DELETE /alice/d/"));
    }

    @Test
    void aDeleteAnsweredGoneIsDone() {
        server.putFile("/alice/g.txt", "g");
        client.stat("/g.txt");
        server.deleteStatus = 410;   // LWS lets a server answer a deletion with 410 Gone

        client.delete("/g.txt", false);
    }

    @Test
    void aConflictDeletingAFileIsNotAFullDirectory() {
        server.putFile("/alice/c.txt", "c");
        server.mkdir("/alice/cd/");
        client.stat("/c.txt");
        client.stat("/cd");
        server.deleteStatus = 409;

        assertEquals(LWSException.Kind.CONFLICT,
                assertThrows(LWSException.class, () -> client.delete("/c.txt", false)).kind());
        assertEquals(LWSException.Kind.NOT_EMPTY,
                assertThrows(LWSException.class, () -> client.delete("/cd", true)).kind());
    }

    @Test
    void recursiveDeleteReportsWhenUnsupported() {
        server.recursiveDelete = false;
        server.putFile("/alice/d/x.txt", "x");

        assertFalse(client.deleteRecursively("/d"));
        assertTrue(server.exists("/alice/d/x.txt"));
    }

    // ------------------------------------------------------------------ discovery

    @Test
    void aStorageDescriptionLeadsToItsStorageRoot() {
        assertEquals(server.base(), client.storageRoot(server.storageDescription()));
        assertEquals(server.base(), client.storageRoot(server.base()), "a container is mounted as given");
    }

    @Test
    void aStorageRootIsUsedExactlyAsTheDescriptionNamesIt() {
        server.descriptionRoot = server.base().toString().replaceAll("/$", "");   // URIs are opaque
        URI root = client.storageRoot(server.storageDescription());
        assertEquals(URI.create(server.descriptionRoot), root);
        assertEquals(root, new LWSClient(root, AuthProvider.anonymous()).base(), "no '/' is added");
    }

    @Test
    void aTypedUrlMissingItsTrailingSlashStillFindsTheContainer() {
        URI typed = URI.create(server.base().toString().replaceAll("/$", ""));
        assertEquals(server.base(), client.storageRoot(typed));
    }

    @Test
    void aStorageDescriptionWithAMalformedRootIsAnError() {
        server.descriptionRoot = "http://[bad";
        LWSException e = assertThrows(LWSException.class, () -> client.storageRoot(server.storageDescription()));
        assertEquals(LWSException.Kind.INVALID, e.kind());
    }

    // ------------------------------------------------------------------ retries and errors

    @Test
    void the503sAreRetriedHonoringRetryAfter() {
        server.putFile("/alice/r.txt", "ok");
        client.stat("/r.txt");   // resolve first, so the counts below are only the reads
        server.failNext(2, 503, "0");

        assertEquals("ok", new String(client.readAll("/r.txt"), UTF_8));
        assertEquals(3, server.count("GET", "/alice/r.txt"));
    }

    @Test
    void retriesAreBoundedAndReportedAsBusy() {
        server.putFile("/alice/r.txt", "ok");
        client.stat("/r.txt");
        server.failNext(10, 429, null);

        LWSException e = assertThrows(LWSException.class, () -> client.readAll("/r.txt"));
        assertEquals(LWSException.Kind.BUSY, e.kind());
        assertEquals(3, server.count("GET", "/alice/r.txt"));
    }

    @Test
    void aRetryAfterBeyondTheLimitIsNotWaitedFor() {
        server.putFile("/alice/r.txt", "ok");
        client.stat("/r.txt");
        server.failNext(1, 503, "3600");

        LWSException e = assertThrows(LWSException.class, () -> client.readAll("/r.txt"));
        assertEquals(LWSException.Kind.BUSY, e.kind());
        assertEquals(1, server.count("GET", "/alice/r.txt"));
    }

    @Test
    void statusCodesMapToSpecificKinds() {
        Map<Integer, LWSException.Kind> expected = Map.of(
                413, LWSException.Kind.TOO_LARGE, 507, LWSException.Kind.NO_SPACE,
                405, LWSException.Kind.FORBIDDEN, 409, LWSException.Kind.CONFLICT,
                412, LWSException.Kind.CHANGED, 501, LWSException.Kind.UNSUPPORTED,
                500, LWSException.Kind.IO);
        expected.forEach((status, kind) ->
                assertEquals(kind, LWSException.fromStatus(status, "x").kind(), "HTTP " + status));
    }

    @Test
    void failingToObtainCredentialsIsPermissionDenied() {
        LWSClient noCredentials = new LWSClient(server.base(), (builder, method, uri) -> {
            throw new AuthException("token endpoint unreachable", new IOException("connection refused"));
        });
        LWSException e = assertThrows(LWSException.class, () -> noCredentials.stat("/x"));
        assertEquals(LWSException.Kind.FORBIDDEN, e.kind());
        assertTrue(server.requests.isEmpty(), "nothing is sent without credentials");
    }

    @Test
    void namesAreTheLastUriSegment() {
        assertEquals("a b.txt", LWSClient.lastSegment(URI.create("http://h/x/a%20b.txt")));
        assertEquals("dir", LWSClient.lastSegment(URI.create("http://h/x/dir/")));
        assertEquals("café", LWSClient.lastSegment(URI.create("http://h/x/caf%C3%A9")));
        assertEquals("a%2Fb", LWSClient.lastSegment(URI.create("http://h/x/a%2Fb")),
                "an encoded '/' does not split the name, and cannot be part of a file name");
        assertNull(LWSClient.lastSegment(URI.create("http://h/")));
    }

    private static Map<String, LWSClient.Member> byName(List<LWSClient.Member> members) {
        return members.stream().collect(Collectors.toMap(LWSClient.Member::name, m -> m));
    }

    private static Map<String, Boolean> kinds(Map<String, LWSClient.Member> members) {
        return members.values().stream().collect(Collectors.toMap(LWSClient.Member::name, LWSClient.Member::directory));
    }
}
