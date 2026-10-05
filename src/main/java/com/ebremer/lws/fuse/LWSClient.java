package com.ebremer.lws.fuse;

import com.ebremer.lws.fuse.auth.AuthException;
import com.ebremer.lws.fuse.auth.AuthProvider;
import com.ebremer.ns.LWS;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpRequest.BodyPublisher;
import java.net.http.HttpRequest.BodyPublishers;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandlers;
import java.net.http.HttpTimeoutException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.time.Duration;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.OptionalLong;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * A small, dependency-light client for a <a href="https://w3c.github.io/lws-protocol/">W3C
 * Linked Web Storage (LWS)</a> server, following the LWS 1.0 core protocol.
 *
 * <p><b>Navigation.</b> LWS URIs are assigned by the server and need not mirror the containment
 * hierarchy, so a filesystem path is resolved the way the protocol describes: from the storage
 * root (the {@link #base() base}), through each container's listing to the member with that name.
 * A member's name is the last segment of its URI. Resolutions are cached; listings for a short
 * while. If a container's listing may not be read, the path is mapped onto the base URI as a
 * hierarchical fallback.
 *
 * <p><b>Operations</b> (LWS core §9, HTTP binding):
 * <ul>
 *   <li>read — {@code GET} (with {@code Range}) / {@code HEAD}; a container is listed as
 *       {@code application/lws+json} (Turtle from servers following earlier drafts is accepted
 *       too), walking {@code Link: rel="next"} pages;</li>
 *   <li>create — {@code POST} to the parent container (with {@code Link: <lws:Container>;
 *       rel="type"} for a container); the server assigns the identifier, and its {@code Location}
 *       is the new URI. The wanted name goes along as a {@code Slug} header, a common hint that
 *       LWS lets servers ignore. A server that refuses {@code POST} with {@code 405}/{@code 501}
 *       but creates with {@code PUT} and {@code If-None-Match: *} (earlier drafts) is switched to
 *       that;</li>
 *   <li>update — {@code PUT} to the resource, conditionally with {@code If-Match} on a strong
 *       {@code ETag} (taken from a {@code HEAD} when a write response carries none);</li>
 *   <li>delete — {@code DELETE}, optionally recursive with {@code Depth: infinity}.</li>
 * </ul>
 * Directory vs. file comes from the listing's {@code type} or a {@code Link: rel="type"} header;
 * the trailing-slash convention is only a fallback.
 *
 * <p><b>Discovery.</b> {@link #storageRoot} follows a storage description
 * ({@code application/lws+cid}) to its {@code StorageRoot} service.
 *
 * <p><b>Credentials</b> come from an {@link AuthProvider}, which sees every request and response
 * and gets one chance to obtain a credential on a {@code 401} (for LWS, by token exchange at the
 * authorization server the challenge names). Requests and listing pages are only sent to the
 * base's origin. Idempotent requests that fail with {@code 429}/{@code 503} or a dropped connection
 * are retried a bounded number of times, honoring {@code Retry-After}; a {@code POST} is retried
 * only on {@code 429}/{@code 503}, which mean it was not processed.
 *
 * <p>This class is thread-safe.
 *
 * @author Erich Bremer
 */
public final class LWSClient {

    private static final Logger log = LoggerFactory.getLogger(LWSClient.class);

    private static final String LINK_CONTAINER_TYPE = "<" + ContainerListing.CONTAINER_IRI + ">; rel=\"type\"";
    private static final String LINK_DATA_RESOURCE_TYPE = "<" + ContainerListing.DATA_RESOURCE_IRI + ">; rel=\"type\"";
    private static final String LISTING_ACCEPT =
            "application/lws+json, application/ld+json;q=0.9, application/json;q=0.8, text/turtle;q=0.5";
    private static final String DESCRIPTION_ACCEPT =
            "application/lws+cid, application/lws+json;q=0.9, application/ld+json;q=0.8, application/json;q=0.7";
    private static final int MAX_CONTAINER_PAGES = 10_000;
    private static final long LISTING_TTL_MS = 2000L;
    private static final int MAX_RESOLVED_PATHS = 100_000;
    private static final char[] HEX = "0123456789ABCDEF".toCharArray();

    /**
     * A single direct member of a container, with whatever metadata the listing stated.
     *
     * @param uri           the member's URI (as listed)
     * @param size          size in bytes, or {@code -1} if the listing did not say
     * @param mtimeSeconds  last-modified time (epoch seconds), or {@code 0} if not stated
     * @param contentType   the media type, or {@code null} if not stated
     */
    public record Member(String name, boolean directory, URI uri, long size, long mtimeSeconds, String contentType) {

        public Member(String name, boolean directory) {
            this(name, directory, null, -1, 0, null);
        }
    }

    /**
     * The outcome of a ranged read.
     *
     * @param data          the bytes read (empty at or past the end of the resource)
     * @param rangeIgnored  the server answered with the whole entity instead of the range; reading
     *                      this resource range by range will download it again every time
     */
    public record ReadResult(byte[] data, boolean rangeIgnored) {}

    /**
     * A resource saved to a local file by {@link #download}.
     *
     * @param etag         the {@code ETag} response header, or {@code null}
     * @param contentType  the {@code Content-Type} response header, or {@code null}
     */
    public record Download(long length, String etag, String contentType, long mtimeSeconds) {}

    /**
     * Where an upload ended up.
     *
     * @param path  the path the content is stored at: the requested one, unless the server gave a
     *              newly created resource a different name
     * @param etag  the new {@code ETag}, or {@code null} if the server sent none
     */
    public record Stored(String path, String etag) {}

    /** A condition for an upload: none, create-only, or "unchanged since this ETag". */
    public record Precondition(String ifMatch, boolean createOnly) {
        public static final Precondition NONE = new Precondition(null, false);
        /** Create a new resource; never replace one (fails with {@link LWSException.Kind#EXISTS}). */
        public static final Precondition CREATE_ONLY = new Precondition(null, true);

        /**
         * {@code If-Match: etag}: fail with {@link LWSException.Kind#CHANGED} if the resource was
         * modified (or deleted) since. Weak or missing ETags cannot be matched this way and give
         * {@link #NONE}.
         */
        public static Precondition ifMatch(String etag) {
            return etag == null || etag.startsWith("W/") ? NONE : new Precondition(etag, false);
        }
    }

    /** What is known about a path: its URI and whether it is a container. */
    private record Node(URI uri, boolean container) {}

    /** A container listing, by member name, as of {@code fetchedAt}. */
    private record Listing(Map<String, Member> members, long fetchedAt) {}

    private final URI base;                 // the root container, exactly as named (LWS URIs are opaque)
    private final HttpClient http;
    private final AuthProvider auth;
    private final Duration requestTimeout;
    private final AtomicBoolean authFailing = new AtomicBoolean();
    private final Map<String, Node> nodes = Collections.synchronizedMap(
            new LinkedHashMap<>(256, 0.75f, true) {
                @Override
                protected boolean removeEldestEntry(Map.Entry<String, Node> eldest) {
                    return size() > MAX_RESOLVED_PATHS;
                }
            });
    private final Map<String, Listing> listings = new ConcurrentHashMap<>();
    private final Map<String, Object> listingLocks = new ConcurrentHashMap<>();
    private volatile boolean postCreateUnsupported;   // an earlier-draft server: create with PUT
    private volatile boolean postCreateWorked;        // a POST has created something: never switch to PUT
    private volatile int maxAttempts = 3;
    private volatile Duration initialBackoff = Duration.ofMillis(500);
    private volatile Duration maxRetryWait = Duration.ofSeconds(10);

    /**
     * @param base         the LWS storage root container, used exactly as given
     * @param bearerToken  optional fixed OAuth 2.0 bearer token, or {@code null} for anonymous access
     */
    public LWSClient(URI base, String bearerToken) {
        this(base, (bearerToken == null || bearerToken.isBlank())
                ? AuthProvider.anonymous() : AuthProvider.bearer(bearerToken));
    }

    /**
     * @param base  the LWS storage root container, used exactly as given: LWS URIs are opaque, so a
     *              container's need not end in {@code '/'} (see {@link #storageRoot} for finding it)
     * @param auth  the credential provider (see {@link com.ebremer.lws.fuse.auth.AuthProvider})
     */
    public LWSClient(URI base, AuthProvider auth) {
        this.base = base;
        this.auth = auth;
        this.requestTimeout = Duration.ofSeconds(60);
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NORMAL)
                .connectTimeout(Duration.ofSeconds(30))
                .build();
    }

    public URI base() {
        return base;
    }

    /**
     * Tune the retry of failed requests ({@code 429}/{@code 503}, dropped connections).
     *
     * @param attempts        total tries per request, at least 1 (default 3)
     * @param initialBackoff  wait before the first retry, doubled for each further one (default 0.5 s)
     * @param maxWait         the longest single wait, including a server's {@code Retry-After};
     *                        a longer {@code Retry-After} is not waited for (default 10 s)
     */
    public LWSClient retryPolicy(int attempts, Duration initialBackoff, Duration maxWait) {
        this.maxAttempts = Math.max(1, attempts);
        this.initialBackoff = initialBackoff;
        this.maxRetryWait = maxWait;
        return this;
    }

    // ------------------------------------------------------------------ discovery

    /**
     * The storage root container to mount for {@code url}: if {@code url} serves an LWS storage
     * description ({@code application/lws+cid}, or a JSON document typed {@code Storage}), the
     * {@code serviceEndpoint} of its {@code StorageRoot} service, exactly as given; otherwise the
     * resource {@code url} names (after any redirects), taken to be a container. As a convenience
     * for typed URLs, if nothing is at {@code url} and its path lacks a trailing {@code '/'}, the
     * same URL with one is tried.
     *
     * @throws LWSException {@link LWSException.Kind#INVALID} if {@code url} is a storage description
     *                      without a usable {@code StorageRoot}
     */
    public URI storageRoot(URI url) {
        HttpResponse<byte[]> r = getDescription(url);
        if (isMissing(r.statusCode()) && url.getRawQuery() == null && url.getRawFragment() == null
                && url.getRawPath() != null && !url.getRawPath().endsWith("/")) {
            URI withSlash = URI.create(url + "/");
            HttpResponse<byte[]> retry = getDescription(withSlash);
            if (is2xx(retry.statusCode())) {
                log.info("Nothing at {}; using {}", url, withSlash);
                r = retry;
            }
        }
        int sc = r.statusCode();
        if (!is2xx(sc)) {
            if (isMissing(sc)) {
                throw new LWSException(LWSException.Kind.NOT_FOUND, "Nothing at " + url);
            }
            throw LWSException.fromStatus(sc, url.toString());
        }
        URI here = r.uri();
        String ct = r.headers().firstValue("Content-Type").orElse("");
        boolean description = ct.toLowerCase(Locale.ROOT).startsWith("application/lws+cid");
        if (Links.hasType(r.headers(), here, ContainerListing.CONTAINER_IRI)
                || !(description || ContainerListing.isJson(ct))) {
            return here;
        }
        JsonObject doc;
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(r.body()))) {
            JsonValue v = reader.readValue();
            if (v.getValueType() != JsonValue.ValueType.OBJECT) {
                return here;
            }
            doc = v.asJsonObject();
        } catch (RuntimeException notJson) {
            return here;
        }
        if (!hasType(doc.get("type"), "Storage")) {
            return here;
        }
        JsonValue services = doc.get("service");
        List<JsonValue> serviceList = services instanceof JsonArray arr ? arr
                : services instanceof JsonObject one ? List.of(one) : List.of();
        for (JsonValue s : serviceList) {
            if (s instanceof JsonObject svc && hasType(svc.get("type"), "StorageRoot")
                    && svc.get("serviceEndpoint") instanceof JsonString ep) {
                URI root;
                try {
                    root = here.resolve(ep.getString());
                } catch (IllegalArgumentException e) {
                    throw new LWSException(LWSException.Kind.INVALID, "Storage description " + url
                            + " names an invalid storage root: " + ep.getString(), e);
                }
                log.info("{} is a storage description; mounting its storage root {}", url, root);
                return root;
            }
        }
        throw new LWSException(LWSException.Kind.INVALID, "Storage description " + url + " has no StorageRoot service");
    }

    private HttpResponse<byte[]> getDescription(URI url) {
        return send("GET", url,
                HttpRequest.newBuilder(url).timeout(requestTimeout).header("Accept", DESCRIPTION_ACCEPT).GET(),
                BodyHandlers.ofByteArray());
    }

    private static boolean hasType(JsonValue type, String wanted) {
        if (type instanceof JsonString s) {
            return matchesType(s.getString(), wanted);
        }
        if (type instanceof JsonArray a) {
            for (JsonValue v : a) {
                if (v instanceof JsonString s && matchesType(s.getString(), wanted)) {
                    return true;
                }
            }
        }
        return false;
    }

    private static boolean matchesType(String t, String wanted) {
        return t.equals(wanted) || t.equals("lws:" + wanted) || t.equals(LWS.NS + wanted);
    }

    // ------------------------------------------------------------------ navigation

    /**
     * Fetch metadata for a path. Returns {@code null} if nothing exists there (→ {@code ENOENT}).
     * Answered from the parent container's listing; a {@code HEAD} is made only when the listing
     * does not state a file's size.
     */
    public ResourceInfo stat(String path) {
        if (isRoot(path)) {
            HttpResponse<Void> r = head(base);
            if (is2xx(r.statusCode())) {
                return new ResourceInfo(true, 0, lastModified(r.headers()));
            }
            if (isMissing(r.statusCode())) {
                return null;
            }
            throw LWSException.fromStatus(r.statusCode(), path);
        }
        Member m = member(path);
        if (m == null) {
            return null;
        }
        if (m.directory()) {
            return new ResourceInfo(true, 0, m.mtimeSeconds());
        }
        if (m.size() >= 0) {
            return new ResourceInfo(false, m.size(), m.mtimeSeconds(), m.contentType());
        }
        HttpResponse<Void> r = head(m.uri());
        if (isMissing(r.statusCode())) {
            forget(path);
            return null;
        }
        if (!is2xx(r.statusCode())) {
            throw LWSException.fromStatus(r.statusCode(), path);
        }
        long mtime = lastModified(r.headers());
        return new ResourceInfo(false, sizeOf(m.uri(), r.headers()), mtime > 0 ? mtime : m.mtimeSeconds(),
                r.headers().firstValue("Content-Type").orElse(m.contentType()));
    }

    /**
     * A file's size: its {@code HEAD} response's {@code Content-Length}, which HTTP lets a server
     * omit; else the total in the {@code Content-Range} of a one-byte range request (LWS servers
     * must support ranges); else 0.
     */
    private long sizeOf(URI uri, HttpHeaders headHeaders) {
        OptionalLong declared = headHeaders.firstValueAsLong("Content-Length");
        if (declared.isPresent()) {
            return declared.getAsLong();
        }
        HttpResponse<InputStream> r = send("GET", uri, baseBuilder(uri).header("Range", "bytes=0-0").GET(),
                BodyHandlers.ofInputStream());
        try (InputStream ignored = r.body()) {   // closing abandons a whole body sent instead of the range
            int sc = r.statusCode();
            if (sc == 206 || sc == 416) {   // "bytes 0-0/N", or "bytes */N" (an empty resource)
                String cr = r.headers().firstValue("Content-Range").orElse("");
                int slash = cr.lastIndexOf('/');
                if (slash >= 0) {
                    try {
                        return Long.parseLong(cr.substring(slash + 1).trim());
                    } catch (NumberFormatException unknownLength) {
                        return 0;   // "*": the server does not know either
                    }
                }
                return 0;
            }
            return sc == 200 ? r.headers().firstValueAsLong("Content-Length").orElse(0L) : 0;
        } catch (IOException e) {
            return 0;
        }
    }

    /**
     * List the members of a container, freshly fetched: every page of its representation, following
     * {@code Link: rel="next"} (or, from earlier-draft servers, in-body {@code lws:next}/{@code lws:first})
     * as long as the page is on the base's origin. A member's name is the last segment of its URI;
     * if two members would share a name, the first is kept.
     */
    public List<Member> list(String path) {
        return List.copyOf(fetchListing(path).members().values());
    }

    /** The member at {@code path} per its parent's listing (cached briefly), or {@code null} if there is none. */
    private Member member(String path) {
        String parent = parentOf(path);
        Listing l = listings.get(parent);
        if (l == null || System.currentTimeMillis() - l.fetchedAt() > LISTING_TTL_MS) {
            try {
                l = fetchListing(parent);
            } catch (LWSException e) {
                if (e.kind() == LWSException.Kind.NOT_FOUND) {
                    return null;   // no parent, no member
                }
                if (e.kind() == LWSException.Kind.FORBIDDEN) {
                    return probeConventional(path);   // the listing is private; the member may not be
                }
                throw e;
            }
        }
        return l.members().get(nameOf(path));
    }

    private Listing fetchListing(String path) {
        Object lock = listingLocks.computeIfAbsent(path, p -> new Object());
        synchronized (lock) {
            Listing cached = listings.get(path);
            if (cached != null && System.currentTimeMillis() - cached.fetchedAt() < 200) {
                return cached;   // another thread just fetched it
            }
            URI container = resolveContainer(path);
            Map<String, Member> members = new LinkedHashMap<>();
            Set<String> visited = new HashSet<>();
            URI page = container;
            int guard = 0;
            while (page != null && visited.add(page.toString()) && guard++ < MAX_CONTAINER_PAGES) {
                HttpResponse<byte[]> r = send("GET", page,
                        baseBuilder(page).header("Accept", LISTING_ACCEPT).GET(), BodyHandlers.ofByteArray());
                int sc = r.statusCode();
                if (isMissing(sc)) {
                    forget(path);
                    throw new LWSException(LWSException.Kind.NOT_FOUND, "No such container: " + path);
                }
                if (!is2xx(sc)) {
                    throw LWSException.fromStatus(sc, path);
                }
                ContainerListing.Page p = ContainerListing.parse(r.body(),
                        r.headers().firstValue("Content-Type").orElse(null), r.uri());
                for (ContainerListing.Entry e : p.entries()) {
                    addMember(path, container, e, members);
                }
                URI next = Links.first(r.headers(), r.uri(), "next");
                if (next == null) {
                    next = p.bodyNext();
                }
                if (next != null) {   // used as given: page URIs are opaque to clients
                    if (!isSameOrigin(next)) {
                        throw new LWSException(LWSException.Kind.IO, "Listing of " + path
                                + " links a page outside the storage's origin (" + next + "); not following it");
                    }
                }
                page = next;
            }
            Listing l = new Listing(Collections.unmodifiableMap(members), System.currentTimeMillis());
            listings.put(path, l);
            sweepListings();
            return l;
        }
    }

    private void addMember(String parentPath, URI container, ContainerListing.Entry e, Map<String, Member> into) {
        if (e.uri().equals(container) || !isSameOrigin(e.uri())) {
            return;   // the container itself, or a member on another origin (never sent credentials)
        }
        String name = lastSegment(e.uri());
        if (name == null || name.equals(".") || name.equals("..") || into.containsKey(name)) {
            return;
        }
        into.put(name, new Member(name, e.container(), e.uri(), e.size(), e.mtimeSeconds(), e.format()));
        nodes.put(childPath(parentPath, name), new Node(e.uri(), e.container()));
    }

    /** The URI of the existing resource at {@code path}, or {@code null} if there is none. */
    URI resolve(String path) {
        if (isRoot(path)) {
            return base;
        }
        Node n = nodes.get(path);
        if (n != null) {
            return n.uri();
        }
        Member m = member(path);
        return m == null ? null : m.uri();
    }

    private URI resolveContainer(String path) {
        if (isRoot(path)) {
            return base;
        }
        Node n = nodes.get(path);
        if (n == null) {
            Member m = member(path);
            if (m == null) {
                throw new LWSException(LWSException.Kind.NOT_FOUND, "No such container: " + path);
            }
            n = new Node(m.uri(), m.directory());
        }
        if (!n.container()) {
            throw new LWSException(LWSException.Kind.NOT_FOUND, "Not a container: " + path);
        }
        return n.uri();
    }

    /**
     * Fallback when the parent's listing may not be read: look the path up where a hierarchical
     * server would put it, as a resource, then as a container.
     */
    private Member probeConventional(String path) {
        for (boolean container : new boolean[] {false, true}) {
            URI uri = conventionalUri(path, container);
            HttpResponse<Void> r = head(uri);
            int sc = r.statusCode();
            if (is2xx(sc)) {
                boolean dir = Links.hasType(r.headers(), r.uri(), ContainerListing.CONTAINER_IRI)
                        || (container && !Links.hasType(r.headers(), r.uri(), ContainerListing.DATA_RESOURCE_IRI));
                nodes.put(path, new Node(uri, dir));
                return new Member(nameOf(path), dir, uri, dir ? 0 : sizeOf(uri, r.headers()),
                        lastModified(r.headers()), dir ? null : r.headers().firstValue("Content-Type").orElse(null));
            }
            if (!isMissing(sc)) {
                throw LWSException.fromStatus(sc, path);
            }
        }
        return null;
    }

    // ------------------------------------------------------------------ reading

    /** Read the entire resource into memory, or {@code null} if it does not exist. */
    public byte[] readAll(String path) {
        URI uri = resolve(path);
        if (uri == null) {
            return null;
        }
        HttpResponse<byte[]> r = send("GET", uri, baseBuilder(uri).GET(), BodyHandlers.ofByteArray());
        int sc = r.statusCode();
        if (is2xx(sc)) {
            return r.body();
        }
        if (isMissing(sc)) {
            forget(path);
            return null;
        }
        throw LWSException.fromStatus(sc, path);
    }

    /**
     * Stream the entire resource into {@code target} (replacing it), or return {@code null} if it
     * does not exist. A {@code Content-Length} larger than the free space where {@code target}
     * lives fails with {@link LWSException.Kind#NO_SPACE} before anything is transferred.
     */
    public Download download(String path, Path target) {
        URI uri = resolve(path);
        if (uri == null) {
            return null;
        }
        HttpResponse<InputStream> r = send("GET", uri, baseBuilder(uri).GET(), BodyHandlers.ofInputStream());
        int sc = r.statusCode();
        try (InputStream in = r.body()) {
            if (isMissing(sc)) {
                forget(path);
                return null;
            }
            if (!is2xx(sc)) {
                throw LWSException.fromStatus(sc, path);
            }
            OptionalLong declared = r.headers().firstValueAsLong("Content-Length");
            if (declared.isPresent() && declared.getAsLong() > usableSpace(target)) {
                throw new LWSException(LWSException.Kind.NO_SPACE, path + " is " + declared.getAsLong()
                        + " bytes, more than the free space for buffering it locally");
            }
            long n = Files.copy(in, target, StandardCopyOption.REPLACE_EXISTING);
            HttpHeaders h = r.headers();
            return new Download(n, h.firstValue("ETag").orElse(null),
                    h.firstValue("Content-Type").orElse(null), lastModified(h));
        } catch (IOException e) {
            throw new LWSException(LWSException.Kind.IO, "GET " + uri + " failed", e);
        }
    }

    private static long usableSpace(Path target) {
        try {
            Path dir = target.toAbsolutePath().getParent();
            return Files.getFileStore(dir).getUsableSpace();
        } catch (IOException | RuntimeException unknown) {
            return Long.MAX_VALUE;
        }
    }

    /** Read up to {@code length} bytes starting at {@code offset}, using an HTTP Range request. */
    public byte[] read(String path, long offset, int length) {
        return readRange(path, offset, length).data();
    }

    /**
     * Read up to {@code length} bytes starting at {@code offset} with an HTTP Range request. If the
     * server ignores {@code Range} and sends the whole entity, only the bytes up to the end of the
     * requested range are received (the rest of the transfer is abandoned) and the result says
     * so, letting the caller switch to downloading the resource once.
     */
    public ReadResult readRange(String path, long offset, int length) {
        if (length <= 0) {
            return new ReadResult(new byte[0], false);
        }
        URI uri = resolve(path);
        if (uri == null) {
            throw new LWSException(LWSException.Kind.NOT_FOUND, "No such resource: " + path);
        }
        long last = offset + (long) length - 1;
        HttpResponse<InputStream> r = send("GET", uri,
                baseBuilder(uri).header("Range", "bytes=" + offset + "-" + last).GET(),
                BodyHandlers.ofInputStream());
        int sc = r.statusCode();
        try (InputStream in = r.body()) {   // closing early abandons the rest of a 200 body
            if (sc == 206) {
                return new ReadResult(in.readNBytes(length), false);
            }
            if (sc == 200) {
                long skipped = in.skip(offset);
                while (skipped < offset) {   // skip() may stop short; read to be sure
                    if (in.read() < 0) {
                        return new ReadResult(new byte[0], true);
                    }
                    skipped++;
                }
                return new ReadResult(in.readNBytes(length), true);
            }
            if (sc == 416) {
                return new ReadResult(new byte[0], false);   // requested range beyond end of resource
            }
            if (isMissing(sc)) {
                forget(path);
                throw new LWSException(LWSException.Kind.NOT_FOUND, "No such resource: " + path);
            }
            throw LWSException.fromStatus(sc, path);
        } catch (IOException e) {
            throw new LWSException(LWSException.Kind.IO, "GET " + uri + " failed", e);
        }
    }

    // ------------------------------------------------------------------ writing

    /** Create or replace a resource with the given bytes and content type. */
    public void putResource(String path, byte[] data, String contentType) {
        store(path, () -> BodyPublishers.ofByteArray(data), contentType, Precondition.NONE);
    }

    /**
     * Upload the content of a local file to {@code path}, subject to {@code precondition}:
     * {@link Precondition#CREATE_ONLY} creates a new resource ({@code POST} to the parent); an
     * {@code If-Match} precondition updates the existing one ({@code PUT}); {@link Precondition#NONE}
     * updates it if it exists and creates it otherwise.
     *
     * @return where the content was stored and its new {@code ETag}
     * @throws LWSException {@link LWSException.Kind#EXISTS} or {@link LWSException.Kind#CHANGED}
     *                      when the precondition fails (including the resource having been deleted)
     */
    public Stored putResource(String path, Path file, String contentType, Precondition precondition) {
        if (!Files.exists(file)) {
            throw new LWSException(LWSException.Kind.IO, "Local buffer for " + path + " is missing",
                    new FileNotFoundException(file.toString()));
        }
        return store(path, () -> {
            try {
                return BodyPublishers.ofFile(file);
            } catch (FileNotFoundException e) {
                throw new LWSException(LWSException.Kind.IO, "Local buffer for " + path + " is missing", e);
            }
        }, contentType, precondition);
    }

    private interface Body {
        BodyPublisher get();
    }

    private Stored store(String path, Body body, String contentType, Precondition precondition) {
        if (precondition.createOnly()) {
            // A POST never replaces anything, but given a taken name the server would store the
            // content under another one; report the clash instead, as If-None-Match: * would.
            if (!postCreateUnsupported && resolve(path) != null) {
                throw new LWSException(LWSException.Kind.EXISTS, path + " already exists on the server");
            }
            return create(path, body.get(), contentType, false);
        }
        URI uri = resolve(path);
        if (uri == null) {
            if (precondition.ifMatch() != null) {
                throw new LWSException(LWSException.Kind.CHANGED, path + " was deleted on the server since it was read");
            }
            return create(path, body.get(), contentType, false);
        }
        try {
            return update(path, uri, body.get(), contentType, precondition.ifMatch());
        } catch (LWSException e) {
            if (e.kind() != LWSException.Kind.NOT_FOUND) {
                throw e;
            }
            if (precondition.ifMatch() != null) {
                throw new LWSException(LWSException.Kind.CHANGED, path + " was deleted on the server since it was read");
            }
            return create(path, body.get(), contentType, false);   // gone meanwhile: recreate it
        }
    }

    /** Replace an existing resource's content ({@code PUT}); {@code 404} if it no longer exists. */
    private Stored update(String path, URI uri, BodyPublisher body, String contentType, String ifMatch) {
        HttpRequest.Builder b = baseBuilder(uri).header("Content-Type", contentType).PUT(body);
        if (ifMatch != null) {
            b.header("If-Match", ifMatch);
        }
        HttpResponse<Void> r = send("PUT", uri, b, BodyHandlers.discarding());
        int sc = r.statusCode();
        if (sc == 412) {
            throw new LWSException(LWSException.Kind.CHANGED, path + " was changed on the server since it was read");
        }
        if (isMissing(sc)) {
            forget(path);
            throw new LWSException(LWSException.Kind.NOT_FOUND, "No such resource: " + path);
        }
        if (!is2xx(sc)) {
            throw LWSException.fromStatus(sc, path);
        }
        invalidateListing(parentOf(path));
        return new Stored(path, etagAfterWrite(uri, r.headers()));
    }

    /**
     * The new {@code ETag} after a successful write. LWS requires one on {@code GET}/{@code HEAD}
     * responses but not on {@code 201}/{@code 204}, so when the write response has none, a
     * {@code HEAD} asks for it; without it the next save could not be conditional.
     */
    private String etagAfterWrite(URI uri, HttpHeaders writeHeaders) {
        Optional<String> etag = writeHeaders.firstValue("ETag");
        if (etag.isPresent()) {
            return etag.get();
        }
        try {
            HttpResponse<Void> r = head(uri);
            return is2xx(r.statusCode()) ? r.headers().firstValue("ETag").orElse(null) : null;
        } catch (LWSException e) {
            log.debug("Could not read the ETag of {} after writing it: {}", uri, e.getMessage());
            return null;
        }
    }

    /**
     * Create a container at {@code path}: {@code POST} to the parent with
     * {@code Link: <lws:Container>; rel="type"} and a {@code Slug} name hint.
     *
     * @throws LWSException {@link LWSException.Kind#EXISTS} if something already exists there
     */
    public void putContainer(String path) {
        if (resolve(path) != null) {
            throw new LWSException(LWSException.Kind.EXISTS, path + " already exists on the server");
        }
        Stored s = create(path, BodyPublishers.noBody(), null, true);
        if (!s.path().equals(path)) {
            log.warn("The server created directory {} as {}", path, s.path());
        }
    }

    /**
     * Create a new resource ({@code POST} to the parent container). The server assigns the
     * identifier; the wanted name is offered as a {@code Slug} header, a widely used hint that LWS
     * does not prescribe, so the server may choose another name. The result says where it went.
     * <p>A {@code 405}/{@code 501} may come from an earlier-draft server, which creates with
     * {@code PUT} and {@code If-None-Match: *} at the hierarchical URI, or from one container that
     * refuses creation. So the {@code PUT} is tried only while no {@code POST} has worked, and the
     * client switches to it only if it succeeds; otherwise the {@code POST}'s refusal is reported.
     */
    private Stored create(String path, BodyPublisher body, String contentType, boolean container) {
        if (postCreateUnsupported) {
            return putCreate(path, body, contentType, container);
        }
        String parent = parentOf(path);
        String name = nameOf(path);
        URI parentUri = resolveContainer(parent);
        StringBuilder slug = new StringBuilder();
        appendEncodedSegment(slug, name);
        HttpRequest.Builder b = baseBuilder(parentUri).header("Slug", slug.toString()).POST(body);
        if (container) {
            b.header("Link", LINK_CONTAINER_TYPE);
        } else {
            b.header("Content-Type", contentType);
        }
        HttpResponse<Void> r = send("POST", parentUri, b, BodyHandlers.discarding());
        int sc = r.statusCode();
        if ((sc == 405 || sc == 501) && !postCreateWorked) {
            Stored s;
            try {
                s = putCreate(path, body, contentType, container);
            } catch (LWSException e) {
                if (e.kind() == LWSException.Kind.EXISTS) {
                    throw e;
                }
                throw LWSException.fromStatus(sc, path);   // not an earlier-draft server either
            }
            if (!postCreateUnsupported) {
                postCreateUnsupported = true;
                log.info("The server does not create resources with POST (an earlier LWS draft); creating with PUT");
            }
            return s;
        }
        if (isMissing(sc)) {
            forget(parent);
            throw new LWSException(LWSException.Kind.NOT_FOUND, "No such container: " + parent);
        }
        if (sc == 409) {
            throw new LWSException(LWSException.Kind.EXISTS, path + " already exists on the server");
        }
        if (!is2xx(sc)) {
            throw LWSException.fromStatus(sc, path);
        }
        postCreateWorked = true;
        URI created = r.headers().firstValue("Location")
                .map(loc -> r.uri().resolve(loc.trim()))
                .orElseGet(() -> conventionalChild(parentUri, name, container));
        invalidateListing(parent);
        if (!isSameOrigin(created)) {
            // Never followed: requests there would carry the storage's credentials to another origin.
            log.warn("The server placed the new resource {} at {}, outside the storage's origin; "
                    + "it will not be shown", path, created);
            return new Stored(path, null);
        }
        String actualName = lastSegment(created);
        String actualPath = path;
        if (actualName != null && !actualName.equals(name)) {
            actualPath = childPath(parent, actualName);
            log.warn("The server named the new resource {} instead of {}", actualPath, path);
        }
        nodes.put(actualPath, new Node(created, container));
        return new Stored(actualPath, container ? null : etagAfterWrite(created, r.headers()));
    }

    /** Earlier-draft creation: {@code PUT} at the hierarchical URI, create-only. */
    private Stored putCreate(String path, BodyPublisher body, String contentType, boolean container) {
        URI uri = conventionalUri(path, container);
        HttpRequest.Builder b = baseBuilder(uri).header("If-None-Match", "*");
        if (container) {
            b.header("Content-Type", "text/turtle").header("Link", LINK_CONTAINER_TYPE).PUT(BodyPublishers.noBody());
        } else {
            b.header("Content-Type", contentType).PUT(body);
            if (!isRdfContentType(contentType)) {
                b.header("Link", LINK_DATA_RESOURCE_TYPE);
            }
        }
        HttpResponse<Void> r = send("PUT", uri, b, BodyHandlers.discarding());
        int sc = r.statusCode();
        if (sc == 412) {
            throw new LWSException(LWSException.Kind.EXISTS, path + " already exists on the server");
        }
        if (!is2xx(sc)) {
            throw LWSException.fromStatus(sc, path);
        }
        nodes.put(path, new Node(uri, container));
        invalidateListing(parentOf(path));
        return new Stored(path, container ? null : etagAfterWrite(uri, r.headers()));
    }

    // ------------------------------------------------------------------ deleting

    /**
     * Delete a resource or container. A {@code 409} on a container is reported as
     * {@code NOT_EMPTY}; a {@code 410 Gone} counts as deleted (LWS lets servers use it).
     */
    public void delete(String path, boolean directory) {
        URI uri = resolve(path);
        if (uri == null) {
            throw new LWSException(LWSException.Kind.NOT_FOUND, "No such resource: " + path);
        }
        HttpResponse<Void> r = send("DELETE", uri, baseBuilder(uri).DELETE(), BodyHandlers.discarding());
        int sc = r.statusCode();
        if (is2xx(sc) || sc == 410) {
            forget(path);
            return;
        }
        if (sc == 409) {
            throw directory
                    ? new LWSException(LWSException.Kind.NOT_EMPTY, "Container not empty: " + path)
                    : new LWSException(LWSException.Kind.CONFLICT, "The server refused to delete " + path + " (409)");
        }
        if (isMissing(sc)) {
            forget(path);
        }
        throw LWSException.fromStatus(sc, path);
    }

    /**
     * Delete a container and everything in it in one request ({@code Depth: infinity}), if the
     * server supports recursive deletion.
     *
     * @return false if the server does not (it refused a non-empty container); nothing was deleted
     */
    public boolean deleteRecursively(String path) {
        URI uri = resolve(path);
        if (uri == null) {
            throw new LWSException(LWSException.Kind.NOT_FOUND, "No such container: " + path);
        }
        HttpResponse<Void> r = send("DELETE", uri,
                baseBuilder(uri).header("Depth", "infinity").DELETE(), BodyHandlers.discarding());
        int sc = r.statusCode();
        if (is2xx(sc)) {
            forget(path);
            return true;
        }
        if (sc == 409 || sc == 400 || sc == 405 || sc == 501) {
            return false;
        }
        throw LWSException.fromStatus(sc, path);
    }

    // ------------------------------------------------------------------ cache upkeep

    /** Drop what is known about {@code path} (and anything below it) and its parent's listing. */
    void forget(String path) {
        String prefix = path.endsWith("/") ? path : path + "/";
        synchronized (nodes) {
            nodes.remove(path);
            nodes.keySet().removeIf(k -> k.startsWith(prefix));
        }
        listings.remove(path);
        listings.keySet().removeIf(k -> k.startsWith(prefix));
        invalidateListing(parentOf(path));
    }

    private void invalidateListing(String path) {
        listings.remove(path);
    }

    private void sweepListings() {
        if (listings.size() > 1024) {
            long now = System.currentTimeMillis();
            listings.values().removeIf(l -> now - l.fetchedAt() > LISTING_TTL_MS);
        }
    }

    /** Best-effort content type for a name, by file extension. */
    public static String guessContentType(String name) {
        String n = name.toLowerCase(Locale.ROOT);
        int dot = n.lastIndexOf('.');
        String ext = dot >= 0 ? n.substring(dot + 1) : "";
        return switch (ext) {
            case "ttl" -> "text/turtle";
            case "jsonld" -> "application/ld+json";
            case "json" -> "application/json";
            case "nt" -> "application/n-triples";
            case "nq" -> "application/n-quads";
            case "trig" -> "application/trig";
            case "rdf", "owl", "xml" -> "application/rdf+xml";
            case "txt", "text", "md" -> "text/plain";
            case "html", "htm" -> "text/html";
            case "csv" -> "text/csv";
            case "png" -> "image/png";
            case "jpg", "jpeg" -> "image/jpeg";
            case "gif" -> "image/gif";
            case "svg" -> "image/svg+xml";
            case "tif", "tiff" -> "image/tiff";
            case "pdf" -> "application/pdf";
            case "zip" -> "application/zip";
            case "gz" -> "application/gzip";
            default -> "application/octet-stream";
        };
    }

    // ------------------------------------------------------------------ HTTP plumbing

    private HttpRequest.Builder baseBuilder(URI uri) {
        return HttpRequest.newBuilder(uri).timeout(requestTimeout);
    }

    private HttpResponse<Void> head(URI uri) {
        return send("HEAD", uri, baseBuilder(uri).method("HEAD", BodyPublishers.noBody()), BodyHandlers.discarding());
    }

    /**
     * Authorize the request through the {@link AuthProvider} and send it.
     * <ul>
     *   <li>On a {@code 401} the provider sees the rejected response; if it has different
     *       credentials to offer, the request is re-authorized and retried once.</li>
     *   <li>A {@code 429}/{@code 503}, or (except for {@code POST}) a connection that failed for a
     *       reason other than a timeout, is retried up to the configured number of attempts,
     *       waiting as long as the server's {@code Retry-After} asks (within the configured
     *       maximum) or else backing off exponentially.</li>
     *   <li>Every attempt is re-authorized, so a DPoP proof is never replayed.</li>
     * </ul>
     */
    private <T> HttpResponse<T> send(String method, URI uri, HttpRequest.Builder builder,
                                     HttpResponse.BodyHandler<T> handler) {
        boolean idempotent = !method.equals("POST");
        boolean authRetried = false;
        int attempt = 1;
        while (true) {
            authorize(builder, method, uri);
            HttpResponse<T> resp;
            try {
                resp = http.send(builder.build(), handler);
            } catch (HttpTimeoutException e) {
                throw new LWSException(LWSException.Kind.IO, method + " " + uri + " timed out", e);
            } catch (IOException e) {
                if (idempotent && attempt < maxAttempts) {
                    log.debug("{} {} failed ({}); retrying", method, uri, e.toString());
                    pause(backoff(attempt), method, uri);
                    attempt++;
                    continue;
                }
                throw new LWSException(LWSException.Kind.IO, method + " " + uri + " failed: " + e.getMessage(), e);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                throw new LWSException(LWSException.Kind.IO, method + " " + uri + " interrupted", e);
            }
            auth.onResponse(resp);
            int sc = resp.statusCode();
            if (sc == 401 && !authRetried) {
                authRetried = true;
                if (onUnauthorized(resp, method, uri)) {
                    discard(resp);
                    continue;   // new credentials; does not count as an attempt
                }
            }
            if ((sc == 429 || sc == 503) && attempt < maxAttempts) {
                Duration wait = retryAfter(resp.headers()).orElse(backoff(attempt));
                if (wait.compareTo(maxRetryWait) <= 0) {
                    log.debug("{} {} returned {}; retrying in {} ms", method, uri, sc, wait.toMillis());
                    discard(resp);
                    pause(wait, method, uri);
                    attempt++;
                    continue;
                }
            }
            return resp;
        }
    }

    /** Run the auth provider, turning a failure to obtain credentials into "permission denied". */
    private void authorize(HttpRequest.Builder builder, String method, URI uri) {
        try {
            auth.authorize(builder, method, uri);
            if (authFailing.get() && authFailing.compareAndSet(true, false)) {
                log.info("Authentication is working again");
            }
        } catch (AuthException e) {
            throw authFailure(e, method, uri);
        }
    }

    private boolean onUnauthorized(HttpResponse<?> resp, String method, URI uri) {
        try {
            return auth.onUnauthorized(resp);
        } catch (AuthException e) {
            discard(resp);
            throw authFailure(e, method, uri);
        }
    }

    private LWSException authFailure(AuthException e, String method, URI uri) {
        // Every filesystem operation would hit this; report it once, not on each request.
        if (authFailing.compareAndSet(false, true)) {
            log.error("Authentication failed; requests are refused until it recovers: {}", e.getMessage());
        } else {
            log.debug("Authentication still failing: {}", e.getMessage());
        }
        return new LWSException(LWSException.Kind.FORBIDDEN, "No credentials for " + method + " " + uri, e);
    }

    private Duration backoff(int attempt) {
        return initialBackoff.multipliedBy(1L << Math.min(attempt - 1, 10));
    }

    private static void pause(Duration wait, String method, URI uri) {
        try {
            Thread.sleep(wait.toMillis());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new LWSException(LWSException.Kind.IO, method + " " + uri + " interrupted", e);
        }
    }

    /** Release a response that will not be used (an unread streamed body holds its connection). */
    private static void discard(HttpResponse<?> resp) {
        if (resp.body() instanceof AutoCloseable c) {
            try {
                c.close();
            } catch (Exception ignore) {
                // nothing more to release
            }
        }
    }

    /** {@code Retry-After} as delay-seconds or an HTTP-date, if present and parseable. */
    static Optional<Duration> retryAfter(HttpHeaders headers) {
        Optional<String> v = headers.firstValue("Retry-After");
        if (v.isEmpty()) {
            return Optional.empty();
        }
        String s = v.get().trim();
        try {
            return Optional.of(Duration.ofSeconds(Math.max(0, Long.parseLong(s))));
        } catch (NumberFormatException notSeconds) {
            try {
                Instant at = ZonedDateTime.parse(s, DateTimeFormatter.RFC_1123_DATE_TIME).toInstant();
                Duration d = Duration.between(Instant.now(), at);
                return Optional.of(d.isNegative() ? Duration.ZERO : d);
            } catch (RuntimeException unparseable) {
                return Optional.empty();
            }
        }
    }

    // ------------------------------------------------------------------ URIs and names

    /** Whether {@code uri} is on the base's origin (scheme, host, port, no user-info), so it may carry credentials. */
    boolean isSameOrigin(URI uri) {
        if (!uri.isAbsolute() || uri.getRawAuthority() == null || uri.getHost() == null) {
            return false;
        }
        return uri.getScheme().equalsIgnoreCase(base.getScheme())
                && uri.getHost().equalsIgnoreCase(base.getHost())
                && effectivePort(uri) == effectivePort(base)
                && uri.getRawUserInfo() == null;
    }

    private static int effectivePort(URI uri) {
        if (uri.getPort() >= 0) {
            return uri.getPort();
        }
        return "https".equalsIgnoreCase(uri.getScheme()) ? 443 : 80;
    }

    /**
     * A member's name: the last segment of its URI path, ignoring a trailing slash, percent-decoded
     * on its own (so an encoded {@code %2F} does not split it). A segment that decodes to a
     * {@code '/'} or NUL, which no file name may contain, is kept encoded.
     */
    static String lastSegment(URI uri) {
        String p = uri.getRawPath();
        if (p == null) {
            return null;
        }
        if (p.endsWith("/")) {
            p = p.substring(0, p.length() - 1);
        }
        String raw = p.substring(p.lastIndexOf('/') + 1);
        if (raw.isEmpty()) {
            return null;
        }
        String name = percentDecode(raw);
        return name.indexOf('/') >= 0 || name.indexOf('\0') >= 0 ? raw : name;
    }

    /** Decode {@code %XX} escapes as UTF-8; a malformed escape is kept as it is. */
    private static String percentDecode(String s) {
        if (s.indexOf('%') < 0) {
            return s;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length());
        int i = 0;
        while (i < s.length()) {
            if (s.charAt(i) == '%' && i + 2 < s.length()
                    && Character.digit(s.charAt(i + 1), 16) >= 0 && Character.digit(s.charAt(i + 2), 16) >= 0) {
                out.write(Character.digit(s.charAt(i + 1), 16) << 4 | Character.digit(s.charAt(i + 2), 16));
                i += 3;
            } else {
                int end = s.indexOf('%', i + 1);   // copy the literal run up to the next escape whole
                end = end < 0 ? s.length() : end;
                out.writeBytes(s.substring(i, end).getBytes(StandardCharsets.UTF_8));
                i = end;
            }
        }
        return out.toString(StandardCharsets.UTF_8);
    }

    /** Map a FUSE path to a resource URL as a hierarchical server would (no trailing slash). */
    URI resourceUri(String path) {
        return conventionalUri(path, false);
    }

    /** Map a FUSE path to a container URL as a hierarchical server would (trailing slash). */
    URI containerUri(String path) {
        return conventionalUri(path, true);
    }

    private static URI conventionalChild(URI parent, String name, boolean container) {
        StringBuilder sb = new StringBuilder(parent.toString());
        if (sb.charAt(sb.length() - 1) != '/') {
            sb.append('/');
        }
        appendEncodedSegment(sb, name);
        if (container) {
            sb.append('/');
        }
        return URI.create(sb.toString());
    }

    private URI conventionalUri(String fusePath, boolean container) {
        String rel = fusePath == null ? "" : fusePath;
        while (rel.startsWith("/")) {
            rel = rel.substring(1);
        }
        if (rel.isEmpty()) {
            return base;
        }
        // Append encoded segments to the base text rather than resolving a relative reference:
        // resolving would parse a first segment such as "x:" as a URI scheme and escape the base.
        // With dot segments rejected, the result is always inside the mounted container.
        StringBuilder sb = new StringBuilder(base.toString());
        if (sb.charAt(sb.length() - 1) != '/') {
            sb.append('/');   // a container URI need not end in '/'
        }
        String[] segments = rel.split("/");
        for (int i = 0; i < segments.length; i++) {
            String segment = segments[i];
            if (segment.isEmpty() || segment.equals(".") || segment.equals("..")) {
                throw new LWSException(LWSException.Kind.INVALID, "Illegal path: " + fusePath);
            }
            if (i > 0) {
                sb.append('/');
            }
            appendEncodedSegment(sb, segment);
        }
        if (container) {
            sb.append('/');
        }
        return URI.create(sb.toString());
    }

    /** Percent-encode one path segment as UTF-8, keeping only RFC 3986 {@code pchar}s literal. */
    private static void appendEncodedSegment(StringBuilder sb, String segment) {
        for (byte b : segment.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            if (isLiteralPathChar(c)) {
                sb.append((char) c);
            } else {
                sb.append('%').append(HEX[c >> 4]).append(HEX[c & 0xF]);
            }
        }
    }

    /** Unreserved, sub-delims, ':' and '@'. A literal '%' is always encoded, so "a%41" stays "a%41". */
    private static boolean isLiteralPathChar(int c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                || "-._~!$&'()*+,;=:@".indexOf(c) >= 0;
    }

    private static boolean isRoot(String path) {
        return path == null || path.isEmpty() || path.equals("/");
    }

    private static String parentOf(String path) {
        String p = path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
        int i = p.lastIndexOf('/');
        return i <= 0 ? "/" : p.substring(0, i);
    }

    private static String nameOf(String path) {
        String p = path.endsWith("/") && path.length() > 1 ? path.substring(0, path.length() - 1) : path;
        String name = p.substring(p.lastIndexOf('/') + 1);
        if (name.isEmpty() || name.equals(".") || name.equals("..")) {
            throw new LWSException(LWSException.Kind.INVALID, "Illegal path: " + path);
        }
        return name;
    }

    private static String childPath(String parent, String name) {
        return parent.equals("/") ? "/" + name : parent + "/" + name;
    }

    // ------------------------------------------------------------------ header helpers

    private static boolean is2xx(int status) {
        return status / 100 == 2;
    }

    private static boolean isMissing(int status) {
        return status == 404 || status == 410;
    }

    private static long lastModified(HttpHeaders headers) {
        Optional<String> value = headers.firstValue("Last-Modified");
        if (value.isPresent()) {
            try {
                return ZonedDateTime.parse(value.get(), DateTimeFormatter.RFC_1123_DATE_TIME).toEpochSecond();
            } catch (RuntimeException ignore) {
                // fall through to 0
            }
        }
        return 0L;
    }

    private static boolean isRdfContentType(String ct) {
        if (ct == null) {
            return false;
        }
        String c = ct.toLowerCase(Locale.ROOT);
        return c.startsWith("text/turtle")
                || c.startsWith("application/ld+json")
                || c.startsWith("application/n-triples")
                || c.startsWith("application/n-quads")
                || c.startsWith("application/trig")
                || c.startsWith("text/n3")
                || c.startsWith("application/rdf+xml");
    }
}
