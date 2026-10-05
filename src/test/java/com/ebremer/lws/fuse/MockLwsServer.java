package com.ebremer.lws.fuse;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * An in-memory LWS server for tests and manual mounts, following the LWS 1.0 core protocol
 * (w3c/lws-protocol, 2026-09):
 * <ul>
 *   <li>a container is listed as {@code application/lws+json} ({@code id}, {@code type},
 *       {@code totalItems}, {@code items} with {@code id}/{@code type}/{@code format}/{@code size}/
 *       {@code modified}), paged with {@code Link: rel="first"/"next"} headers;</li>
 *   <li>resources are created with {@code POST} to a container ({@code Slug} names them,
 *       {@code Link: <lws:Container>; rel="type"} makes a container), answered with {@code 201} and
 *       {@code Location}; {@code PUT} only updates ({@code 404} for a missing resource) and honors
 *       {@code If-Match}; {@code DELETE} refuses non-empty containers unless {@code Depth: infinity};</li>
 *   <li>every {@code GET}/{@code HEAD} carries an {@code ETag} and {@code Link} headers for
 *       {@code type}, {@code up}, {@code linkset} and {@code lws#storage}; {@code /storage} is the
 *       storage description ({@code application/lws+cid});</li>
 *   <li>with {@link #requiredToken} set, requests without that bearer token get {@code 401} with an
 *       LWS challenge ({@code as_uri}, {@code realm}).</li>
 * </ul>
 * Membership is tracked explicitly (parent links), so with {@link #flatIds} the URIs of created
 * resources do not mirror the hierarchy. {@link #legacy} switches to an earlier draft: no
 * {@code POST} (405), {@code PUT} creates, Turtle listings with in-body paging.
 *
 * <p>For a live mount, run it standalone:
 * {@code java -cp target/test-classes com.ebremer.lws.fuse.MockLwsServer [port] [flat] [legacy]}.
 */
public final class MockLwsServer implements AutoCloseable {

    public static final String ROOT = "/alice/";
    private static final String LWS = "https://www.w3.org/ns/lws#";
    private static final String LAST_MODIFIED = "Wed, 01 Jan 2025 00:00:00 GMT";
    private static final String MODIFIED_ISO = "2025-01-01T00:00:00Z";
    private static final Pattern RANGE = Pattern.compile("bytes=(\\d+)-(\\d+)");

    /** A stored resource: a container, or a data resource with its content. */
    private static final class Res {
        final boolean container;
        volatile String parent;   // raw path of the parent container; null for the root
        volatile byte[] data;
        volatile String contentType;
        volatile long version;

        Res(boolean container, String parent, byte[] data, String contentType, long version) {
            this.container = container;
            this.parent = parent;
            this.data = data;
            this.contentType = contentType;
            this.version = version;
        }

        String etag() {
            return "\"v" + version + "\"";
        }
    }

    private final HttpServer server;
    private final ExecutorService executor = Executors.newCachedThreadPool();
    private final Map<String, Res> resources = new ConcurrentHashMap<>();
    private final Map<String, String> listingOverrides = new ConcurrentHashMap<>();
    private final AtomicLong versions = new AtomicLong();
    private final AtomicLong ids = new AtomicLong();
    private final AtomicInteger failuresLeft = new AtomicInteger();
    private volatile int failureStatus;
    private volatile String failureRetryAfter;

    /** Every request received, as {@code "METHOD /raw/path[?query]"}. */
    public final List<String> requests = new CopyOnWriteArrayList<>();
    /** The path of every resource created (by POST, or by PUT in {@link #legacy} mode). */
    public final List<String> created = new CopyOnWriteArrayList<>();

    /** When positive, listings are paged this many members at a time. */
    public volatile int pageSize;
    /** Answer {@code Range} requests with the whole body and {@code 200}. */
    public volatile boolean ignoreRange;
    /** When positive, answer every {@code PUT} and {@code POST} with this status and store nothing. */
    public volatile int putStatus;
    /** Earlier-draft behavior: POST → 405, PUT creates, Turtle listings with lws:contains and in-body paging. */
    public volatile boolean legacy;
    /** Give created resources URIs that do not mirror the hierarchy ({@code /alice/o<n>/<slug>}). */
    public volatile boolean flatIds;
    /** Ignore the Slug: name created resources {@code <slug>-srv}. */
    public volatile boolean renameOnCreate;
    /** List only the required member properties (id, type, format), not size or modified. */
    public volatile boolean minimalListing;
    /** Support recursive DELETE ({@code Depth: infinity}). */
    public volatile boolean recursiveDelete = true;
    /** When set, every request must carry {@code Authorization: Bearer <requiredToken>}. */
    public volatile String requiredToken;
    /** The authorization server named in 401 challenges; without one, the challenge is a bare {@code Bearer}. */
    public volatile URI authorizationServer;
    /** The realm named in 401 challenges; {@link #base()} when null. */
    public volatile URI realm;
    /** A challenge sent before the LWS one in each 401, e.g. naming another authorization server. */
    public volatile String extraChallenge;
    /** Send an {@code ETag} on POST/PUT responses (LWS requires one only on GET/HEAD). */
    public volatile boolean etagOnWrites = true;
    /** Send {@code Content-Length} on HEAD responses (HTTP lets a server omit it). */
    public volatile boolean contentLengthOnHead = true;
    /** Containers (raw paths) that refuse creation with {@code 405}. */
    public final Set<String> refusePostTo = ConcurrentHashMap.newKeySet();
    /** When positive, answer every DELETE with this status and delete nothing. */
    public volatile int deleteStatus;
    /** Put this origin in front of the {@code Location} of created resources (another origin). */
    public volatile String locationOrigin;
    /** The storage description's {@code StorageRoot} endpoint; {@link #base()} when null. */
    public volatile String descriptionRoot;
    /** How many DELETEs asked for recursion ({@code Depth: infinity}). */
    public final AtomicInteger recursiveDeletes = new AtomicInteger();
    /** Print each request to stdout. */
    public volatile boolean verbose;

    public MockLwsServer() throws IOException {
        this(0);
    }

    public MockLwsServer(int port) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", port), 0);
        server.createContext("/", this::handle);
        server.setExecutor(executor);
        resources.put(ROOT, new Res(true, null, null, null, versions.incrementAndGet()));
        server.start();
    }

    /** The URL of the root container, {@code http://127.0.0.1:<port>/alice/}. */
    public URI base() {
        return URI.create(origin() + ROOT);
    }

    /** The storage description, which names {@link #base()} as its {@code StorageRoot}. */
    public URI storageDescription() {
        return URI.create(origin() + "/storage");
    }

    private String origin() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    // ------------------------------------------------------------------ seeding and inspection

    /** Store a text file at {@code rawPath} (hierarchical id), creating missing parent containers. */
    public void putFile(String rawPath, String content) {
        putFile(rawPath, content.getBytes(UTF_8), "text/plain");
    }

    public void putFile(String rawPath, byte[] content, String contentType) {
        String parent = parentOf(rawPath);
        mkdir(parent);
        Res existing = resources.get(rawPath);
        if (existing != null && !existing.container) {
            existing.data = content;
            existing.contentType = contentType;
            existing.version = versions.incrementAndGet();
        } else {
            resources.put(rawPath, new Res(false, parent, content, contentType, versions.incrementAndGet()));
        }
    }

    /** Create a container at {@code rawPath} (and its missing parents). */
    public void mkdir(String rawPath) {
        String p = rawPath.endsWith("/") ? rawPath : rawPath + "/";
        if (p.equals(ROOT) || resources.containsKey(p)) {
            return;
        }
        String parent = parentOf(p);
        mkdir(parent);
        resources.put(p, new Res(true, parent, null, null, versions.incrementAndGet()));
    }

    /** The stored content of a data resource as UTF-8, or {@code null} if there is none. */
    public String content(String rawPath) {
        Res r = resources.get(rawPath);
        return r == null || r.container ? null : new String(r.data, UTF_8);
    }

    public byte[] bytes(String rawPath) {
        Res r = resources.get(rawPath);
        return r == null || r.container ? null : r.data;
    }

    /** The media type a data resource was stored with. */
    public String contentType(String rawPath) {
        Res r = resources.get(rawPath);
        return r == null ? null : r.contentType;
    }

    public boolean exists(String rawPath) {
        return resources.containsKey(rawPath);
    }

    /** The path of the member named {@code name} in container {@code containerPath}, or {@code null}. */
    public String memberNamed(String containerPath, String name) {
        for (String child : children(containerPath)) {
            if (name.equals(nameOf(child))) {
                return child;
            }
        }
        return null;
    }

    /** Serve {@code body} verbatim as the listing of {@code containerPath}, with {@code contentType}. */
    public void overrideListing(String containerPath, String body) {
        listingOverrides.put(containerPath, body);
    }

    /** Answer the next {@code times} requests with {@code status} (and a {@code Retry-After}, if given). */
    public void failNext(int times, int status, String retryAfter) {
        failureStatus = status;
        failureRetryAfter = retryAfter;
        failuresLeft.set(times);
    }

    public long count(String method, String rawPath) {
        String key = method + " " + rawPath;
        return requests.stream().filter(key::equals).count();
    }

    public long count(String method) {
        return requests.stream().filter(r -> r.startsWith(method + " ")).count();
    }

    /** Uploads of {@code rawPath}: PUTs to it, plus the POST that created it (in legacy mode that was a PUT too). */
    public long uploads(String rawPath) {
        return count("PUT", rawPath) + (legacy ? 0 : created.stream().filter(rawPath::equals).count());
    }

    @Override
    public void close() {
        server.stop(0);
        executor.shutdownNow();
    }

    // ------------------------------------------------------------------ request handling

    private void handle(HttpExchange ex) throws IOException {
        try {
            String path = ex.getRequestURI().getRawPath();
            String query = ex.getRequestURI().getRawQuery();
            String line = ex.getRequestMethod() + " " + path + (query != null ? "?" + query : "");
            requests.add(line);
            if (verbose) {
                System.out.println(line);
            }
            byte[] body = ex.getRequestBody().readAllBytes();
            if (failuresLeft.getAndUpdate(n -> Math.max(0, n - 1)) > 0) {
                if (failureRetryAfter != null) {
                    ex.getResponseHeaders().set("Retry-After", failureRetryAfter);
                }
                send(ex, failureStatus, null);
                return;
            }
            String token = requiredToken;
            if (token != null && !("Bearer " + token).equals(ex.getRequestHeaders().getFirst("Authorization"))) {
                URI as = authorizationServer;
                ex.getResponseHeaders().add("Link", "<" + storageDescription() + ">; rel=\"" + LWS + "storage\"");
                String challenge = as == null ? "Bearer"
                        : "Bearer as_uri=\"" + as + "\", realm=\"" + (realm != null ? realm : base()) + "\""
                        + (ex.getRequestHeaders().getFirst("Authorization") != null ? ", error=\"invalid_token\"" : "");
                ex.getResponseHeaders().set("WWW-Authenticate",
                        extraChallenge != null ? extraChallenge + ", " + challenge : challenge);
                send(ex, 401, null);
                return;
            }
            if (path.equals("/storage")) {
                description(ex);
                return;
            }
            switch (ex.getRequestMethod()) {
                case "GET", "HEAD" -> get(ex, path, query);
                case "POST" -> post(ex, path, body);
                case "PUT" -> put(ex, path, body);
                case "DELETE" -> delete(ex, path);
                default -> send(ex, 405, null);
            }
        } finally {
            ex.close();
        }
    }

    private void description(HttpExchange ex) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/lws+cid");
        send(ex, 200, ("{\"@context\":[\"https://www.w3.org/ns/cid/v1\",\"https://www.w3.org/ns/lws/v1\"],"
                + "\"id\":\"" + storageDescription() + "\",\"type\":\"Storage\","
                + "\"service\":[{\"type\":\"StorageRoot\",\"serviceEndpoint\":\""
                + (descriptionRoot != null ? descriptionRoot : base()) + "\"}]}").getBytes(UTF_8));
    }

    private void get(HttpExchange ex, String path, String query) throws IOException {
        Res r = resources.get(path);
        if (r == null) {
            send(ex, 404, null);
            return;
        }
        metadataHeaders(ex, path, r);
        if (r.container) {
            boolean turtle = legacy;
            ex.getResponseHeaders().set("Content-Type", turtle ? "text/turtle" : "application/lws+json");
            ex.getResponseHeaders().set("Vary", "Accept");
            String override = listingOverrides.get(path);
            byte[] listing = (override != null ? override
                    : turtle ? turtleListing(path, query) : jsonListing(ex, path, query)).getBytes(UTF_8);
            send(ex, 200, listing);
            return;
        }
        byte[] data = r.data;
        ex.getResponseHeaders().set("Content-Type", r.contentType);
        String range = ex.getRequestHeaders().getFirst("Range");
        Matcher m = range == null ? null : RANGE.matcher(range);
        if (m != null && m.matches() && !ignoreRange) {
            long from = Long.parseLong(m.group(1));
            long to = Long.parseLong(m.group(2));
            if (from >= data.length) {
                ex.getResponseHeaders().set("Content-Range", "bytes */" + data.length);
                send(ex, 416, null);
                return;
            }
            int end = (int) Math.min(to, data.length - 1L);
            ex.getResponseHeaders().set("Content-Range", "bytes " + from + "-" + end + "/" + data.length);
            send(ex, 206, Arrays.copyOfRange(data, (int) from, end + 1));
            return;
        }
        send(ex, 200, data);
    }

    private void metadataHeaders(HttpExchange ex, String path, Res r) {
        var h = ex.getResponseHeaders();
        h.set("ETag", r.etag());
        h.set("Last-Modified", LAST_MODIFIED);
        h.add("Link", "<" + LWS + (r.container ? "Container" : "DataResource") + ">; rel=\"type\"");
        h.add("Link", "<" + path + ".meta>; rel=\"linkset\"; type=\"application/linkset+json\"");
        h.add("Link", "<" + storageDescription() + ">; rel=\"" + LWS + "storage\"");
        if (r.parent != null) {
            h.add("Link", "<" + r.parent + ">; rel=\"up\"");
        }
    }

    private synchronized void post(HttpExchange ex, String path, byte[] body) throws IOException {
        if (legacy) {
            send(ex, 405, null);
            return;
        }
        if (putStatus > 0) {
            send(ex, putStatus, null);
            return;
        }
        Res parent = resources.get(path);
        if (parent == null) {
            send(ex, 404, null);
            return;
        }
        if (!parent.container || refusePostTo.contains(path)) {
            send(ex, 405, null);
            return;
        }
        String link = ex.getRequestHeaders().getFirst("Link");
        boolean container = link != null && link.contains(LWS + "Container");
        String slug = ex.getRequestHeaders().getFirst("Slug");
        String name = slug == null || slug.isBlank() ? "r" + ids.incrementAndGet()
                : URLDecoder.decode(slug.replace("+", "%2B"), UTF_8);
        if (renameOnCreate) {
            name = name + "-srv";
        }
        String encoded = encodeSegment(name);
        String id = flatIds ? ROOT + "o" + ids.incrementAndGet() + "/" + encoded : path + encoded;
        if (container) {
            id += "/";
        }
        while (resources.containsKey(id) || memberNamed(path, name) != null) {   // keep names unique
            name = name + "-" + ids.incrementAndGet();
            encoded = encodeSegment(name);
            id = (flatIds ? ROOT + "o" + ids.incrementAndGet() + "/" : path) + encoded + (container ? "/" : "");
        }
        String type = ex.getRequestHeaders().getFirst("Content-Type");
        Res r = new Res(container, path, container ? null : body,
                container ? null : (type != null ? type : "application/octet-stream"), versions.incrementAndGet());
        resources.put(id, r);
        created.add(id);
        ex.getResponseHeaders().set("Location", (locationOrigin != null ? locationOrigin : "") + id);
        metadataHeaders(ex, id, r);
        if (!etagOnWrites) {
            ex.getResponseHeaders().remove("ETag");
        }
        send(ex, 201, null);
    }

    private synchronized void put(HttpExchange ex, String path, byte[] body) throws IOException {
        if (putStatus > 0) {
            send(ex, putStatus, null);
            return;
        }
        Res current = resources.get(path);
        String ifNoneMatch = ex.getRequestHeaders().getFirst("If-None-Match");
        String ifMatch = ex.getRequestHeaders().getFirst("If-Match");
        if (("*".equals(ifNoneMatch) && current != null)
                || (ifMatch != null && (current == null || !ifMatch.equals(current.etag())))) {
            send(ex, 412, null);
            return;
        }
        if (current == null) {
            if (!legacy) {
                send(ex, 404, null);   // LWS: PUT updates; create with POST
                return;
            }
            String parent = parentOf(path);
            if (!resources.containsKey(parent) || !resources.get(parent).container) {
                send(ex, 409, null);
                return;
            }
            String link = ex.getRequestHeaders().getFirst("Link");
            boolean container = link != null && link.contains(LWS + "Container");
            String key = container && !path.endsWith("/") ? path + "/" : path;
            if (!container && resources.containsKey(path + "/")) {
                send(ex, 409, null);
                return;
            }
            Res r = new Res(container, parent, container ? null : body,
                    container ? null : contentTypeOf(ex), versions.incrementAndGet());
            resources.put(key, r);
            created.add(key);
            ex.getResponseHeaders().set("ETag", r.etag());
            send(ex, 201, null);
            return;
        }
        if (current.container) {
            send(ex, 409, null);
            return;
        }
        current.data = body;
        current.contentType = contentTypeOf(ex);
        current.version = versions.incrementAndGet();
        if (etagOnWrites) {
            ex.getResponseHeaders().set("ETag", current.etag());
        }
        send(ex, 204, null);
    }

    private static String contentTypeOf(HttpExchange ex) {
        String type = ex.getRequestHeaders().getFirst("Content-Type");
        return type != null ? type : "application/octet-stream";
    }

    private synchronized void delete(HttpExchange ex, String path) throws IOException {
        if ("infinity".equalsIgnoreCase(ex.getRequestHeaders().getFirst("Depth"))) {
            recursiveDeletes.incrementAndGet();
        }
        if (deleteStatus > 0) {
            send(ex, deleteStatus, null);
            return;
        }
        Res r = resources.get(path);
        if (r == null || path.equals(ROOT)) {
            send(ex, r == null ? 404 : 405, null);
            return;
        }
        if (r.container && !children(path).isEmpty()) {
            if (!(recursiveDelete && "infinity".equalsIgnoreCase(ex.getRequestHeaders().getFirst("Depth")))) {
                send(ex, 409, null);
                return;
            }
            removeTree(path);
        }
        resources.remove(path);
        send(ex, 204, null);
    }

    private void removeTree(String container) {
        for (String child : children(container)) {
            if (resources.get(child).container) {
                removeTree(child);
            }
            resources.remove(child);
        }
    }

    // ------------------------------------------------------------------ listings

    private String jsonListing(HttpExchange ex, String path, String query) {
        List<String> members = children(path);
        int from = 0;
        int to = members.size();
        if (pageSize > 0) {
            int page = query != null && query.startsWith("page=") ? Integer.parseInt(query.substring(5)) : 0;
            from = Math.min(page * pageSize, members.size());
            to = Math.min(from + pageSize, members.size());
            ex.getResponseHeaders().add("Link", "<" + path + "?page=0>; rel=\"first\"");
            if (to < members.size()) {
                ex.getResponseHeaders().add("Link", "<" + path + "?page=" + (page + 1) + ">; rel=\"next\"");
            }
        }
        StringBuilder sb = new StringBuilder("{\"@context\":\"https://www.w3.org/ns/lws/v1\",\"id\":\"")
                .append(path).append("\",\"type\":\"Container\",\"totalItems\":").append(members.size())
                .append(",\"items\":[");
        for (int i = from; i < to; i++) {
            String m = members.get(i);
            Res r = resources.get(m);
            sb.append(i > from ? "," : "").append("{\"id\":\"").append(m).append("\",\"type\":\"")
                    .append(r.container ? "Container" : "DataResource").append('"');
            if (!r.container) {
                sb.append(",\"format\":\"").append(r.contentType).append('"');
                if (!minimalListing) {
                    sb.append(",\"size\":").append(r.data.length);
                }
            }
            if (!minimalListing) {
                sb.append(",\"modified\":\"").append(MODIFIED_ISO).append('"');
            }
            sb.append('}');
        }
        return sb.append("]}").toString();
    }

    private String turtleListing(String path, String query) {
        List<String> members = children(path);
        StringBuilder sb = new StringBuilder("@prefix lws: <" + LWS + "> .\n")
                .append("@prefix schema: <http://schema.org/> .\n")
                .append("@prefix dcterms: <http://purl.org/dc/terms/> .\n")
                .append("@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .\n");
        List<String> page = members;
        if (pageSize <= 0) {
            sb.append('<').append(path).append("> a lws:Container .\n");
        } else if (query == null) {
            sb.append('<').append(path).append("> a lws:Container ; lws:first <").append(path).append("?page=0> .\n");
            page = List.of();
        } else {
            int n = Integer.parseInt(query.substring("page=".length()));
            int from = Math.min(n * pageSize, members.size());
            int to = Math.min(from + pageSize, members.size());
            sb.append('<').append(path).append("?page=").append(n).append("> a lws:ContainerPage");
            if (to < members.size()) {
                sb.append(" ; lws:next <").append(path).append("?page=").append(n + 1).append('>');
            }
            sb.append(" .\n");
            page = members.subList(from, to);
        }
        for (String m : page) {
            Res r = resources.get(m);
            sb.append('<').append(path).append("> lws:contains <").append(m).append("> .\n");
            sb.append('<').append(m).append("> a lws:").append(r.container ? "Container" : "DataResource").append(" .\n");
            if (!r.container && !minimalListing) {
                sb.append('<').append(m).append("> schema:size ").append(r.data.length)
                        .append(" ; dcterms:modified \"").append(MODIFIED_ISO).append("\"^^xsd:dateTime")
                        .append(" ; dcterms:format \"").append(r.contentType).append("\" .\n");
            }
        }
        return sb.toString();
    }

    /** Members of a container (by parent link), sorted by path. */
    private List<String> children(String container) {
        List<String> out = new ArrayList<>();
        for (Map.Entry<String, Res> e : resources.entrySet()) {
            if (container.equals(e.getValue().parent)) {
                out.add(e.getKey());
            }
        }
        out.sort(null);
        return out;
    }

    private static String nameOf(String path) {
        String p = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return URLDecoder.decode(p.substring(p.lastIndexOf('/') + 1).replace("+", "%2B"), UTF_8);
    }

    private static String parentOf(String path) {
        String p = path.endsWith("/") ? path.substring(0, path.length() - 1) : path;
        return p.substring(0, p.lastIndexOf('/') + 1);
    }

    private static String encodeSegment(String name) {
        StringBuilder sb = new StringBuilder();
        for (byte b : name.getBytes(UTF_8)) {
            int c = b & 0xFF;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || "-._~!$&'()*+,;=:@".indexOf(c) >= 0) {
                sb.append((char) c);
            } else {
                sb.append('%').append(String.format("%02X", c));
            }
        }
        return sb.toString();
    }

    private void send(HttpExchange ex, int status, byte[] body) throws IOException {
        boolean head = "HEAD".equals(ex.getRequestMethod());
        if (body == null || body.length == 0) {
            ex.sendResponseHeaders(status, -1);
        } else if (head) {
            if (contentLengthOnHead) {
                ex.getResponseHeaders().set("Content-Length", String.valueOf(body.length));
            }
            ex.sendResponseHeaders(status, -1);
        } else {
            ex.sendResponseHeaders(status, body.length);
            ex.getResponseBody().write(body);
        }
    }

    /**
     * Standalone server for manual mounts, seeded with a couple of files:
     * {@code MockLwsServer [port] [flat] [legacy]} ({@code flat}: URIs that do not mirror the
     * hierarchy; {@code legacy}: earlier-draft behavior).
     */
    public static void main(String[] args) throws Exception {
        int port = args.length > 0 ? Integer.parseInt(args[0]) : 8765;
        MockLwsServer s = new MockLwsServer(port);
        List<String> flags = List.of(args).subList(Math.min(1, args.length), args.length);
        s.flatIds = flags.contains("flat");
        s.legacy = flags.contains("legacy");
        s.verbose = true;
        s.putFile(ROOT + "hello.txt", "Hello from the mock LWS server\n");
        s.mkdir(ROOT + "docs/");
        s.putFile(ROOT + "docs/readme.md", "# Readme\n");
        System.out.println("Mock LWS server at " + s.base() + " (Ctrl-C to stop)");
        Thread.currentThread().join();
    }
}
