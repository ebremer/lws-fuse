package com.ebremer.lws.fuse;

import com.ebremer.lws.fuse.auth.AuthProvider;
import com.ebremer.lws.fuse.auth.AuthorizationCodeFlow;
import com.ebremer.lws.fuse.auth.CredentialSource;
import com.ebremer.lws.fuse.auth.CredentialStore;
import com.ebremer.lws.fuse.auth.DPoP;
import com.ebremer.lws.fuse.auth.DidKey;
import com.ebremer.lws.fuse.auth.InteractiveLogin;
import com.ebremer.lws.fuse.auth.Keys;
import com.ebremer.lws.fuse.auth.LwsAuthProvider;
import com.ebremer.lws.fuse.auth.OpenIdAuthProvider;
import com.ebremer.lws.fuse.auth.PrivateFiles;
import com.ebremer.lws.fuse.auth.SamlAuthProvider;
import com.ebremer.lws.fuse.auth.SelfIssuedJwtAuthProvider;
import com.nimbusds.jose.jwk.ECKey;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.stream.Stream;
import jnr.ffi.Platform;
import jnr.ffi.Pointer;
import jnr.ffi.types.mode_t;
import jnr.ffi.types.off_t;
import jnr.ffi.types.size_t;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import ru.serce.jnrfuse.ErrorCodes;
import ru.serce.jnrfuse.FuseFillDir;
import ru.serce.jnrfuse.FuseStubFS;
import ru.serce.jnrfuse.struct.FileStat;
import ru.serce.jnrfuse.struct.FuseFileInfo;
import ru.serce.jnrfuse.struct.Statvfs;
import ru.serce.jnrfuse.struct.Timespec;
import static jnr.ffi.Platform.OS.WINDOWS;

/**
 * A FUSE filesystem that mounts a <a href="https://w3c.github.io/lws-protocol/">W3C Linked Web
 * Storage (LWS)</a> server as a local drive, mapping filesystem operations onto LWS HTTP
 * requests via {@link LWSClient}:
 *
 * <pre>
 *   directory  &lt;-&gt; lws:Container       file  &lt;-&gt; lws:DataResource
 *   getattr    -&gt; the parent's listing (HEAD only where it omits a file's size)
 *   readdir    -&gt; GET container (application/lws+json), its items (paged)
 *   read       -&gt; GET (Range)       write    -&gt; buffer, then PUT on flush/release
 *   create     -&gt; POST to the parent (Slug), on first close
 *   mkdir      -&gt; POST to the parent (Slug, Link: lws:Container)
 *   unlink     -&gt; DELETE resource   rmdir    -&gt; DELETE container
 *   rename     -&gt; GET + POST/PUT + DELETE (a directory: copied entry by entry, then deleted)
 * </pre>
 *
 * <p>Because HTTP offers no random-access write, a resource opened for writing is buffered in
 * full by an {@link OpenFile} (spooled to a temporary file) and uploaded once ({@code PUT}, or
 * {@code POST} for a new file) when its last handle closes — conditionally, so a concurrent change
 * on the server is not overwritten. If that final upload fails, the buffer stays registered for a
 * retry and a copy is saved to a local recovery directory, so the changes are never silently
 * dropped; buffers still pending at unmount are uploaded then. Reads of unchanged files stream
 * with {@code Range} requests through a per-handle {@link ReadAhead}.
 *
 * <p>A short-lived attribute cache absorbs the burst of {@code getattr} calls the OS issues around
 * every operation; a directory listing seeds it with the sizes and dates the listing states, and
 * answers lookups of names it does not contain without asking the server. The implementation is
 * pure LWS/HTTP and contains no Solid-specific code.
 *
 * <p>Run it directly:
 * <pre>
 *   java com.ebremer.lws.fuse.LWSFileSystem &lt;lws-base-url&gt; [mount-point]
 *   # or: -Dlws.base=... -Dlws.mount=... -Dlws.tokenFile=...   (token also via env LWS_TOKEN)
 * </pre>
 *
 * @author Erich Bremer
 */
public class LWSFileSystem extends FuseStubFS {

    private static final Logger log = LoggerFactory.getLogger(LWSFileSystem.class);
    private static final long ATTR_TTL_MS = 1500L;
    /** How long a listing answers "no such name" without asking the server. */
    private static final long LISTING_TTL_MS = 3000L;
    /** A truncate-to-zero without an open handle waits this long for the write that usually follows. */
    private static final long DEFERRED_TRUNCATE_MS = 2000L;
    /** Above this many entries the caches are swept of expired ones (at most once a second). */
    private static final int CACHE_SWEEP_THRESHOLD = 4096;
    /** A directory rename copies at most this many entries; a larger one is refused with EXDEV. */
    static final int MAX_DIRECTORY_RENAME_ENTRIES = 1000;
    private static final DateTimeFormatter RECOVERY_STAMP =
            DateTimeFormatter.ofPattern("yyyyMMdd-HHmmss-SSS").withZone(ZoneId.systemDefault());

    private final LWSClient client;
    private final Path recoveryDir;
    private final Path spoolDir;
    private final long mountedAt = System.currentTimeMillis() / 1000L;
    /** FUSE handle id ({@code fi.fh}) → the handle; its file follows renames and unlinks. */
    private final Map<Long, Handle> handles = new ConcurrentHashMap<>();
    private final AtomicLong nextHandle = new AtomicLong(1);
    /** Path → the file currently open there, so new opens share it and getattr/read see its edits. */
    private final Map<String, OpenFile> openFiles = new ConcurrentHashMap<>();
    private final Map<String, CachedAttr> attrCache = new ConcurrentHashMap<>();
    /** Directory path → the names its last listing contained. */
    private final Map<String, CachedListing> listings = new ConcurrentHashMap<>();
    private final AtomicLong lastSweep = new AtomicLong();
    private final ScheduledExecutorService scheduler;
    private final AtomicBoolean shutDown = new AtomicBoolean();
    /** See {@link #DEFERRED_TRUNCATE_MS}; adjustable for tests. */
    volatile long deferredTruncateMs = DEFERRED_TRUNCATE_MS;

    private record CachedAttr(ResourceInfo info, long expiresAt) {}

    private record CachedListing(Set<String> names, long expiresAt) {}

    /** One open FUSE handle: the shared file, plus this handle's own read-ahead. */
    private static final class Handle {
        final OpenFile file;
        final ReadAhead readAhead = new ReadAhead();
        /** This handle wrote or truncated, so closing it should upload. */
        volatile boolean changed;

        Handle(OpenFile file) {
            this.file = file;
        }
    }

    /** Saves changes whose final upload failed under {@code ~/.lws/recovery}. */
    public LWSFileSystem(LWSClient client) {
        this(client, Path.of(System.getProperty("user.home"), ".lws", "recovery"));
    }

    /**
     * @param recoveryDir where to save a file's changes when its upload on close fails, so they
     *                    survive the process
     */
    public LWSFileSystem(LWSClient client, Path recoveryDir) {
        this.client = client;
        this.recoveryDir = recoveryDir;
        try {
            this.spoolDir = Files.createTempDirectory("lws-fuse-");   // owner-only on POSIX
        } catch (IOException e) {
            throw new UncheckedIOException("Cannot create a directory for file buffers", e);
        }
        this.scheduler = Executors.newSingleThreadScheduledExecutor(r -> {
            Thread t = new Thread(r, "lws-deferred-upload");
            t.setDaemon(true);
            return t;
        });
    }

    /** Where open files are buffered (for tests). */
    Path spoolDir() {
        return spoolDir;
    }

    /** How many attribute entries are cached (for tests). */
    int cachedAttributes() {
        return attrCache.size();
    }

    // ------------------------------------------------------------------ metadata

    @Override
    public int getattr(String path, FileStat stat) {
        try {
            ResourceInfo info = attributes(path);
            if (info == null) {
                return -ErrorCodes.ENOENT();
            }
            if (info.directory()) {
                stat.st_mode.set(FileStat.S_IFDIR | 0755);
                stat.st_nlink.set(2);
            } else {
                stat.st_mode.set(FileStat.S_IFREG | 0644);
                stat.st_nlink.set(1);
                stat.st_size.set(info.size());
            }
            // An unknown modification time is shown as the mount time rather than 1970.
            long t = info.mtimeSeconds() > 0 ? info.mtimeSeconds() : mountedAt;
            stat.st_mtim.tv_sec.set(t);
            stat.st_atim.tv_sec.set(t);
            stat.st_ctim.tv_sec.set(t);
            stat.st_uid.set(getContext().uid.get());
            stat.st_gid.set(getContext().gid.get());
            return 0;
        } catch (LWSException e) {
            return fail("getattr", path, e);
        } catch (RuntimeException e) {
            log.error("getattr {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    @Override
    public int readdir(String path, Pointer buf, FuseFillDir filter, @off_t long offset, FuseFileInfo fi) {
        try {
            List<String> names = listDirectory(path);
            filter.apply(buf, ".", null, 0);
            filter.apply(buf, "..", null, 0);
            for (String name : names) {
                filter.apply(buf, name, null, 0);
            }
            return 0;
        } catch (LWSException e) {
            return fail("readdir", path, e);
        } catch (RuntimeException e) {
            log.error("readdir {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    /**
     * The names in a directory: the server's listing plus files created here that are not
     * uploaded yet. Seeds the attribute cache with what the listing says about each member and
     * remembers the names, so lookups of anything else can be answered locally for a while.
     */
    List<String> listDirectory(String path) {
        List<LWSClient.Member> members = client.list(path);
        long now = System.currentTimeMillis();
        List<String> names = new ArrayList<>(members.size());
        Set<String> seen = new HashSet<>();
        for (LWSClient.Member m : members) {
            names.add(m.name());
            seen.add(m.name());
            String child = childPath(path, m.name());
            // Seed what the listing states, so the OS's follow-up getattr needs no HEAD.
            if (m.directory()) {
                cache(child, new ResourceInfo(true, 0, m.mtimeSeconds()), now);
            } else if (m.size() >= 0) {
                cache(child, new ResourceInfo(false, m.size(), m.mtimeSeconds(), m.contentType()), now);
            }
        }
        String prefix = path.endsWith("/") ? path : path + "/";
        for (OpenFile f : openFiles.values()) {
            String p = f.path();
            if (p.startsWith(prefix) && p.indexOf('/', prefix.length()) < 0 && !f.detached()) {
                String name = p.substring(prefix.length());
                if (!name.isEmpty() && seen.add(name)) {
                    names.add(name);   // created here, not uploaded yet
                }
            }
        }
        listings.put(path, new CachedListing(Set.copyOf(seen), now + LISTING_TTL_MS));
        return names;
    }

    // ------------------------------------------------------------------ reading

    @Override
    public int read(String path, Pointer buf, @size_t long size, @off_t long offset, FuseFileInfo fi) {
        try {
            int max = (int) Math.min(size, Integer.MAX_VALUE);
            Handle h = handleOf(fi);
            OpenFile f = h != null ? h.file : openFiles.get(path);
            byte[] data;
            if (f != null && (f.dirty() || f.loaded() || f.rangeIgnored())) {
                data = f.read(client, offset, max);          // the buffer: local edits, or a whole download
            } else {
                String target = f != null ? f.path() : path;
                LWSClient.ReadResult r = h != null
                        ? h.readAhead.read(offset, max, (o, n) -> client.readRange(target, o, n))
                        : client.readRange(target, offset, max);
                if (r.rangeIgnored() && f != null) {
                    // The server sends the whole file for every Range request; download it once
                    // into the buffer instead of again for each read.
                    log.debug("{}: server ignores Range; buffering the whole file", target);
                    f.markRangeIgnored();
                }
                data = r.data();
            }
            if (data.length > 0) {
                buf.put(0, data, 0, data.length);
            }
            return data.length;
        } catch (LWSException e) {
            return fail("read", path, e);
        } catch (RuntimeException e) {
            log.error("read {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    // ------------------------------------------------------------------ writing

    @Override
    public int create(String path, @mode_t long mode, FuseFileInfo fi) {
        try {
            attach(path, fi).initNew();
            invalidate(path);
            return 0;
        } catch (LWSException e) {
            return fail("create", path, e);
        } catch (RuntimeException e) {
            log.error("create {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    @Override
    public int open(String path, FuseFileInfo fi) {
        attach(path, fi);
        return 0;
    }

    @Override
    public int write(String path, Pointer buf, @size_t long size, @off_t long offset, FuseFileInfo fi) {
        try {
            OpenFile f = fileFor(path, fi);
            if (f == null) {
                return -ErrorCodes.EBADF();   // no open handle: nothing to write into
            }
            markChanged(fi);
            int len = (int) Math.min(size, Integer.MAX_VALUE);
            byte[] src = new byte[len];
            buf.get(0, src, 0, len);
            int written = f.write(client, src, offset);
            invalidate(path);
            return written;
        } catch (LWSException e) {
            return fail("write", path, e);
        } catch (RuntimeException e) {
            log.error("write {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    /**
     * Truncate by path. If the file is open, its buffer is resized. Otherwise a truncation to
     * zero — the first step of many saves — is held back briefly as a pending empty file, so the
     * write that normally follows replaces the content in one upload (and a failed save never
     * leaves an empty file on the server); if nothing follows, it is uploaded on its own.
     */
    @Override
    public int truncate(String path, @off_t long size) {
        try {
            OpenFile f = openFiles.get(path);
            if (f != null) {
                f.truncate(client, size);
            } else if (size == 0) {
                deferTruncateToZero(path);
            } else {
                OpenFile once = new OpenFile(path, spoolDir);
                try {
                    seed(once, path);
                    once.truncate(client, size);   // downloads, resizes, uploads conditionally
                    once.flush(client);
                } finally {
                    once.close();
                }
            }
            invalidate(path);
            return 0;
        } catch (LWSException e) {
            return fail("truncate", path, e);
        } catch (RuntimeException e) {
            log.error("truncate {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    @Override
    public int ftruncate(String path, @off_t long size, FuseFileInfo fi) {
        try {
            OpenFile f = fileFor(path, fi);
            if (f == null) {
                return truncate(path, size);
            }
            markChanged(fi);
            f.truncate(client, size);
            invalidate(path);
            return 0;
        } catch (LWSException e) {
            return fail("ftruncate", path, e);
        } catch (RuntimeException e) {
            log.error("ftruncate {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    /**
     * Called on every close of a handle. Uploads pending changes if this handle made any; closing
     * a handle that only read (or that was opened just to delete the file) uploads nothing — the
     * last handle's release still uploads whatever is pending.
     */
    @Override
    public int flush(String path, FuseFileInfo fi) {
        Handle h = handleOf(fi);
        if (h != null && !h.changed) {
            return 0;
        }
        return doFlush(path, fi);
    }

    @Override
    public int fsync(String path, int isdatasync, FuseFileInfo fi) {
        return doFlush(path, fi);
    }

    @Override
    public int release(String path, FuseFileInfo fi) {
        Handle h = fi != null ? handles.remove(fi.fh.get()) : null;
        if (h == null || !h.file.release()) {
            return 0;   // unknown handle, or other handles still share this file
        }
        return finish(h.file);
    }

    /** Upload a file nobody holds any more, then drop it; on failure keep or rescue its changes. */
    private int finish(OpenFile f) {
        try {
            if (upload(f)) {
                invalidate(f.path());
            }
            if (f.detached() || forget(f)) {
                f.close();
            }
            return 0;
        } catch (LWSException e) {
            if (e.kind() == LWSException.Kind.CHANGED || e.kind() == LWSException.Kind.EXISTS) {
                resolveConflict(f, e);
            } else {
                preserveUnsaved(f, e);
            }
            return errno(e);
        } catch (RuntimeException e) {
            preserveUnsaved(f, e);
            return -ErrorCodes.EIO();
        }
    }

    // ------------------------------------------------------------------ namespace

    @Override
    public int mkdir(String path, @mode_t long mode) {
        try {
            if (attributes(path) != null) {
                return -ErrorCodes.EEXIST();
            }
            client.putContainer(path);   // POST to the parent with Link: <lws:Container>; rel="type"
            invalidate(path);
            return 0;
        } catch (LWSException e) {
            return fail("mkdir", path, e);
        } catch (RuntimeException e) {
            log.error("mkdir {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    @Override
    public int unlink(String path) {
        try {
            OpenFile f = openFiles.get(path);
            try {
                client.delete(path, false);
            } catch (LWSException e) {
                if (e.kind() != LWSException.Kind.NOT_FOUND || f == null) {
                    throw e;
                }
                // created but not yet uploaded: it exists only here
            }
            if (f != null) {
                openFiles.remove(path, f);
                f.detach();   // handles still open keep their data, but must not re-upload it
                if (f.refs() <= 0) {
                    f.close();
                }
            }
            invalidate(path);
            return 0;
        } catch (LWSException e) {
            return fail("unlink", path, e);
        } catch (RuntimeException e) {
            log.error("unlink {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    @Override
    public int rmdir(String path) {
        try {
            client.delete(path, true);
            invalidate(path);
            return 0;
        } catch (LWSException e) {
            return fail("rmdir", path, e);
        } catch (RuntimeException e) {
            log.error("rmdir {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    @Override
    public int rename(String oldpath, String newpath) {
        try {
            ResourceInfo info = attributes(oldpath);
            if (info == null) {
                return -ErrorCodes.ENOENT();
            }
            if (oldpath.equals(newpath)) {
                return 0;
            }
            if (info.directory()) {
                return renameDirectory(oldpath, newpath);
            }
            ResourceInfo target = attributes(newpath);
            if (target != null && target.directory()) {
                return -ErrorCodes.EISDIR();
            }
            OpenFile moving = openFiles.get(oldpath);
            if (moving != null) {
                upload(moving);   // upload pending edits under the old name first
            }
            Copy copy = copyFile(oldpath, newpath);
            if (copy == null) {
                return -ErrorCodes.ENOENT();
            }
            client.delete(oldpath, false);
            if (!copy.path().equals(newpath)) {
                log.warn("Renamed {}, but the server stored it as {}", oldpath, copy.path());
            }
            // Handles open on a file that this rename replaces keep that (now unlinked) file and
            // must not upload it over the renamed content later.
            OpenFile replaced = openFiles.remove(newpath);
            if (replaced != null && replaced != moving) {
                replaced.detach();
                if (replaced.refs() <= 0) {
                    replaced.close();
                }
            }
            // Handles open on the renamed file follow it to the new name.
            if (moving != null) {
                openFiles.remove(oldpath, moving);
                moving.moveTo(copy.path(), copy.contentType(), copy.etag());
                openFiles.put(copy.path(), moving);
            }
            invalidate(oldpath);
            invalidate(newpath);
            return 0;
        } catch (LWSException e) {
            return fail("rename " + oldpath + " ->", newpath, e);
        } catch (RuntimeException e) {
            log.error("rename {} -> {}", oldpath, newpath, e);
            return -ErrorCodes.EIO();
        }
    }

    /** What a file copy left on the server: where, with which media type, and its new ETag. */
    private record Copy(String path, String contentType, String etag) {}

    /**
     * Copy one file on the server through a local temporary file (LWS has no copy or move
     * primitive), or return {@code null} if the source does not exist. The media type is kept,
     * unless it was evidently derived from the old extension and the new name implies another.
     */
    private Copy copyFile(String from, String to) {
        Path tmp = tempFile();
        try {
            LWSClient.Download d = client.download(from, tmp);
            if (d == null) {
                return null;
            }
            String type = renamedContentType(from, to, d.contentType());
            LWSClient.Stored stored = client.putResource(to, tmp, type, LWSClient.Precondition.NONE);
            return new Copy(stored.path(), type, stored.etag());
        } finally {
            deleteQuietly(tmp);
        }
    }

    static String renamedContentType(String from, String to, String serverType) {
        String guessedNew = LWSClient.guessContentType(to);
        if (serverType == null) {
            return guessedNew;
        }
        String mediaType = serverType.split(";", 2)[0].trim();
        boolean derivedFromName = mediaType.equalsIgnoreCase(LWSClient.guessContentType(from));
        return derivedFromName ? guessedNew : serverType;
    }

    /**
     * Rename a directory by copying its tree to the new name and then deleting the original.
     * LWS has no move, and a plain {@code EXDEV} (let the caller copy) works for {@code mv} but
     * makes Explorer and most Windows programs fail outright. Guarded: a tree of more than
     * {@link #MAX_DIRECTORY_RENAME_ENTRIES} entries is refused with {@code EXDEV}; the original
     * is only deleted once everything was copied, so a failure part-way leaves it intact (plus a
     * partial copy at the new name, which is reported).
     */
    private int renameDirectory(String oldpath, String newpath) {
        if (newpath.startsWith(oldpath + "/")) {
            return -ErrorCodes.EINVAL();   // into its own subtree
        }
        ResourceInfo target = attributes(newpath);
        if (target != null) {
            if (!target.directory()) {
                return -ErrorCodes.ENOTDIR();
            }
            if (!client.list(newpath).isEmpty()) {
                return -ErrorCodes.ENOTEMPTY();
            }
        }
        List<LWSClient.Member> tree = new ArrayList<>();   // relative names, parents before children
        if (!walk(oldpath, "", tree)) {
            log.info("Not renaming {}: more than {} entries; reporting a cross-device rename instead",
                    oldpath, MAX_DIRECTORY_RENAME_ENTRIES);
            return -ErrorCodes.EXDEV();
        }
        String oldPrefix = oldpath + "/";
        for (OpenFile f : List.copyOf(openFiles.values())) {
            if (f.path().startsWith(oldPrefix)) {
                upload(f);   // copy the latest content
            }
        }
        Map<String, Copy> copies = new HashMap<>();
        int copied = 0;
        try {
            if (target == null) {
                client.putContainer(newpath);
            }
            for (LWSClient.Member m : tree) {
                String to = newpath + "/" + m.name();
                if (m.directory()) {
                    client.putContainer(to);
                } else {
                    Copy c = copyFile(oldpath + "/" + m.name(), to);
                    if (c != null) {
                        copies.put(m.name(), c);
                    }
                }
                copied++;
            }
        } catch (LWSException e) {
            log.warn("Renaming {} to {} failed after copying {} of {} entries; the original is intact "
                    + "and the partial copy at {} was left in place", oldpath, newpath, copied, tree.size(), newpath);
            clearCaches();
            throw e;
        }
        // Delete the original entry by entry, bottom-up, not with one recursive DELETE: a listing
        // shows only what this client may access, so a recursive delete could remove members that
        // were never seen, and so never copied. Those make a container's DELETE fail instead.
        List<LWSClient.Member> bottomUp = new ArrayList<>(tree);
        Collections.reverse(bottomUp);
        try {
            for (LWSClient.Member m : bottomUp) {
                client.delete(oldpath + "/" + m.name(), m.directory());
            }
            client.delete(oldpath, true);
        } catch (LWSException e) {
            log.warn("Copied {} to {}, but could not delete all of the original ({}); what remains is still at {}",
                    oldpath, newpath, e.getMessage(), oldpath);
            clearCaches();
            throw e;
        }
        // Open files inside follow the directory to its new name.
        for (Map.Entry<String, OpenFile> e : List.copyOf(openFiles.entrySet())) {
            String p = e.getKey();
            if (p.startsWith(oldPrefix)) {
                String rel = p.substring(oldPrefix.length());
                OpenFile f = e.getValue();
                if (openFiles.remove(p, f)) {
                    Copy c = copies.get(rel);
                    f.moveTo(newpath + "/" + rel, c != null ? c.contentType() : null, c != null ? c.etag() : null);
                    openFiles.put(newpath + "/" + rel, f);
                }
            }
        }
        clearCaches();
        return 0;
    }

    /**
     * Collect the entries under {@code dir} into {@code out} (names relative to the renamed
     * directory), parents before children. Returns false once the limit is exceeded.
     */
    private boolean walk(String dir, String rel, List<LWSClient.Member> out) {
        for (LWSClient.Member m : client.list(rel.isEmpty() ? dir : dir + "/" + rel)) {
            String name = rel.isEmpty() ? m.name() : rel + "/" + m.name();
            out.add(new LWSClient.Member(name, m.directory()));
            if (out.size() > MAX_DIRECTORY_RENAME_ENTRIES) {
                return false;
            }
            if (m.directory() && !walk(dir, name, out)) {
                return false;
            }
        }
        return true;
    }

    // ------------------------------------------------------------------ no-op metadata ops

    /** Report a large virtual volume so tools permit writes (WinFsp derives free space here). */
    @Override
    public int statfs(String path, Statvfs stbuf) {
        long blocks = 1L << 40;
        long files = 1L << 30;
        stbuf.f_bsize.set(4096);
        stbuf.f_frsize.set(4096);
        stbuf.f_blocks.set(blocks);
        stbuf.f_bfree.set(blocks);
        stbuf.f_bavail.set(blocks);
        stbuf.f_files.set(files);
        stbuf.f_ffree.set(files);
        stbuf.f_favail.set(files);
        stbuf.f_namemax.set(255);
        return 0;
    }

    @Override
    public int access(String path, int mask) {
        return 0;
    }

    @Override
    public int chmod(String path, @mode_t long mode) {
        return 0;   // permissions are not modeled by LWS; accept silently
    }

    @Override
    public int chown(String path, long uid, long gid) {
        return 0;   // ownership is not modeled by LWS; accept silently
    }

    @Override
    public int utimens(String path, Timespec[] timespec) {
        return 0;   // timestamps are server-managed; accept silently so cp -p / editors work
    }

    // ------------------------------------------------------------------ unmount

    /** Called by FUSE when the filesystem is unmounted. */
    @Override
    public void destroy(Pointer initResult) {
        shutdown();
    }

    /**
     * Upload every change still buffered — open files, failed uploads awaiting a retry, pending
     * truncations — then delete the local buffers. Runs at unmount (and from the shutdown hook on
     * Ctrl-C); later calls do nothing. A file that still cannot be uploaded is saved to the
     * recovery directory and reported.
     */
    public void shutdown() {
        if (!shutDown.compareAndSet(false, true)) {
            return;
        }
        scheduler.shutdownNow();
        Set<OpenFile> files = Collections.newSetFromMap(new IdentityHashMap<>());
        files.addAll(openFiles.values());
        for (Handle h : handles.values()) {
            files.add(h.file);
        }
        int unsaved = 0;
        for (OpenFile f : files) {
            try {
                upload(f);
            } catch (LWSException e) {
                unsaved++;
                if (e.kind() == LWSException.Kind.CHANGED || e.kind() == LWSException.Kind.EXISTS) {
                    resolveConflict(f, e);
                } else {
                    preserveUnsaved(f, e);
                }
            } catch (RuntimeException e) {
                unsaved++;
                preserveUnsaved(f, e);
            }
        }
        for (OpenFile f : files) {
            f.close();
        }
        deleteTree(spoolDir);
        if (unsaved > 0) {
            log.error("{} file(s) could not be uploaded before unmount; their changes are in {}", unsaved, recoveryDir);
        }
    }

    // ------------------------------------------------------------------ helpers

    private int doFlush(String path, FuseFileInfo fi) {
        try {
            OpenFile f = fileFor(path, fi);
            if (f != null && upload(f)) {
                invalidate(f.path());
            }
            return 0;
        } catch (LWSException e) {
            return fail("flush", path, e);
        } catch (RuntimeException e) {
            log.error("flush {}", path, e);
            return -ErrorCodes.EIO();
        }
    }

    /**
     * Upload a file's pending changes. If the server stored a newly created file under a name
     * other than the one asked for (LWS lets it), the file is re-registered under that name.
     *
     * @return true if an upload happened
     */
    private boolean upload(OpenFile f) {
        String before = f.path();
        boolean uploaded = f.flush(client);
        String after = f.path();
        if (!after.equals(before)) {
            if (openFiles.remove(before, f)) {
                openFiles.putIfAbsent(after, f);
            }
            invalidate(before);
            invalidate(after);
        }
        return uploaded;
    }

    /**
     * Resolve attributes for a path, consulting (in order) an open buffered file, the short-lived
     * attribute cache, the parent's recent listing (a name it lacks does not exist), then the
     * server. Returns {@code null} when nothing exists at the path.
     */
    ResourceInfo attributes(String path) {
        OpenFile f = openFiles.get(path);
        if (f != null && (f.dirty() || f.loaded())) {
            return new ResourceInfo(false, f.length(), f.mtimeSeconds(), f.contentType());
        }
        long now = System.currentTimeMillis();
        CachedAttr cached = attrCache.get(path);
        if (cached != null && cached.expiresAt > now) {
            return cached.info;
        }
        if (!path.equals("/")) {
            CachedListing parent = listings.get(parentOf(path));
            if (parent != null && parent.expiresAt > now && !parent.names.contains(nameOf(path))) {
                return null;   // e.g. Explorer's desktop.ini probes, editors' swap files
            }
        }
        ResourceInfo info = client.stat(path);
        cache(path, info, now);
        return info;
    }

    private void cache(String path, ResourceInfo info, long now) {
        attrCache.put(path, new CachedAttr(info, now + ATTR_TTL_MS));
        if (attrCache.size() + listings.size() > CACHE_SWEEP_THRESHOLD) {
            long last = lastSweep.get();
            if (now - last > 1000 && lastSweep.compareAndSet(last, now)) {
                attrCache.values().removeIf(c -> c.expiresAt <= now);
                listings.values().removeIf(l -> l.expiresAt <= now);
            }
        }
    }

    /** Forget cached facts about {@code path}: its attributes, its listing, and its parent's listing. */
    private void invalidate(String path) {
        attrCache.remove(path);
        listings.remove(path);
        listings.remove(parentOf(path));
    }

    private void clearCaches() {
        attrCache.clear();
        listings.clear();
    }

    private void seed(OpenFile f, String path) {
        CachedAttr cached = attrCache.get(path);
        if (cached != null && cached.info != null) {
            f.seed(cached.info);
        }
    }

    /**
     * Open a new handle on {@code path}: share the file already open there (or start one), count
     * the reference, and record the handle in {@code fi.fh}. The reference is taken inside the map
     * update, so it cannot interleave with {@link #forget} dropping the same file.
     */
    private OpenFile attach(String path, FuseFileInfo fi) {
        OpenFile f = openFiles.compute(path, (p, cur) -> {
            OpenFile g = cur;
            if (g == null) {
                g = new OpenFile(p, spoolDir);
                seed(g, p);
            }
            g.retain();
            return g;
        });
        long id = nextHandle.getAndIncrement();
        handles.put(id, new Handle(f));
        fi.fh.set(id);
        return f;
    }

    private Handle handleOf(FuseFileInfo fi) {
        return fi != null ? handles.get(fi.fh.get()) : null;
    }

    private void markChanged(FuseFileInfo fi) {
        Handle h = handleOf(fi);
        if (h != null) {
            h.changed = true;
        }
    }

    /** The file behind a FUSE handle, falling back to the file open at {@code path}. */
    private OpenFile fileFor(String path, FuseFileInfo fi) {
        Handle h = handleOf(fi);
        return h != null ? h.file : openFiles.get(path);
    }

    /**
     * After the last handle closed cleanly: unregister the file unless a new open has picked it
     * up. Returns true if the file is no longer needed (and may be closed).
     */
    private boolean forget(OpenFile f) {
        String path = f.path();
        AtomicBoolean drop = new AtomicBoolean(true);
        openFiles.computeIfPresent(path, (p, cur) -> {
            if (cur != f) {
                return cur;   // a different file lives at this path now
            }
            if (f.refs() > 0) {
                drop.set(false);   // re-opened meanwhile
                return cur;
            }
            return null;
        });
        invalidate(path);
        return drop.get();
    }

    /** Register an empty pending file at {@code path} and upload it unless a handle takes it over. */
    private void deferTruncateToZero(String path) {
        OpenFile f = openFiles.compute(path, (p, cur) -> {
            OpenFile g = cur != null ? cur : new OpenFile(p, spoolDir);
            if (cur == null) {
                seed(g, p);
            }
            return g;
        });
        f.truncate(client, 0);
        scheduler.schedule(() -> {
            if (f.refs() <= 0) {
                finish(f);   // nothing opened it in time: upload the empty file now
            }
        }, deferredTruncateMs, TimeUnit.MILLISECONDS);
    }

    /**
     * The last handle on {@code f} closed but its upload failed. The release errno never
     * reaches the application, so instead of dropping the changes: leave the dirty buffer
     * registered (a later open/flush/release of the path retries the PUT, and reads keep seeing
     * the edited content) and write a recovery copy to disk in case the mount goes away first.
     */
    private void preserveUnsaved(OpenFile f, Exception cause) {
        String path = f.path();
        try {
            Path copy = writeRecoveryCopy(f);
            log.error("Upload of {} failed; changes kept for retry and saved to {}", path, copy, cause);
        } catch (IOException | RuntimeException e) {
            log.error("Upload of {} failed; changes kept in memory only (recovery copy failed: {})",
                    path, e.toString(), cause);
        }
    }

    /**
     * The upload was refused because the resource changed (or appeared) on the server after it
     * was read here. Retrying would overwrite someone else's work, so the local version is saved
     * to the recovery directory and dropped from the mount, which then shows the server's version.
     * If the copy cannot be saved, the changes are kept for a retry instead.
     */
    private void resolveConflict(OpenFile f, LWSException conflict) {
        String path = f.path();
        Path copy;
        try {
            copy = writeRecoveryCopy(f);
        } catch (IOException | RuntimeException e) {
            preserveUnsaved(f, conflict);
            return;
        }
        log.error("{} was changed on the server while it was open here, so this version was not uploaded "
                + "(it would have overwritten the other change); it is saved at {}", path, copy);
        f.detach();
        openFiles.remove(path, f);
        invalidate(path);
        if (f.refs() <= 0) {
            f.close();
        }
    }

    /** Save a file's buffer under the recovery directory, readable only by its owner. */
    private Path writeRecoveryCopy(OpenFile f) throws IOException {
        String flat = f.path().replaceFirst("^/+", "").replaceAll("[/\\\\:*?\"<>|]", "_");
        if (flat.length() > 150) {
            flat = flat.substring(flat.length() - 150);   // keep the tail: file name and extension
        }
        Path file = recoveryDir.resolve(RECOVERY_STAMP.format(Instant.now()) + "-" + flat);
        PrivateFiles.createNew(file, new byte[0]);
        f.copyTo(file);
        return file;
    }

    private Path tempFile() {
        try {
            return Files.createTempFile(spoolDir, "lws-", ".copy");
        } catch (IOException e) {
            throw new LWSException(LWSException.Kind.IO, "Cannot create a temporary file in " + spoolDir, e);
        }
    }

    private static void deleteQuietly(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException ignore) {
            // a stray temp file is harmless
        }
    }

    private static void deleteTree(Path dir) {
        try (Stream<Path> paths = Files.walk(dir)) {
            paths.sorted(Comparator.reverseOrder()).forEach(LWSFileSystem::deleteQuietly);
        } catch (IOException | UncheckedIOException ignore) {
            // temp files left behind are cleaned up by the OS
        }
    }

    private static String childPath(String parent, String name) {
        return parent.equals("/") ? "/" + name : parent + "/" + name;
    }

    private static String parentOf(String path) {
        int i = path.lastIndexOf('/');
        return i <= 0 ? "/" : path.substring(0, i);
    }

    private static String nameOf(String path) {
        return path.substring(path.lastIndexOf('/') + 1);
    }

    /** Translate a failure into an errno, logging the ones a user would want to know about. */
    private static int fail(String op, String path, LWSException e) {
        switch (e.kind()) {
            case NOT_FOUND, FORBIDDEN, NOT_EMPTY, INVALID, EXISTS -> log.debug("{} {}: {}", op, path, e.getMessage());
            default -> log.warn("{} {}: {}", op, path, e.getMessage());
        }
        return errno(e);
    }

    static int errno(LWSException e) {
        return -switch (e.kind()) {
            case NOT_FOUND -> ErrorCodes.ENOENT();
            case FORBIDDEN -> ErrorCodes.EACCES();
            case EXISTS -> ErrorCodes.EEXIST();
            case CHANGED -> ErrorCodes.ESTALE();
            case NOT_EMPTY -> ErrorCodes.ENOTEMPTY();
            case INVALID -> ErrorCodes.EINVAL();
            case TOO_LARGE -> ErrorCodes.EFBIG();
            case NO_SPACE -> ErrorCodes.ENOSPC();
            case BUSY -> ErrorCodes.EAGAIN();
            case UNSUPPORTED -> ErrorCodes.ENOSYS();
            case CONFLICT, IO -> ErrorCodes.EIO();
        };
    }

    // ------------------------------------------------------------------ entry point

    public static void main(String[] args) {
        // jffi (under jnr-fuse) otherwise uses sun.misc.Unsafe memory access, which JDK 24+ warns
        // about and a future JDK will remove; its JNI implementation needs no such access. This
        // must be set before jnr-fuse first touches native memory.
        if (System.getProperty("jffi.unsafe.disabled") == null) {
            System.setProperty("jffi.unsafe.disabled", "true");
        }
        String base = System.getProperty("lws.base", args.length > 0 ? args[0] : null);
        if (base == null) {
            printUsage();
            return;
        }
        String mount = System.getProperty("lws.mount", args.length > 1 ? args[1] : defaultMount());
        Path mountPoint = Paths.get(mount);
        if (!isWindows()) {
            // libfuse needs an existing, empty directory (WinFsp, by contrast, creates its own).
            try {
                if (Files.notExists(mountPoint)) {
                    Files.createDirectories(mountPoint);
                    log.info("Created mount point {}", mountPoint);
                } else if (!Files.isDirectory(mountPoint)) {
                    System.err.println("Mount point " + mountPoint + " exists but is not a directory");
                    System.exit(2);
                }
            } catch (IOException e) {
                System.err.println("Cannot create mount point " + mountPoint + ": " + e.getMessage());
                System.exit(2);
            }
        }

        AuthProvider auth = buildAuthProvider(base);
        LWSClient client = new LWSClient(storageRoot(URI.create(base), auth), auth);
        LWSFileSystem fs = new LWSFileSystem(client);
        // Ctrl-C: upload pending changes even if FUSE does not call destroy() on the way out.
        Runtime.getRuntime().addShutdownHook(new Thread(fs::shutdown, "lws-unmount-flush"));
        log.info("Mounting LWS {} at {}", client.base(), mount);
        try {
            fs.mount(mountPoint, true, false);
        } finally {
            fs.umount();
        }
    }

    /**
     * The container to mount for {@code url}: the storage root, if {@code url} serves a storage
     * description; otherwise {@code url}. If the check fails, {@code url} is mounted as given,
     * unless it is a storage description without a usable storage root.
     */
    private static URI storageRoot(URI url, AuthProvider auth) {
        try {
            return new LWSClient(url, auth).storageRoot(url);
        } catch (LWSException e) {
            if (e.kind() == LWSException.Kind.INVALID) {
                throw e;
            }
            log.warn("Could not check whether {} is a storage description ({}); mounting it as a container",
                    url, e.getMessage());
            return url;
        }
    }

    /**
     * Build the credential provider from {@code -Dlws.*} properties. Every authentication suite is
     * wrapped in an {@link LwsAuthProvider}, which exchanges its credential for an access token at
     * the authorization server a storage names, and presents the credential directly to servers of
     * earlier drafts that name none:
     * <ul>
     *   <li>{@code -Dlws.auth=did-key|cid|saml}: a self-issued JWT or a SAML assertion;</li>
     *   <li>OpenID (browser login, refresh token, or client credentials) when an issuer/token
     *       endpoint and client id are supplied — the ID token is the credential;</li>
     *   <li>else a fixed, pre-obtained access token ({@code -Dlws.tokenFile} / env {@code LWS_TOKEN} /
     *       {@code -Dlws.token}), else anonymous.</li>
     * </ul>
     */
    private static AuthProvider buildAuthProvider(String base) {
        AuthProvider ssi = buildSsiOrSamlProvider(base);
        if (ssi != null) {
            return lws((CredentialSource) ssi, ssi);
        }

        String issuer = System.getProperty("lws.issuer");
        String tokenEndpoint = System.getProperty("lws.tokenEndpoint");
        String clientId = System.getProperty("lws.clientId");
        String clientSecret = secret("lws.clientSecret", "LWS_CLIENT_SECRET");
        String scope = System.getProperty("lws.scope");

        // Flow 2: interactive browser login (RFC 8252 loopback + PKCE), reusing a saved refresh token.
        if (Boolean.parseBoolean(System.getProperty("lws.login", "false"))) {
            if (issuer == null || clientId == null) {
                throw new IllegalArgumentException(
                        "Interactive login (-Dlws.login=true) requires -Dlws.issuer and -Dlws.clientId");
            }
            OpenIdAuthProvider login = interactiveLogin(issuer, tokenEndpoint, clientId, clientSecret, scope);
            return lws(login, login);
        }

        // Flow 1 (OpenID, non-interactive): client-credentials, or refresh-token from properties.
        if ((issuer != null || tokenEndpoint != null) && clientId != null) {
            OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
            if (issuer != null) {
                cfg.issuer = URI.create(issuer);
            }
            if (tokenEndpoint != null) {
                cfg.tokenEndpoint = URI.create(tokenEndpoint);
            }
            cfg.clientId = clientId;
            cfg.clientSecret = clientSecret;
            cfg.scope = scope;
            if ("refresh_token".equalsIgnoreCase(System.getProperty("lws.grant"))) {
                cfg.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
                cfg.refreshToken = secret("lws.refreshToken", "LWS_REFRESH_TOKEN");
                AtomicBoolean warned = new AtomicBoolean();
                cfg.refreshTokenListener = rotated -> {
                    if (warned.compareAndSet(false, true)) {
                        log.warn("The server rotated the refresh token, so the one passed in is now "
                                + "spent; use -Dlws.login=true to have rotations saved automatically");
                    }
                };
            }
            if (Boolean.parseBoolean(System.getProperty("lws.dpop", "false"))) {
                cfg.dpop = new DPoP();   // nothing is persisted, so an ephemeral key will do
            }
            log.info("Authenticating to LWS via OpenID ({}) as client {}",
                    issuer != null ? issuer : tokenEndpoint, clientId);
            OpenIdAuthProvider openId = new OpenIdAuthProvider(HttpClient.newHttpClient(), cfg, Duration.ofSeconds(30));
            return lws(openId, openId);
        }

        // Flow 1 (token): a fixed bearer token, else anonymous.
        String token = secret("lws.token", "LWS_TOKEN");
        if (token != null && !token.isBlank()) {
            return AuthProvider.bearer(token);
        }
        return AuthProvider.anonymous();
    }

    /** LWS authorization around a credential source, optionally pinned with {@code -Dlws.authServer}. */
    private static AuthProvider lws(CredentialSource source, AuthProvider direct) {
        String pinned = System.getProperty("lws.authServer");
        return new LwsAuthProvider(HttpClient.newHttpClient(), source, direct, Duration.ofSeconds(30),
                pinned == null || pinned.isBlank() ? null : URI.create(pinned));
    }

    /**
     * A secret option, looked up in order: the file named by {@code -D<property>File}, the
     * {@code -D<property>} value itself (with a warning: the command line is visible to other
     * local users), then the environment variable {@code env}. Returns {@code null} if none is set.
     */
    static String secret(String property, String env) {
        String file = System.getProperty(property + "File");
        if (file != null && !file.isBlank()) {
            try {
                return Files.readString(Path.of(file)).strip();
            } catch (IOException e) {
                throw new IllegalArgumentException("Cannot read -D" + property + "File=" + file + ": " + e.getMessage(), e);
            }
        }
        String value = System.getProperty(property);
        if (value != null) {
            log.warn("-D{} is visible to other local users in the process list; prefer -D{}File=<file> "
                    + "or the {} environment variable", property, property, env);
            return value;
        }
        String fromEnv = System.getenv(env);
        return fromEnv != null && !fromEnv.isBlank() ? fromEnv : null;
    }

    /**
     * Interactive login (see {@link InteractiveLogin}): reuse the saved refresh token — re-running
     * the browser login if the server rejects it — or log in through the browser and save the
     * token. Rotated refresh tokens are saved as they arrive. With DPoP, the tokens are bound to a
     * key kept at {@code ~/.lws/dpop.jwk}, since the saved refresh token only works with that key.
     */
    private static OpenIdAuthProvider interactiveLogin(String issuer, String tokenEndpoint,
                                                       String clientId, String clientSecret, String scope) {
        OpenIdAuthProvider.Config cfg = new OpenIdAuthProvider.Config();
        cfg.issuer = URI.create(issuer);
        if (tokenEndpoint != null) {
            cfg.tokenEndpoint = URI.create(tokenEndpoint);
        }
        cfg.clientId = clientId;
        cfg.clientSecret = clientSecret;
        cfg.scope = scope;
        if (Boolean.parseBoolean(System.getProperty("lws.dpop", "false"))) {
            cfg.dpop = new DPoP(Keys.loadOrGenerateP256(lwsFile("dpop.jwk")));
        }
        boolean force = Boolean.parseBoolean(System.getProperty("lws.forceLogin", "false"));
        HttpClient http = HttpClient.newHttpClient();
        Duration timeout = Duration.ofSeconds(30);
        try {
            return new InteractiveLogin(http, CredentialStore.defaultStore(),
                    new AuthorizationCodeFlow(http, timeout), timeout).authenticate(cfg, force);
        } catch (IOException e) {
            throw new IllegalStateException("Interactive login failed: " + e.getMessage(), e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interactive login interrupted", e);
        }
    }

    /**
     * Build a self-issued-credential provider for the SSI controlled-identifier suite (with an
     * HTTPS or a did:key subject) or the SAML suite when {@code -Dlws.auth} selects one; returns
     * {@code null} otherwise. Exchanged at an authorization server, a self-issued JWT names that
     * server as its audience; presented directly (earlier drafts) it names the LWS base, or
     * {@code -Dlws.audience}.
     */
    private static AuthProvider buildSsiOrSamlProvider(String base) {
        String mode = System.getProperty("lws.auth");
        if (mode == null || mode.isBlank()) {
            return null;
        }
        Duration ttl = Duration.ofMinutes(5);
        String audience = System.getProperty("lws.audience", base);
        switch (mode.toLowerCase(Locale.ROOT)) {
            case "did-key", "didkey", "did:key" -> {
                ECKey key = Keys.loadOrGenerateP256(keyFile("did-key"));
                // On stdout, not just the log: the user has to copy this into the server's ACLs.
                System.out.println("Authenticating as " + DidKey.fromP256(key)
                        + " (controlled-identifier suite, did:key subject)");
                return SelfIssuedJwtAuthProvider.didKey(key, audience, ttl);
            }
            case "cid", "ssi-cid", "controlled-identifier" -> {
                String cid = System.getProperty("lws.cid");
                if (cid == null || cid.isBlank()) {
                    throw new IllegalArgumentException(
                            "-Dlws.auth=cid requires -Dlws.cid=<controlled-identifier URI>");
                }
                ECKey key = Keys.loadOrGenerateP256(keyFile("cid"));
                String kid = System.getProperty("lws.kid", cid + "#key-0");
                log.info("Authenticating with controlled identifier {} (SSI-CID suite)", cid);
                return SelfIssuedJwtAuthProvider.controlledIdentifier(cid, key, kid, audience, ttl);
            }
            case "saml" -> {
                String path = System.getProperty("lws.samlAssertion");
                if (path == null || path.isBlank()) {
                    throw new IllegalArgumentException(
                            "-Dlws.auth=saml requires -Dlws.samlAssertion=<assertion file>");
                }
                try {
                    log.info("Authenticating with SAML assertion from {}", path);
                    return new SamlAuthProvider(Files.readAllBytes(Path.of(path)));
                } catch (IOException e) {
                    throw new IllegalStateException("Cannot read SAML assertion: " + path, e);
                }
            }
            default -> throw new IllegalArgumentException(
                    "Unknown -Dlws.auth mode: " + mode + " (expected did-key | cid | saml)");
        }
    }

    /** The JWK file backing a self-issued identity: {@code -Dlws.keyFile} or {@code ~/.lws/<name>.jwk}. */
    private static Path keyFile(String name) {
        String custom = System.getProperty("lws.keyFile");
        return custom != null ? Path.of(custom) : lwsFile(name + ".jwk");
    }

    private static Path lwsFile(String name) {
        return Path.of(System.getProperty("user.home"), ".lws", name);
    }

    private static void printUsage() {
        System.err.println("Usage: LWSFileSystem <lws-base-url> [mount-point]");
        System.err.println("  -Dlws.base=URL          LWS container base URL");
        System.err.println("  -Dlws.mount=PATH        mount point (default: " + defaultMount() + ")");
        System.err.println("  Authentication (optional; pick one):");
        System.err.println("    Bearer token:         -Dlws.tokenFile=FILE  (or env LWS_TOKEN)");
        System.err.println("    Client credentials:   -Dlws.issuer=URL -Dlws.clientId=ID -Dlws.clientSecretFile=FILE");
        System.err.println("                          (or env LWS_CLIENT_SECRET)");
        System.err.println("    Browser login:        -Dlws.login=true -Dlws.issuer=URL -Dlws.clientId=ID");
        System.err.println("                          [-Dlws.clientSecretFile=FILE] [-Dlws.forceLogin=true]");
        System.err.println("    Common OpenID opts:   [-Dlws.tokenEndpoint=URL] [-Dlws.scope=...]");
        System.err.println("                          [-Dlws.grant=client_credentials|refresh_token]");
        System.err.println("                          [-Dlws.refreshTokenFile=FILE (or env LWS_REFRESH_TOKEN)]");
        System.err.println("                          [-Dlws.dpop=true]");
        System.err.println("    SSI did:key:          -Dlws.auth=did-key  [-Dlws.keyFile=PATH]");
        System.err.println("    SSI controlled id:    -Dlws.auth=cid -Dlws.cid=URI  [-Dlws.keyFile=PATH] [-Dlws.kid=ID]");
        System.err.println("    SAML assertion:       -Dlws.auth=saml -Dlws.samlAssertion=FILE");
        System.err.println("    Authorization server: [-Dlws.authServer=URI]  only exchange credentials there");
        System.err.println("  Self-issued JWTs presented directly to an earlier-draft server name the base");
        System.err.println("  URL as their audience; override with -Dlws.audience=URI.");
        System.err.println("  Secrets can also be given inline (-Dlws.token, -Dlws.clientSecret,");
        System.err.println("  -Dlws.refreshToken), but other local users can read the command line.");
    }

    private static boolean isWindows() {
        return Platform.getNativePlatform().getOS() == WINDOWS;
    }

    private static String defaultMount() {
        return isWindows() ? "L:\\" : "/tmp/lws";
    }
}
