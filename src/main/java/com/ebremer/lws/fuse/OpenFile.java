package com.ebremer.lws.fuse;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.Arrays;
import java.util.Locale;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.ReentrantLock;

/**
 * An open file that backs FUSE reads and writes: shared by every handle opened on it, and
 * reference-counted by those handles.
 *
 * <p>HTTP has no random-access write, so a resource being modified is buffered in full — in a
 * temporary <em>spool file</em>, not in memory, so its size is bounded by local disk rather than
 * the heap. The server content is downloaded on the first read-modify (not at all when the file
 * is truncated to zero first), mutated in place by {@link #write}/{@link #truncate}, and uploaded
 * with a single {@code PUT} by {@link #flush} (called from FUSE {@code flush}/{@code release}).
 *
 * <p>Uploads protect against lost updates: a file created here is sent with
 * {@code If-None-Match: *}, and a downloaded one with {@code If-Match} on the ETag it was read at,
 * so a concurrent change on the server fails the upload with
 * {@link LWSException.Kind#EXISTS}/{@link LWSException.Kind#CHANGED} instead of being overwritten.
 * The server's media type is kept rather than re-guessed from the name.
 *
 * <p>The file follows its resource: {@link #moveTo} re-targets it after a rename, and
 * {@link #detach} marks it unlinked (or replaced by a rename) so that handles still holding it
 * keep their data but never upload it over whatever now lives at the path. {@link #close} deletes
 * the spool file once the last handle is gone.
 *
 * <p>Locking: buffer state is guarded by the instance monitor, which is never held across network
 * I/O. Downloads are serialized by a load lock and uploads by a flush lock: an upload sends a
 * snapshot of the buffer, so reads, writes and {@code getattr} carry on meanwhile, and a change
 * made during the upload keeps the file dirty. The reference count is atomic so that opening a file
 * never waits behind any of this.
 *
 * @author Erich Bremer
 */
final class OpenFile {

    private static final int ZERO_CHUNK = 64 * 1024;

    private final Path spoolDir;
    private String path;
    private Path spoolFile;              // the buffer, once loaded; its size is always 'length'
    private FileChannel buffer;
    private long length = 0;
    private boolean loaded = false;      // the buffer holds the file's content
    private boolean dirty = false;       // buffer holds unflushed changes
    private boolean detached = false;    // unlinked or replaced: never upload again
    private boolean closed = false;
    private boolean createNew = false;   // created here, never uploaded: upload create-only
    private boolean rangeIgnored = false;
    private String etag;                 // server version the buffer is based on
    private String contentType;          // the server's media type, kept on upload
    private long mtimeSeconds;           // server Last-Modified, or the time of the last local change
    private long generation;             // bumped by every change, so a flush can tell if more arrived
    private final ReentrantLock loadLock = new ReentrantLock();
    private final ReentrantLock flushLock = new ReentrantLock();
    private final AtomicInteger refs = new AtomicInteger();

    /** A file whose buffer, if needed, is spooled under the system temporary directory. */
    OpenFile(String path) {
        this(path, Path.of(System.getProperty("java.io.tmpdir")));
    }

    OpenFile(String path, Path spoolDir) {
        this.path = path;
        this.spoolDir = spoolDir;
    }

    void retain() {
        refs.incrementAndGet();
    }

    /** Release one reference; returns true when the last handle has been closed. */
    boolean release() {
        return refs.decrementAndGet() <= 0;
    }

    int refs() {
        return refs.get();
    }

    /** The path this file currently uploads to. */
    synchronized String path() {
        return path;
    }

    /**
     * Re-target the file after its resource was copied to {@code newPath} (a rename), where the
     * server now stores it with {@code newContentType} (keep the current type when {@code null})
     * under {@code newEtag} (the ETag the copy was given, or {@code null} if unknown).
     */
    synchronized void moveTo(String newPath, String newContentType, String newEtag) {
        path = newPath;
        if (newContentType != null) {
            contentType = newContentType;
        }
        etag = newEtag;
        createNew = false;
    }

    /** The resource was deleted or replaced: keep the data for open handles, but never upload it. */
    synchronized void detach() {
        detached = true;
    }

    synchronized boolean detached() {
        return detached;
    }

    synchronized boolean dirty() {
        return dirty;
    }

    synchronized boolean loaded() {
        return loaded;
    }

    synchronized long length() {
        return length;
    }

    /** Last-modified time to report: the server's, or the time of the latest local change. */
    synchronized long mtimeSeconds() {
        return mtimeSeconds;
    }

    /** The media type an upload will use, or {@code null} if it will be guessed from the name. */
    synchronized String contentType() {
        return contentType;
    }

    /** The server answered a Range request with the whole body: read this file through the buffer. */
    synchronized void markRangeIgnored() {
        rangeIgnored = true;
    }

    synchronized boolean rangeIgnored() {
        return rangeIgnored;
    }

    /** Record what a {@code HEAD} or listing said about the resource before it is loaded. */
    synchronized void seed(ResourceInfo info) {
        if (info == null || loaded) {
            return;
        }
        if (contentType == null) {
            contentType = info.contentType();
        }
        mtimeSeconds = info.mtimeSeconds();
    }

    /** Mark this as a brand-new, empty resource (FUSE {@code create}): loaded and pending upload. */
    synchronized void initNew() {
        resetBuffer();
        createNew = true;
        changed();
    }

    /** Ensure the current server content is present in the buffer, downloading it once if needed. */
    void ensureLoaded(LWSClient client) {
        if (loaded()) {
            return;
        }
        loadLock.lock();
        try {
            String p;
            synchronized (this) {
                if (loaded) {
                    return;
                }
                ensureOpen();
                p = path;
            }
            Path download = newSpoolFile();
            LWSClient.Download d;
            try {
                d = client.download(p, download);
            } catch (RuntimeException e) {
                deleteQuietly(download);
                throw e;
            }
            synchronized (this) {
                if (loaded || closed) {   // truncated to zero meanwhile, or gone
                    deleteQuietly(download);
                    return;
                }
                install(download);
                length = d == null ? 0 : d.length();
                createNew = d == null;    // vanished from the server: recreate, but don't clobber
                if (d != null) {
                    etag = d.etag();
                    if (d.contentType() != null) {
                        contentType = d.contentType();
                    }
                    mtimeSeconds = d.mtimeSeconds();
                }
                loaded = true;
            }
        } finally {
            loadLock.unlock();
        }
    }

    /** Apply a write at {@code offset}; returns the number of bytes written. */
    int write(LWSClient client, byte[] src, long offset) {
        if (offset < 0) {
            throw new LWSException(LWSException.Kind.INVALID, "Negative write offset: " + path());
        }
        ensureLoaded(client);
        synchronized (this) {
            ensureOpen();
            try {
                if (offset > length) {
                    zeroFill(length, offset);   // the gap reads as zeros
                }
                writeFully(ByteBuffer.wrap(src), offset);
                length = Math.max(length, offset + src.length);
            } catch (IOException e) {
                throw spoolFailure(e);
            }
            changed();
            return src.length;
        }
    }

    /** Read up to {@code max} bytes from {@code offset} out of the buffer. */
    byte[] read(LWSClient client, long offset, int max) {
        ensureLoaded(client);
        synchronized (this) {
            ensureOpen();
            if (offset < 0 || offset >= length) {
                return new byte[0];
            }
            int n = (int) Math.min((long) max, length - offset);
            ByteBuffer bb = ByteBuffer.allocate(n);
            try {
                while (bb.hasRemaining()) {
                    if (buffer.read(bb, offset + bb.position()) < 0) {
                        break;
                    }
                }
            } catch (IOException e) {
                throw spoolFailure(e);
            }
            return bb.position() == n ? bb.array() : Arrays.copyOf(bb.array(), bb.position());
        }
    }

    /**
     * Resize the file, padding with zero bytes when growing. Truncating to zero does not need the
     * old content, so it is not downloaded.
     */
    void truncate(LWSClient client, long size) {
        if (size < 0) {
            throw new LWSException(LWSException.Kind.INVALID, "Negative size: " + path());
        }
        if (size == 0) {
            synchronized (this) {
                ensureOpen();
                if (!loaded) {
                    resetBuffer();
                } else {
                    try {
                        buffer.truncate(0);
                    } catch (IOException e) {
                        throw spoolFailure(e);
                    }
                    length = 0;
                }
                changed();
            }
            return;
        }
        ensureLoaded(client);
        synchronized (this) {
            ensureOpen();
            try {
                if (size < length) {
                    buffer.truncate(size);
                } else if (size > length) {
                    zeroFill(length, size);
                }
            } catch (IOException e) {
                throw spoolFailure(e);
            }
            length = size;
            changed();
        }
    }

    /**
     * If dirty (and not detached), upload a snapshot of the buffer with a single PUT. The dirty
     * flag is cleared only if nothing changed while the upload was in flight.
     *
     * @return true if an upload happened, false if there was nothing to flush
     * @throws LWSException on failure, the file stays dirty; {@link LWSException.Kind#EXISTS} or
     *                      {@link LWSException.Kind#CHANGED} if someone else wrote the resource
     */
    boolean flush(LWSClient client) {
        flushLock.lock();
        try {
            Path snapshot;
            long gen;
            String p;
            String type;
            LWSClient.Precondition precondition;
            synchronized (this) {
                if (!dirty || detached || closed) {
                    return false;
                }
                p = path;
                gen = generation;
                type = contentType != null ? contentType : LWSClient.guessContentType(p);
                precondition = createNew ? LWSClient.Precondition.CREATE_ONLY : LWSClient.Precondition.ifMatch(etag);
                snapshot = newSpoolFile();
                try {
                    copyBufferTo(snapshot);
                } catch (IOException e) {
                    deleteQuietly(snapshot);
                    throw spoolFailure(e);
                }
            }
            try {
                LWSClient.Stored stored = client.putResource(p, snapshot, type, precondition);
                synchronized (this) {
                    createNew = false;
                    etag = stored.etag();   // null: the server gave none, so the next upload is unconditional
                    contentType = type;
                    if (!stored.path().equals(p) && path.equals(p)) {
                        path = stored.path();   // a new file the server chose another name for
                    }
                    if (generation == gen) {
                        dirty = false;
                    }
                }
                return true;
            } finally {
                deleteQuietly(snapshot);
            }
        } finally {
            flushLock.unlock();
        }
    }

    /** Copy the current content to {@code target} (e.g. to save changes whose upload failed). */
    synchronized void copyTo(Path target) throws IOException {
        ensureOpen();
        if (!loaded) {
            Files.write(target, new byte[0]);
            return;
        }
        copyBufferTo(target);
    }

    /** Delete the spool file. The file must not be used afterwards. */
    synchronized void close() {
        closed = true;
        loaded = false;
        dropBuffer();
    }

    // ------------------------------------------------------------------ internals

    private void changed() {
        dirty = true;
        generation++;
        mtimeSeconds = System.currentTimeMillis() / 1000L;
    }

    private void ensureOpen() {
        if (closed) {
            throw new LWSException(LWSException.Kind.IO, "File already closed: " + path);
        }
    }

    /** Replace the buffer with an empty, loaded one. */
    private void resetBuffer() {
        install(newSpoolFile());
        length = 0;
        loaded = true;
    }

    private void install(Path file) {
        dropBuffer();
        try {
            buffer = FileChannel.open(file, StandardOpenOption.READ, StandardOpenOption.WRITE);
        } catch (IOException e) {
            deleteQuietly(file);
            throw spoolFailure(e);
        }
        spoolFile = file;
    }

    private void dropBuffer() {
        if (buffer != null) {
            try {
                buffer.close();
            } catch (IOException ignore) {
                // deleting the file below is what matters
            }
            buffer = null;
        }
        if (spoolFile != null) {
            deleteQuietly(spoolFile);
            spoolFile = null;
        }
    }

    private Path newSpoolFile() {
        try {
            Files.createDirectories(spoolDir);
            return Files.createTempFile(spoolDir, "lws-", ".buf");   // owner-only on POSIX
        } catch (IOException e) {
            throw spoolFailure(e);
        }
    }

    private void copyBufferTo(Path target) throws IOException {
        try (FileChannel out = FileChannel.open(target, StandardOpenOption.WRITE,
                StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING)) {
            long pos = 0;
            while (pos < length) {
                long n = buffer.transferTo(pos, length - pos, out);
                if (n <= 0) {
                    throw new IOException("Short copy of the buffer for " + path);
                }
                pos += n;
            }
        }
    }

    private void writeFully(ByteBuffer src, long position) throws IOException {
        while (src.hasRemaining()) {
            position += buffer.write(src, position);
        }
    }

    private void zeroFill(long from, long to) throws IOException {
        ByteBuffer zeros = ByteBuffer.allocate((int) Math.min(ZERO_CHUNK, to - from));
        for (long pos = from; pos < to; ) {
            zeros.clear().limit((int) Math.min(zeros.capacity(), to - pos));
            int n = zeros.remaining();
            writeFully(zeros, pos);
            pos += n;
        }
    }

    /** A local spool failure; "no space left" / "not enough space" becomes {@code NO_SPACE}. */
    private LWSException spoolFailure(IOException e) {
        String detail = String.valueOf(e.getMessage());
        LWSException.Kind kind = detail.toLowerCase(Locale.ROOT).contains("space")
                ? LWSException.Kind.NO_SPACE : LWSException.Kind.IO;
        return new LWSException(kind, "Local buffer for " + path + " failed: " + detail, e);
    }

    private static void deleteQuietly(Path file) {
        try {
            Files.deleteIfExists(file);
        } catch (IOException ignore) {
            // a stray temp file is harmless
        }
    }
}
