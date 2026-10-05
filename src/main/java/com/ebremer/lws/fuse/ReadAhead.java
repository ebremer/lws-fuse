package com.ebremer.lws.fuse;

import java.util.Arrays;

/**
 * Read-ahead for one open file handle. The OS reads in small pieces (WinFsp asks for 4 KiB at a
 * time, the Linux kernel for up to 128 KiB), and every piece fetched separately costs a full
 * HTTP round-trip. Each fetch from the server is therefore at least {@link #INITIAL_WINDOW} bytes
 * and is kept, so that following reads inside it are served locally; while access stays
 * sequential the window doubles on every fetch, up to {@link #MAX_WINDOW}. A read elsewhere (a
 * seek) resets the window.
 *
 * <p>The cached block is only used for a file without local changes; once a file is being
 * written its reads come from the {@link OpenFile} buffer instead. Thread-safe (FUSE may issue
 * concurrent reads on one handle; they are served one at a time).
 *
 * @author Erich Bremer
 */
final class ReadAhead {

    static final int INITIAL_WINDOW = 128 * 1024;
    static final int MAX_WINDOW = 4 * 1024 * 1024;

    /** Fetches {@code length} bytes at {@code offset} from the server. */
    @FunctionalInterface
    interface Fetcher {
        LWSClient.ReadResult fetch(long offset, int length);
    }

    private byte[] block;          // the last fetched block, or null
    private long blockStart;
    private boolean blockAtEof;    // the server had nothing beyond the block
    private long nextOffset = 0;   // where a sequential reader will read next
    private int window = INITIAL_WINDOW;

    /** Read up to {@code size} bytes at {@code offset}, from the cached block or a new fetch. */
    synchronized LWSClient.ReadResult read(long offset, int size, Fetcher fetcher) {
        if (block != null && offset >= blockStart) {
            long end = blockStart + block.length;
            if (offset + size <= end || (blockAtEof && offset <= end)) {
                nextOffset = offset + size;
                return new LWSClient.ReadResult(slice(offset, size), false);
            }
        }
        boolean sequential = offset == nextOffset;
        if (sequential && block != null) {
            window = (int) Math.min((long) window * 2, MAX_WINDOW);
        } else if (!sequential) {
            window = INITIAL_WINDOW;
        }
        int want = Math.max(size, window);
        LWSClient.ReadResult r = fetcher.fetch(offset, want);
        nextOffset = offset + size;
        if (r.rangeIgnored()) {
            block = null;   // the caller switches this file to a full download
            return new LWSClient.ReadResult(head(r.data(), size), true);
        }
        block = r.data();
        blockStart = offset;
        blockAtEof = block.length < want;
        return new LWSClient.ReadResult(slice(offset, size), false);
    }

    private byte[] slice(long offset, int size) {
        int from = (int) (offset - blockStart);
        int to = (int) Math.min((long) block.length, (long) from + size);
        return from >= to ? new byte[0] : Arrays.copyOfRange(block, from, to);
    }

    private static byte[] head(byte[] data, int size) {
        return data.length <= size ? data : Arrays.copyOf(data, size);
    }
}
