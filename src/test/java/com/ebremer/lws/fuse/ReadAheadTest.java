package com.ebremer.lws.fuse;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

class ReadAheadTest {

    private static final int FILE_SIZE = 3 * 1024 * 1024;
    private final byte[] file = new byte[FILE_SIZE];
    /** Every server fetch, as {offset, length}. */
    private final List<long[]> fetches = new ArrayList<>();

    ReadAheadTest() {
        for (int i = 0; i < file.length; i++) {
            file[i] = (byte) (i * 31);
        }
    }

    private LWSClient.ReadResult serve(long offset, int length) {
        fetches.add(new long[] {offset, length});
        int from = (int) Math.min(offset, file.length);
        int to = (int) Math.min((long) file.length, offset + length);
        return new LWSClient.ReadResult(Arrays.copyOfRange(file, from, to), false);
    }

    @Test
    void sequentialSmallReadsNeedFewFetchesWithAGrowingWindow() {
        ReadAhead ra = new ReadAhead();
        byte[] all = new byte[FILE_SIZE];
        for (int off = 0; off < FILE_SIZE; off += 4096) {
            byte[] chunk = ra.read(off, 4096, this::serve).data();
            System.arraycopy(chunk, 0, all, off, chunk.length);
        }
        assertArrayEquals(file, all);
        // 128K, 256K, 512K, 1M, then 4M covers the rest: far from 768 single-page fetches.
        assertTrue(fetches.size() <= 6, "fetches: " + fetches.size());
        assertEquals(ReadAhead.INITIAL_WINDOW, fetches.get(0)[1]);
        assertEquals(2L * ReadAhead.INITIAL_WINDOW, fetches.get(1)[1]);
    }

    @Test
    void theWindowIsCapped() {
        ReadAhead ra = new ReadAhead();
        for (int off = 0; off < FILE_SIZE; off += 4096) {
            ra.read(off, 4096, this::serve);
        }
        assertTrue(fetches.stream().allMatch(f -> f[1] <= ReadAhead.MAX_WINDOW));
    }

    @Test
    void aSeekResetsTheWindow() {
        ReadAhead ra = new ReadAhead();
        ra.read(0, 4096, this::serve);
        ra.read(ReadAhead.INITIAL_WINDOW, 4096, this::serve);   // sequential miss: window doubles
        ra.read(2_000_000, 4096, this::serve);                   // seek

        assertEquals(ReadAhead.INITIAL_WINDOW, fetches.get(2)[1]);
        assertArrayEquals(Arrays.copyOfRange(file, 2_000_000, 2_004_096), ra.read(2_000_000, 4096, this::serve).data());
        assertEquals(3, fetches.size(), "served from the block just fetched");
    }

    @Test
    void readsAtTheEndOfAShortFileNeedNoMoreFetches() {
        ReadAhead ra = new ReadAhead();
        byte[] small = Arrays.copyOf(file, 10_000);
        ReadAhead.Fetcher f = (o, n) -> {
            fetches.add(new long[] {o, n});
            int from = (int) Math.min(o, small.length);
            return new LWSClient.ReadResult(Arrays.copyOfRange(small, from, (int) Math.min(small.length, o + n)), false);
        };
        assertEquals(4096, ra.read(0, 4096, f).data().length);
        assertEquals(10_000 - 8192, ra.read(8192, 4096, f).data().length);
        assertEquals(0, ra.read(10_000, 4096, f).data().length);
        assertEquals(1, fetches.size());
    }

    @Test
    void anIgnoredRangeIsPassedOnAndNotCached() {
        ReadAhead ra = new ReadAhead();
        LWSClient.ReadResult r = ra.read(0, 4, (o, n) -> new LWSClient.ReadResult(new byte[] {1, 2, 3, 4, 5, 6}, true));
        assertTrue(r.rangeIgnored());
        assertArrayEquals(new byte[] {1, 2, 3, 4}, r.data());
    }
}
