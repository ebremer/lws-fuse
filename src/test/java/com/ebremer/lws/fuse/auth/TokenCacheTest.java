package com.ebremer.lws.fuse.auth;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.Test;

class TokenCacheTest {

    private static final Instant T0 = Instant.parse("2026-01-01T00:00:00Z");
    private static final Duration MIN_AGE = Duration.ofSeconds(10);

    private final AtomicInteger fetches = new AtomicInteger();
    /** Every token expires at T0 + 100 s; the default refresh skew is 30 s. */
    private final TokenCache cache = new TokenCache(
            () -> new TokenCache.Token("t" + fetches.incrementAndGet(), "Bearer", T0.plusSeconds(100)));

    @Test
    void cachesUntilShortlyBeforeExpiry() {
        assertEquals("t1", cache.get(T0).accessToken());
        assertEquals("t1", cache.get(T0.plusSeconds(69)).accessToken());
        assertEquals("t2", cache.get(T0.plusSeconds(71)).accessToken());
    }

    @Test
    void aTokenWithoutExpiryIsKept() {
        TokenCache forever = new TokenCache(
                () -> new TokenCache.Token("t" + fetches.incrementAndGet(), "Bearer", null));
        forever.get(T0);
        assertEquals("t1", forever.get(T0.plus(Duration.ofDays(365))).accessToken());
    }

    @Test
    void rejectingAnOlderTokenKeepsTheCurrentOne() {
        cache.get(T0);
        assertTrue(cache.invalidate("t0", T0.plusSeconds(60), MIN_AGE), "retry with the newer token");
        assertEquals("t1", cache.get(T0.plusSeconds(60)).accessToken());
        assertEquals(1, fetches.get());
    }

    @Test
    void rejectingAYoungTokenIsNotRetried() {
        cache.get(T0);
        assertFalse(cache.invalidate("t1", T0.plusSeconds(5), MIN_AGE));
        assertEquals("t1", cache.get(T0.plusSeconds(5)).accessToken());
        assertEquals(1, fetches.get());
    }

    @Test
    void rejectingAnOlderCurrentTokenForcesARefetch() {
        cache.get(T0);
        assertTrue(cache.invalidate("t1", T0.plusSeconds(11), MIN_AGE));
        assertEquals("t2", cache.get(T0.plusSeconds(11)).accessToken());
    }

    @Test
    void fetchFailuresAreReportedAsAuthFailures() {
        TokenCache failing = new TokenCache(() -> {
            throw new IOException("token endpoint down");
        });
        AuthException e = assertThrows(AuthException.class, () -> failing.get(T0));
        assertInstanceOf(IOException.class, e.getCause());
    }

    @Test
    void anInterruptedFetchKeepsTheInterruptFlag() {
        TokenCache interrupted = new TokenCache(() -> {
            throw new InterruptedException();
        });
        try {
            assertThrows(AuthException.class, () -> interrupted.get(T0));
            assertTrue(Thread.currentThread().isInterrupted());
        } finally {
            Thread.interrupted();   // clear it for the next test
        }
    }
}
