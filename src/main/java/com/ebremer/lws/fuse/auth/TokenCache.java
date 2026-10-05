package com.ebremer.lws.fuse.auth;

import java.time.Duration;
import java.time.Instant;

/**
 * Caches an access token and refreshes it (via a supplied {@link Fetcher}) shortly before it
 * expires. Thread-safe: concurrent callers serialize on a single in-flight refresh, so the token
 * endpoint is hit once per expiry rather than once per request.
 *
 * @author Erich Bremer
 */
public final class TokenCache {

    /** An access token with its type and absolute expiry ({@code null} expiry = never refreshed). */
    public record Token(String accessToken, String tokenType, Instant expiresAt) {
        boolean isFresh(Instant now, Duration skew) {
            return expiresAt == null || now.plus(skew).isBefore(expiresAt);
        }
    }

    /** Acquires a fresh token from the authorization server (or mints a self-issued one). */
    @FunctionalInterface
    public interface Fetcher {
        Token fetch() throws Exception;
    }

    private final Fetcher fetcher;
    private final Duration skew;   // refresh this long before actual expiry
    private Token current;
    private Instant fetchedAt;     // when 'current' was obtained

    public TokenCache(Fetcher fetcher) {
        this(fetcher, Duration.ofSeconds(30));
    }

    public TokenCache(Fetcher fetcher, Duration skew) {
        this.fetcher = fetcher;
        this.skew = skew;
    }

    /**
     * Return a token that is fresh at {@code now}, fetching or refreshing under lock if needed.
     *
     * @throws AuthException if no token could be obtained (the cause says why); an interrupted
     *                       fetch keeps the thread's interrupt flag set
     */
    public synchronized Token get(Instant now) {
        if (current != null && current.isFresh(now, skew)) {
            return current;
        }
        try {
            current = fetcher.fetch();
            fetchedAt = now;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AuthException("Interrupted while obtaining an access token", e);
        } catch (AuthException e) {
            throw e;
        } catch (Exception e) {
            throw new AuthException("Could not obtain an access token: " + e.getMessage(), e);
        }
        return current;
    }

    /** Fetch a new token now, whatever the cached one's state (e.g. to obtain a fresh ID token alongside). */
    public synchronized Token refresh(Instant now) {
        current = null;
        return get(now);
    }

    /** Use {@code token}, obtained elsewhere (e.g. by a login), as the current token. */
    public synchronized void put(Token token, Instant now) {
        current = token;
        fetchedAt = now;
    }

    /**
     * React to a server rejecting {@code rejectedAccessToken} (a {@code 401}) and say whether
     * retrying the request is worthwhile:
     * <ul>
     *   <li>if a different token is cached, another request already refreshed — retry with it;</li>
     *   <li>if the rejected token is the cached one but younger than {@code minAge}, keep it and
     *       don't retry: refusing a token we just obtained is not an expiry problem (often it is
     *       "authenticated but not permitted"), and refreshing on every such 401 would serialize
     *       all requests behind the token endpoint;</li>
     *   <li>otherwise drop it, so the next {@link #get} fetches a new one, and retry.</li>
     * </ul>
     * Only the rejected token is ever dropped, so a concurrent 401 cannot discard a token that
     * another thread has just fetched.
     */
    public synchronized boolean invalidate(String rejectedAccessToken, Instant now, Duration minAge) {
        if (current == null || !current.accessToken().equals(rejectedAccessToken)) {
            return true;
        }
        if (fetchedAt != null && now.isBefore(fetchedAt.plus(minAge))) {
            return false;
        }
        current = null;
        return true;
    }
}
