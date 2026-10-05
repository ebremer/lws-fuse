package com.ebremer.lws.fuse.auth;

import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Supplies credentials for outgoing LWS requests. It is the single seam through which the
 * {@code LWSClient} authenticates: every request is passed through {@link #authorize} just before
 * it is sent, every response is shown to {@link #onResponse}, and a {@code 401} response is
 * offered to {@link #onUnauthorized} so the provider can refresh and the client can retry once.
 *
 * <p>Implementations must be thread-safe (FUSE issues requests concurrently) and should set
 * headers with {@link HttpRequest.Builder#setHeader} rather than {@code header} so that a retry
 * cleanly replaces stale credentials.
 *
 * @author Erich Bremer
 */
public interface AuthProvider {

    /**
     * Add any {@code Authorization}/{@code DPoP} headers for an {@code method} request to
     * {@code uri}. Called for every request; implementations cache and refresh tokens internally.
     *
     * @throws AuthException if no credential can be obtained
     */
    void authorize(HttpRequest.Builder builder, String method, URI uri);

    /**
     * Invoked with every response the server sends (including a {@code 401}, before
     * {@link #onUnauthorized}) — e.g. to pick up a new {@code DPoP-Nonce}. The default does nothing.
     */
    default void onResponse(HttpResponse<?> response) {
    }

    /**
     * Invoked once when a request comes back {@code 401 Unauthorized}. Implementations may use the
     * rejected request ({@link HttpResponse#request()}, including which credential it carried)
     * and the response's challenge headers to decide whether to (re)acquire credentials.
     *
     * @return {@code true} if retrying the request once is worthwhile (the next {@link #authorize}
     *         will supply different credentials); {@code false} (the default) to let the 401 stand
     */
    default boolean onUnauthorized(HttpResponse<?> response) {
        return false;
    }

    /** A no-op provider for public LWS servers. */
    static AuthProvider anonymous() {
        return AnonymousAuthProvider.INSTANCE;
    }

    /** A provider that sends a fixed, externally-obtained OAuth 2.0 bearer token. */
    static AuthProvider bearer(String token) {
        return (builder, method, uri) -> builder.setHeader("Authorization", "Bearer " + token);
    }
}
