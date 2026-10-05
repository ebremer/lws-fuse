package com.ebremer.lws.fuse.auth;

import java.net.URI;
import java.net.http.HttpRequest;

/**
 * The default {@link AuthProvider}: adds no credentials, for public (unauthenticated) LWS servers.
 *
 * @author Erich Bremer
 */
public final class AnonymousAuthProvider implements AuthProvider {

    static final AnonymousAuthProvider INSTANCE = new AnonymousAuthProvider();

    private AnonymousAuthProvider() {
    }

    @Override
    public void authorize(HttpRequest.Builder builder, String method, URI uri) {
        // no credentials
    }
}
