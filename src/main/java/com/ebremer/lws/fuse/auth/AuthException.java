package com.ebremer.lws.fuse.auth;

/**
 * No credential could be obtained for a request — the token endpoint refused or could not be
 * reached, or a self-issued credential could not be signed. Thrown by
 * {@link AuthProvider#authorize}; the LWS client reports it as "permission denied" rather than an
 * I/O error.
 *
 * @author Erich Bremer
 */
public class AuthException extends RuntimeException {

    public AuthException(String message, Throwable cause) {
        super(message, cause);
    }
}
