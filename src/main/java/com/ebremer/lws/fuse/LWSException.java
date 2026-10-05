package com.ebremer.lws.fuse;

/**
 * A failure while talking to the LWS server, tagged with a {@link Kind} that the FUSE layer
 * translates into a POSIX errno. Keeping the translation table out of {@link LWSClient} lets
 * the client stay free of any FUSE/jnr dependency.
 *
 * @author Erich Bremer
 */
public class LWSException extends RuntimeException {

    /** Coarse failure categories, each mapped to an errno by the filesystem layer. */
    public enum Kind {
        /** Target does not exist (HTTP 404/410). */
        NOT_FOUND,
        /** Not authorized (HTTP 401/403/405), or no credential could be obtained. */
        FORBIDDEN,
        /** The request conflicts with the server's state (HTTP 409), e.g. a missing parent container. */
        CONFLICT,
        /** A create-only request ({@code If-None-Match: *}) found something already there (HTTP 412). */
        EXISTS,
        /** The resource changed on the server since it was read ({@code If-Match} failed, HTTP 412). */
        CHANGED,
        /** Container is not empty and cannot be deleted (HTTP 409 on DELETE). */
        NOT_EMPTY,
        /** Malformed request or path (HTTP 400/415, encoding errors). */
        INVALID,
        /** The resource is too large for the server (HTTP 413). */
        TOO_LARGE,
        /** The server is out of storage (HTTP 507), or there is no local room to buffer a file. */
        NO_SPACE,
        /** The server is overloaded or rate-limiting (HTTP 429/503) and retries did not help. */
        BUSY,
        /** Operation not supported by this client or server (HTTP 501). */
        UNSUPPORTED,
        /** Network error or unexpected server response. */
        IO
    }

    private final Kind kind;

    public LWSException(Kind kind, String message) {
        super(message);
        this.kind = kind;
    }

    public LWSException(Kind kind, String message, Throwable cause) {
        super(message, cause);
        this.kind = kind;
    }

    public Kind kind() {
        return kind;
    }

    /**
     * Map a non-2xx HTTP status code to an {@code LWSException}. A {@code 412} is reported as
     * {@link Kind#CHANGED}; callers that sent {@code If-None-Match: *} translate it to
     * {@link Kind#EXISTS} themselves.
     */
    static LWSException fromStatus(int status, String what) {
        Kind kind = switch (status) {
            case 401, 403, 405 -> Kind.FORBIDDEN;
            case 404, 410 -> Kind.NOT_FOUND;
            case 409 -> Kind.CONFLICT;
            case 412 -> Kind.CHANGED;
            case 400, 415 -> Kind.INVALID;
            case 413 -> Kind.TOO_LARGE;
            case 507 -> Kind.NO_SPACE;
            case 429, 503 -> Kind.BUSY;
            case 501 -> Kind.UNSUPPORTED;
            default -> Kind.IO;
        };
        return new LWSException(kind, "HTTP " + status + " for " + what);
    }
}
