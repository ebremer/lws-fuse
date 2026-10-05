package com.ebremer.lws.fuse;

/**
 * Immutable metadata about a single LWS resource or container — what a FUSE {@code getattr}
 * needs to fill a {@code FileStat}, plus the media type to keep when the file is rewritten.
 *
 * @param directory     true for an {@code lws:Container} (directory), false for a data resource (file)
 * @param size          resource size in bytes (0 for containers)
 * @param mtimeSeconds  last-modified time as seconds since the Unix epoch (0 if unknown)
 * @param contentType   the server's media type for a data resource, or {@code null} if unknown
 *
 * @author Erich Bremer
 */
public record ResourceInfo(boolean directory, long size, long mtimeSeconds, String contentType) {

    public ResourceInfo(boolean directory, long size, long mtimeSeconds) {
        this(directory, size, mtimeSeconds, null);
    }
}
