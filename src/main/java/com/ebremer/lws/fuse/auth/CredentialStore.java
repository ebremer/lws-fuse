package com.ebremer.lws.fuse.auth;

import java.io.IOException;
import java.io.Reader;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Properties;

/**
 * Persists an OAuth 2.0 refresh token (keyed by issuer + client id) so a user logs in once and
 * later mounts reuse the saved token instead of re-authenticating. Stored as a simple properties
 * file, by default at {@code ~/.lws/credentials.properties}, readable only by its owner (see
 * {@link PrivateFiles}).
 *
 * @author Erich Bremer
 */
public final class CredentialStore {

    private final Path file;

    public CredentialStore(Path file) {
        this.file = file;
    }

    public static CredentialStore defaultStore() {
        return new CredentialStore(Path.of(System.getProperty("user.home"), ".lws", "credentials.properties"));
    }

    public Path path() {
        return file;
    }

    public synchronized String loadRefreshToken(String issuer, String clientId) {
        return load().getProperty(refreshKey(issuer, clientId));
    }

    /** Save (or replace) the refresh token, atomically and owner-only from the start (see {@link PrivateFiles}). */
    public synchronized void saveRefreshToken(String issuer, String clientId, String refreshToken) throws IOException {
        Properties p = load();
        p.setProperty(refreshKey(issuer, clientId), refreshToken);
        StringWriter w = new StringWriter();
        p.store(w, "LWS credentials — refresh tokens, keyed by issuer|client");
        PrivateFiles.writeAtomically(file, w.toString().getBytes(StandardCharsets.UTF_8));
    }

    private Properties load() {
        Properties p = new Properties();
        if (Files.isReadable(file)) {
            try (Reader r = Files.newBufferedReader(file)) {
                p.load(r);
            } catch (IOException ignore) {
                // treat an unreadable/corrupt store as empty
            }
        }
        return p;
    }

    private static String refreshKey(String issuer, String clientId) {
        return issuer + "|" + clientId + ".refresh_token";
    }
}
