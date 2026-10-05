package com.ebremer.lws.fuse.auth;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.gen.ECKeyGenerator;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.FileAlreadyExistsException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.UUID;

/**
 * Loads (or generates and persists) the P-256 EC key that signs self-issued LWS credentials.
 * Persisting the key gives a stable did:key / controlled-identifier identity across runs.
 *
 * <p>The key <em>is</em> the identity: a different key means a different did:key, and a CID whose
 * published key no longer matches. So an existing key file is never overwritten — if it cannot be
 * read or is not a usable private P-256 key, loading fails and the file is left untouched.
 *
 * @author Erich Bremer
 */
public final class Keys {

    private Keys() {
    }

    /**
     * Load the key from {@code file}, or — only if no file exists there — generate a new one and
     * save it, readable only by its owner from the moment it exists (see {@link PrivateFiles}). A
     * {@code null} file means a fresh ephemeral key each call.
     *
     * @throws IllegalStateException if the file exists but does not hold a private P-256 JWK, or
     *                               a new key cannot be saved
     */
    public static ECKey loadOrGenerateP256(Path file) {
        if (file != null && Files.exists(file)) {
            return load(file);
        }
        ECKey key;
        try {
            key = new ECKeyGenerator(Curve.P_256).keyID(UUID.randomUUID().toString()).generate();
        } catch (JOSEException e) {
            throw new IllegalStateException("Cannot generate a P-256 key", e);
        }
        if (file == null) {
            return key;
        }
        try {
            PrivateFiles.createNew(file, key.toJSONString().getBytes(StandardCharsets.UTF_8));
        } catch (FileAlreadyExistsException e) {
            return load(file);   // another process created it first; use theirs
        } catch (IOException e) {
            throw new IllegalStateException("Cannot save the new signing key to " + file, e);
        }
        return key;
    }

    private static ECKey load(Path file) {
        ECKey key;
        try {
            key = ECKey.parse(Files.readString(file));
        } catch (IOException | ParseException e) {
            throw new IllegalStateException("Cannot read the signing key " + file + " (" + e.getMessage()
                    + "). The file was left untouched; repair or move it — a new key is a new identity.", e);
        }
        if (!Curve.P_256.equals(key.getCurve()) || !key.isPrivate()) {
            throw new IllegalStateException("The signing key " + file
                    + " must be a private P-256 EC JWK; the file was left untouched.");
        }
        return key;
    }
}
