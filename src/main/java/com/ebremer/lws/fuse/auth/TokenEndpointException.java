package com.ebremer.lws.fuse.auth;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;

/**
 * An OAuth 2.0 token endpoint refused a request — carrying the HTTP status and, when the body is a
 * standard error response (RFC 6749 §5.2), its {@code error} code.
 *
 * @author Erich Bremer
 */
public final class TokenEndpointException extends IOException {

    private final int status;
    private final String error;

    TokenEndpointException(int status, String error, String body) {
        super("Token endpoint returned HTTP " + status + ": " + body);
        this.status = status;
        this.error = error;
    }

    /** Build from a non-2xx token endpoint response, extracting the {@code error} code if present. */
    static TokenEndpointException of(int status, byte[] body) {
        String text = new String(body, StandardCharsets.UTF_8);
        String error = null;
        try (JsonReader reader = Json.createReader(new StringReader(text))) {
            JsonObject o = reader.readObject();
            if (o.containsKey("error")) {
                error = o.getString("error");
            }
        } catch (RuntimeException notAnOAuthErrorBody) {
            // leave error null
        }
        return new TokenEndpointException(status, error, text);
    }

    public int status() {
        return status;
    }

    /** The RFC 6749 {@code error} code (e.g. {@code invalid_grant}), or {@code null}. */
    public String error() {
        return error;
    }

    /** The grant (e.g. a refresh token) is invalid, expired, revoked, or was already used. */
    public boolean isInvalidGrant() {
        return "invalid_grant".equals(error);
    }
}
