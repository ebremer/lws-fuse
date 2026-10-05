package com.ebremer.lws.fuse.auth;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Requests to an OAuth 2.0 token endpoint, shared by the authorization-code exchange and the
 * refresh/client-credentials grants: client authentication ({@code client_secret_basic}, or
 * {@code client_id} in the body for a public client), an optional DPoP proof, and the one retry
 * RFC 9449 §8 prescribes when the server answers {@code use_dpop_nonce} with a fresh nonce.
 *
 * @author Erich Bremer
 */
final class TokenEndpoint {

    private TokenEndpoint() {
    }

    /**
     * POST {@code form} to {@code endpoint} and parse the token response.
     *
     * @throws TokenEndpointException if the endpoint answered with an error status
     */
    static AuthorizationCodeFlow.Tokens request(HttpClient http, URI endpoint, Map<String, String> form,
                                                String clientId, String clientSecret, DPoP dpop, Duration timeout)
            throws IOException, InterruptedException {
        Map<String, String> body = new LinkedHashMap<>(form);
        String basic = null;
        if (clientSecret != null) {
            basic = "Basic " + Base64.getEncoder().encodeToString(
                    (enc(clientId) + ":" + enc(clientSecret)).getBytes(StandardCharsets.UTF_8));
        } else if (clientId != null) {
            body.put("client_id", clientId);
        }
        String encoded = formEncode(body);
        for (int attempt = 1; ; attempt++) {
            HttpRequest.Builder b = HttpRequest.newBuilder(endpoint)
                    .timeout(timeout)
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .header("Accept", "application/json");
            if (basic != null) {
                b.header("Authorization", basic);
            }
            if (dpop != null) {
                // DPoP-bind the token request itself (htu = token endpoint, htm = POST, no ath).
                b.header("DPoP", dpop.proof("POST", endpoint, null));
            }
            HttpResponse<byte[]> r = http.send(b.POST(HttpRequest.BodyPublishers.ofString(encoded)).build(),
                    HttpResponse.BodyHandlers.ofByteArray());
            boolean gotNonce = dpop != null && dpop.rememberNonce(endpoint, r.headers());
            if (r.statusCode() / 100 == 2) {
                return parse(r.body());
            }
            TokenEndpointException error = TokenEndpointException.of(r.statusCode(), r.body());
            if (attempt == 1 && gotNonce && "use_dpop_nonce".equals(error.error())) {
                continue;   // the server wants its nonce in the proof: try once more with it
            }
            throw error;
        }
    }

    private static AuthorizationCodeFlow.Tokens parse(byte[] body) throws IOException {
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(body))) {
            JsonObject o = reader.readObject();
            return new AuthorizationCodeFlow.Tokens(
                    o.getString("access_token"),
                    o.containsKey("refresh_token") ? o.getString("refresh_token") : null,
                    o.containsKey("token_type") ? o.getString("token_type") : "Bearer",
                    o.containsKey("expires_in") ? o.getJsonNumber("expires_in").longValue() : null,
                    o.containsKey("id_token") ? o.getString("id_token") : null);
        } catch (RuntimeException e) {
            throw new IOException("Malformed token response: " + e.getMessage(), e);
        }
    }

    static String formEncode(Map<String, String> form) {
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : form.entrySet()) {
            if (sb.length() > 0) {
                sb.append('&');
            }
            sb.append(enc(e.getKey())).append('=').append(enc(e.getValue()));
        }
        return sb.toString();
    }

    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }
}
