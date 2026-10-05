package com.ebremer.lws.fuse.auth;

import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * OpenID Connect provider metadata discovery — fetches {@code <issuer>/.well-known/openid-configuration}
 * and extracts the endpoints the LWS OpenID auth suite needs. Pure OIDC/OAuth 2.0; no Solid.
 *
 * <p>As OpenID Connect Discovery §4.3 requires, the document's {@code issuer} must be the issuer
 * it was fetched for; otherwise the metadata (and every endpoint in it) is rejected.
 *
 * @author Erich Bremer
 */
public final class OpenIdDiscovery {

    /**
     * The subset of OpenID Provider metadata this client uses.
     *
     * @param issParameterSupported the provider promises an RFC 9207 {@code iss} parameter in
     *                              authorization responses
     *                              ({@code authorization_response_iss_parameter_supported})
     */
    public record ProviderMetadata(URI issuer, URI tokenEndpoint, URI authorizationEndpoint, URI jwksUri,
                                   boolean issParameterSupported) {}

    private OpenIdDiscovery() {
    }

    /**
     * @throws IOException if the document cannot be fetched or parsed, or names a different issuer
     */
    public static ProviderMetadata discover(HttpClient http, URI issuer, Duration timeout)
            throws IOException, InterruptedException {
        String base = issuer.toString();
        String url = base.endsWith("/")
                ? base + ".well-known/openid-configuration"
                : base + "/.well-known/openid-configuration";
        HttpRequest req = HttpRequest.newBuilder(URI.create(url))
                .timeout(timeout)
                .header("Accept", "application/json")
                .GET()
                .build();
        HttpResponse<byte[]> r = http.send(req, HttpResponse.BodyHandlers.ofByteArray());
        if (r.statusCode() / 100 != 2) {
            throw new IOException("OpenID discovery failed: HTTP " + r.statusCode() + " for " + url);
        }
        ProviderMetadata md;
        try (JsonReader reader = Json.createReader(new ByteArrayInputStream(r.body()))) {
            JsonObject o = reader.readObject();
            md = new ProviderMetadata(
                    requireUri(o, "issuer"),
                    requireUri(o, "token_endpoint"),
                    optionalUri(o, "authorization_endpoint"),
                    optionalUri(o, "jwks_uri"),
                    o.getBoolean("authorization_response_iss_parameter_supported", false));
        } catch (RuntimeException e) {
            throw new IOException("OpenID metadata from " + url + " is malformed: " + e.getMessage(), e);
        }
        if (!sameIssuer(md.issuer().toString(), base)) {
            throw new IOException("OpenID metadata from " + url + " is for issuer " + md.issuer()
                    + ", not the configured " + issuer + "; refusing to use it");
        }
        return md;
    }

    /**
     * Issuer identifiers are compared exactly, except that a single trailing {@code '/'} is
     * ignored (users type the issuer both ways; it names the same path).
     */
    public static boolean sameIssuer(String a, String b) {
        return a != null && b != null && stripSlash(a).equals(stripSlash(b));
    }

    private static String stripSlash(String s) {
        return s.endsWith("/") ? s.substring(0, s.length() - 1) : s;
    }

    private static URI requireUri(JsonObject o, String key) throws IOException {
        if (!o.containsKey(key)) {
            throw new IOException("OpenID metadata missing required '" + key + "'");
        }
        return URI.create(o.getString(key));
    }

    private static URI optionalUri(JsonObject o, String key) {
        return o.containsKey(key) ? URI.create(o.getString(key)) : null;
    }
}
