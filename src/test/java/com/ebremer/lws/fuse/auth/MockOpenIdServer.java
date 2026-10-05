package com.ebremer.lws.fuse.auth;

import static java.nio.charset.StandardCharsets.UTF_8;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Function;

/**
 * An in-JVM OpenID provider for tests: a discovery document and a token endpoint whose answers
 * come from {@link #tokenHandler}. The authorization endpoint is never served — tests stand in for
 * the user's browser via {@link AuthorizationCodeFlow#browserOpener}.
 */
final class MockOpenIdServer implements AutoCloseable {

    /** A token endpoint answer, with any extra response headers. */
    record Reply(int status, String json, Map<String, String> headers) {
        Reply(int status, String json) {
            this(status, json, Map.of());
        }

        static Reply ok(String json) {
            return new Reply(200, json);
        }

        static Reply error(int status, String error) {
            return new Reply(status, "{\"error\":\"" + error + "\"}");
        }

        Reply withHeader(String name, String value) {
            Map<String, String> h = new LinkedHashMap<>(headers);
            h.put(name, value);
            return new Reply(status, json, h);
        }
    }

    /** A token endpoint request: its form parameters and {@code Authorization} and {@code DPoP} headers. */
    record TokenRequest(Map<String, String> form, String authorization, String dpop) {}

    private final HttpServer server;
    final List<TokenRequest> tokenRequests = new CopyOnWriteArrayList<>();
    volatile Function<TokenRequest, Reply> tokenHandler = request -> Reply.error(400, "unsupported_grant_type");
    /** The {@code issuer} the discovery document claims; defaults to the server's own URL. */
    volatile String advertisedIssuer;
    /** The advertised authorization endpoint; defaults to {@code <issuer>/authorize}. */
    volatile String authorizationEndpoint;
    /** Advertise {@code authorization_response_iss_parameter_supported} (RFC 9207). */
    volatile boolean issParameterSupported;
    /** The {@code issuer} its LWS authorization server metadata claims; defaults to the server's own URL. */
    volatile String lwsIssuer;
    /** Its {@code subject_token_types_supported} (JSON array text). */
    volatile String subjectTokenTypes =
            "[\"urn:ietf:params:oauth:token-type:jwt\",\"urn:ietf:params:oauth:token-type:id_token\"]";

    MockOpenIdServer() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/.well-known/openid-configuration", ex -> respond(ex, new Reply(200,
                "{\"issuer\":\"" + (advertisedIssuer != null ? advertisedIssuer : issuer().toString()) + "\","
                        + "\"token_endpoint\":\"" + issuer() + "/token\","
                        + "\"authorization_endpoint\":\""
                        + (authorizationEndpoint != null ? authorizationEndpoint : issuer() + "/authorize") + "\","
                        + "\"authorization_response_iss_parameter_supported\":" + issParameterSupported + "}")));
        server.createContext("/.well-known/lws-configuration", ex -> respond(ex, new Reply(200,
                "{\"issuer\":\"" + (lwsIssuer != null ? lwsIssuer : issuer().toString()) + "\","
                        + "\"token_endpoint\":\"" + issuer() + "/token\","
                        + "\"grant_types_supported\":[\"urn:ietf:params:oauth:grant-type:token-exchange\"],"
                        + "\"subject_token_types_supported\":" + subjectTokenTypes + ","
                        + "\"subject_identifier_types_supported\":[\"https\",\"did:key\"]}")));
        server.createContext("/token", ex -> {
            Map<String, String> form = parseForm(new String(ex.getRequestBody().readAllBytes(), UTF_8));
            TokenRequest request = new TokenRequest(form, ex.getRequestHeaders().getFirst("Authorization"),
                    ex.getRequestHeaders().getFirst("DPoP"));
            tokenRequests.add(request);
            respond(ex, tokenHandler.apply(request));
        });
        server.start();
    }

    URI issuer() {
        return URI.create("http://127.0.0.1:" + server.getAddress().getPort());
    }

    /** A successful token response. */
    static String tokens(String accessToken, String refreshToken, long expiresIn) {
        return tokens(accessToken, refreshToken, expiresIn, "Bearer");
    }

    static String tokens(String accessToken, String refreshToken, long expiresIn, String tokenType) {
        return "{\"access_token\":\"" + accessToken + "\",\"token_type\":\"" + tokenType + "\",\"expires_in\":" + expiresIn
                + (refreshToken != null ? ",\"refresh_token\":\"" + refreshToken + "\"" : "") + "}";
    }

    static Map<String, String> parseForm(String body) {
        Map<String, String> form = new LinkedHashMap<>();
        if (body == null || body.isEmpty()) {
            return form;
        }
        for (String pair : body.split("&")) {
            int eq = pair.indexOf('=');
            form.put(URLDecoder.decode(pair.substring(0, eq), UTF_8), URLDecoder.decode(pair.substring(eq + 1), UTF_8));
        }
        return form;
    }

    @Override
    public void close() {
        server.stop(0);
    }

    private static void respond(HttpExchange ex, Reply reply) throws IOException {
        byte[] body = reply.json().getBytes(UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json");
        reply.headers().forEach((k, v) -> ex.getResponseHeaders().set(k, v));
        ex.sendResponseHeaders(reply.status(), body.length);
        ex.getResponseBody().write(body);
        ex.close();
    }
}
