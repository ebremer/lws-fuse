package com.ebremer.lws.fuse.auth;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;

/**
 * Stands in for the user's browser in {@link AuthorizationCodeFlow}: on receiving the authorization
 * URL it immediately "approves" (or denies) the login by calling the loopback redirect URI.
 */
final class SimulatedBrowser implements Consumer<URI> {

    private final String code;
    private final String error;
    private final String errorDescription;
    /** Sent as the RFC 9207 {@code iss} parameter, when set. */
    volatile String iss;
    /** Before answering, hit the callback with a forged request (wrong {@code state}). */
    volatile boolean forgedRequestFirst;
    /** The query parameters of every authorization URL opened. */
    final List<Map<String, String>> requests = new CopyOnWriteArrayList<>();
    /** What the loopback listener answered, per callback request made. */
    final List<HttpResponse<String>> callbackResponses = new CopyOnWriteArrayList<>();

    private SimulatedBrowser(String code, String error, String errorDescription) {
        this.code = code;
        this.error = error;
        this.errorDescription = errorDescription;
    }

    static SimulatedBrowser approving(String code) {
        return new SimulatedBrowser(code, null, null);
    }

    static SimulatedBrowser denying(String error) {
        return new SimulatedBrowser(null, error, null);
    }

    static SimulatedBrowser denying(String error, String description) {
        return new SimulatedBrowser(null, error, description);
    }

    @Override
    public void accept(URI authorizationUrl) {
        Map<String, String> query = MockOpenIdServer.parseForm(authorizationUrl.getRawQuery());
        requests.add(query);
        String redirect = query.get("redirect_uri");
        if (forgedRequestFirst) {
            callback(redirect + "?error=access_denied&state=forged");
        }
        String params = (error != null ? "error=" + enc(error) : "code=" + enc(code))
                + (errorDescription != null ? "&error_description=" + enc(errorDescription) : "")
                + (iss != null ? "&iss=" + enc(iss) : "")
                + "&state=" + enc(query.get("state"));
        callback(redirect + "?" + params);
    }

    private void callback(String url) {
        try {
            callbackResponses.add(HttpClient.newHttpClient().send(
                    HttpRequest.newBuilder(URI.create(url)).GET().build(), HttpResponse.BodyHandlers.ofString()));
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, UTF_8);
    }
}
