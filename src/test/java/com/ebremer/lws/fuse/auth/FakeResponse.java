package com.ebremer.lws.fuse.auth;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import javax.net.ssl.SSLSession;

/** A response to hand to {@link AuthProvider#onUnauthorized} / {@link AuthProvider#onResponse}. */
record FakeResponse(int statusCode, HttpRequest request, HttpHeaders headers) implements HttpResponse<Void> {

    static FakeResponse of(int status, HttpRequest request, Map<String, String> headers) {
        Map<String, List<String>> h = headers.entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, e -> List.of(e.getValue())));
        return new FakeResponse(status, request, HttpHeaders.of(h, (k, v) -> true));
    }

    @Override
    public Optional<HttpResponse<Void>> previousResponse() {
        return Optional.empty();
    }

    @Override
    public Void body() {
        return null;
    }

    @Override
    public Optional<SSLSession> sslSession() {
        return Optional.empty();
    }

    @Override
    public URI uri() {
        return request.uri();
    }

    @Override
    public HttpClient.Version version() {
        return HttpClient.Version.HTTP_1_1;
    }
}
