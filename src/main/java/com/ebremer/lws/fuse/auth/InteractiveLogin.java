package com.ebremer.lws.fuse.auth;

import java.io.IOException;
import java.net.http.HttpClient;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Log-in-once user authentication: reuse the refresh token saved by an earlier browser login, or
 * run the browser flow ({@link AuthorizationCodeFlow}) and save the result in a
 * {@link CredentialStore}.
 *
 * <p>The saved token is kept current: every refresh token the server issues (rotation) is written
 * back immediately, since with rotation the previous one is spent. A saved token is also checked
 * up front; if the server no longer accepts it ({@code invalid_grant} — expired, revoked, or
 * already used), the browser login runs again instead of the mount failing on every request.
 *
 * <p>With DPoP, the login binds the tokens to the configured key, so a saved refresh token only
 * works with that same key: pass a persisted one (see {@link DPoP#DPoP(com.nimbusds.jose.jwk.ECKey)}).
 *
 * @author Erich Bremer
 */
public final class InteractiveLogin {

    private static final Logger log = LoggerFactory.getLogger(InteractiveLogin.class);

    private final HttpClient http;
    private final CredentialStore store;
    private final AuthorizationCodeFlow flow;
    private final Duration timeout;

    public InteractiveLogin(HttpClient http, CredentialStore store, AuthorizationCodeFlow flow, Duration timeout) {
        this.http = http;
        this.store = store;
        this.flow = flow;
        this.timeout = timeout;
    }

    /**
     * Authenticate and return a provider for the mount.
     *
     * @param config     issuer (required), optional token endpoint, client id/secret, scope and
     *                   DPoP; this method sets its grant, refresh token and listener
     * @param forceLogin ignore any saved refresh token and log in through the browser
     */
    public OpenIdAuthProvider authenticate(OpenIdAuthProvider.Config config, boolean forceLogin)
            throws IOException, InterruptedException {
        String issuer = config.issuer.toString();
        String saved = forceLogin ? null : store.loadRefreshToken(issuer, config.clientId);
        if (saved != null) {
            log.info("Using saved credentials for {} (client {})", issuer, config.clientId);
            OpenIdAuthProvider provider = refreshing(config, saved);
            try {
                provider.prefetch();
                return provider;
            } catch (TokenEndpointException e) {
                if (!e.isInvalidGrant()) {
                    throw e;
                }
                log.warn("The saved login for {} is no longer accepted (invalid_grant); "
                        + "starting the browser login again", issuer);
            }
        } else {
            log.info("No saved credentials for {}; starting interactive browser login", issuer);
        }

        AuthorizationCodeFlow.Tokens tokens = flow.login(config.issuer, null, config.tokenEndpoint,
                config.clientId, config.clientSecret, config.scope, config.dpop);
        if (tokens.refreshToken() == null) {
            log.warn("Logged in, but no refresh token was issued; this session will expire and "
                    + "require re-login (request the 'offline_access' scope to enable refresh)");
        } else {
            save(issuer, config.clientId, tokens.refreshToken());
            log.info("Login successful; refresh token saved to {}", store.path());
        }
        OpenIdAuthProvider provider = refreshing(config, tokens.refreshToken());
        provider.seed(tokens);   // the login's ID and access tokens, so nothing is refreshed yet
        return provider;
    }

    /** A refresh-token provider that writes every newly issued refresh token back to the store. */
    private OpenIdAuthProvider refreshing(OpenIdAuthProvider.Config config, String refreshToken) {
        String issuer = config.issuer.toString();
        String clientId = config.clientId;
        config.grant = OpenIdAuthProvider.Grant.REFRESH_TOKEN;
        config.refreshToken = refreshToken;
        config.refreshTokenListener = rotated -> save(issuer, clientId, rotated);
        return new OpenIdAuthProvider(http, config, timeout);
    }

    private void save(String issuer, String clientId, String refreshToken) {
        try {
            store.saveRefreshToken(issuer, clientId, refreshToken);
        } catch (IOException e) {
            log.warn("Could not save the refresh token to {} ({}); the next mount will need a new login",
                    store.path(), e.toString());
        }
    }
}
