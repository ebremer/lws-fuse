package com.ebremer.lws.fuse.auth;

import java.io.IOException;
import java.net.URI;

/**
 * Produces LWS <em>authentication credentials</em> — the signed tokens an LWS authentication
 * suite defines — which {@link LwsAuthProvider} exchanges at an authorization server for access
 * tokens (LWS core, Authorization: token exchange, RFC 8693).
 *
 * @author Erich Bremer
 */
public interface CredentialSource {

    /** OpenID Connect suite: an ID token. */
    String ID_TOKEN = "urn:ietf:params:oauth:token-type:id_token";
    /** SSI controlled-identifier suite: a self-issued JWT. */
    String JWT = "urn:ietf:params:oauth:token-type:jwt";
    /** SAML 2.0 suite: a base64url-encoded assertion. */
    String SAML2 = "urn:ietf:params:oauth:token-type:saml2";

    /**
     * @param token      the credential, as sent in {@code subject_token}
     * @param tokenType  its RFC 8693 token type URI, as sent in {@code subject_token_type}
     * @param subject    the LWS subject identifier it asserts, if known (for checking which
     *                   identifier types the authorization server accepts); may be {@code null}
     */
    record Credential(String token, String tokenType, String subject) {}

    /**
     * A credential to present to {@code authorizationServer}, which a suite may require to be in
     * the credential's audience.
     *
     * @throws AuthException if no credential can be produced (the message says why)
     */
    Credential credential(URI authorizationServer) throws IOException, InterruptedException;
}
