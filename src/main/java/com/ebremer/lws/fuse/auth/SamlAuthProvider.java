package com.ebremer.lws.fuse.auth;

import java.net.URI;
import java.net.http.HttpRequest;
import java.util.Base64;

/**
 * Presents a pre-obtained SAML 2.0 assertion as the authentication credential for the
 * <a href="https://w3c.github.io/lws-protocol/lws10-authn-saml/">LWS SAML authentication suite</a>
 * (token type {@code urn:ietf:params:oauth:token-type:saml2}).
 *
 * <p>Under LWS authorization it is a {@link CredentialSource}: the base64url-encoded assertion is
 * the {@code subject_token} that {@link LwsAuthProvider} exchanges (type
 * {@code urn:ietf:params:oauth:token-type:saml2}, RFC 8693 §3). For servers following earlier
 * drafts it is also presented directly, as {@code Authorization: Bearer <assertion>}. Obtaining the
 * assertion (via an IdP / SAML SSO) is left to the deployment.
 *
 * @author Erich Bremer
 */
public final class SamlAuthProvider implements AuthProvider, CredentialSource {

    private final String bearer;

    public SamlAuthProvider(byte[] assertionXml) {
        this.bearer = Base64.getUrlEncoder().withoutPadding().encodeToString(assertionXml);
    }

    @Override
    public void authorize(HttpRequest.Builder builder, String method, URI uri) {
        builder.setHeader("Authorization", "Bearer " + bearer);
    }

    @Override
    public Credential credential(URI authorizationServer) {
        return new Credential(bearer, SAML2, null);
    }
}
