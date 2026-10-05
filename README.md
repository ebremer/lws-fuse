# lws-fuse

A **FUSE client that mounts a W3C [Linked Web Storage (LWS)](https://w3c.github.io/lws-protocol/)
server as a local drive** — so you can browse and edit your linked-web storage with `ls`, `cat`, an
editor, `cp`, or drag-and-drop, like any folder.

It is pure LWS/HTTP: it depends only on the JDK, Apache Jena, jnr-fuse, nimbus-jose-jwt,
`jakarta.json` and SLF4J (with `slf4j-simple` for logging) — **no Solid libraries, no server
framework**.

---

## How it works

Mount an LWS storage (or any container in it) as a drive letter (Windows) or directory
(Linux/macOS) and use it like any folder. The client follows the
[LWS 1.0 core protocol](https://w3c.github.io/lws-protocol/lws10-core/) as of 2026-10-05 and keeps
working with servers that implement earlier drafts. Filesystem operations map onto LWS requests:

| Filesystem | LWS |
|---|---|
| directory | `lws:Container` |
| file | `lws:DataResource` |
| `readdir` | `GET` container as `application/lws+json`, read its `items` (paged with `Link: rel="next"`) |
| path lookup | walk container listings from the mounted container (URIs need not mirror the hierarchy) |
| read | `GET` with `Range` |
| create / `mkdir` | `POST` to the parent container (with a `Slug` name hint; the server assigns the URI) |
| write | buffer, then `PUT` on close (conditional on the `ETag`) |
| `rm` / `rmdir` | `DELETE` |
| `mv` | copy to the new name, then `DELETE` the old (LWS has no move) |

Access follows **LWS authorization**: the storage names an authorization server, where the client
exchanges an authentication credential (an OpenID Connect ID token from a **browser login**, a
self-issued controlled-identifier JWT, or a SAML assertion) for an access token.

🌐 **Documentation site:** <https://ebremer.github.io/lws-fuse/> (built from [docs/](docs/))
📖 **Full usage guide:** [docs/usage.md](docs/usage.md)
🔧 **Build from source:** [docs/building.md](docs/building.md)

---

## Requirements

- **Java 25** or newer (GraalVM or any JDK 25+) — the project targets `maven.compiler.release=25`.
- A **user-space filesystem driver**: [WinFsp](https://winfsp.dev/) (Windows), libfuse 2 (Linux),
  or [macFUSE](https://osxfuse.github.io/) (macOS).
- A reachable **LWS server** and the URL of its storage (or of the container to mount).
- *To build:* Maven 3.9 or newer.

## Quick start

```bash
mvn -Pjar package                                                         # -> target/lws-fuse-1.0.0.jar
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ L:\        # Windows
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ /tmp/lws   # Linux, macOS
```

The mount runs in the foreground; `Ctrl-C` unmounts. On Linux/macOS the mount directory is created
if missing.

## Authentication

**How LWS authorization works.**
1. A request without a token gets `401` with `WWW-Authenticate: Bearer as_uri="…", realm="…"`.
2. The client reads that authorization server's `/.well-known/lws-configuration`.
3. It exchanges its authentication credential there for an access token (RFC 8693 token exchange,
   `resource` = the realm).
4. It sends the token as `Authorization: Bearer` within the realm, renewing it before it expires.

Servers that implement earlier drafts (no `as_uri` challenge) receive a credential directly
instead: the self-issued JWT or SAML assertion, or the OpenID provider's access token.

Pick a credential via `-Dlws.*` properties — all standard OAuth 2.0 / OpenID Connect or W3C
controlled identifiers, with no Solid-specific code:

| Method | Flags | LWS suite (credential) |
|--------|-------|------------------------|
| Anonymous | *(none)* | — |
| OpenID Connect — browser login (loopback + PKCE) | `-Dlws.login=true -Dlws.issuer=… -Dlws.clientId=…` | [OpenID][s-openid] (ID token) |
| OpenID Connect — refresh token | `-Dlws.issuer=… -Dlws.clientId=… -Dlws.grant=refresh_token -Dlws.refreshTokenFile=…` | [OpenID][s-openid] (ID token) |
| Self-issued — **controlled identifier** | `-Dlws.auth=cid -Dlws.cid=… [-Dlws.keyFile=…] [-Dlws.kid=…]` | [Controlled identifier][s-cid] (JWT) |
| Self-issued — **did:key** subject | `-Dlws.auth=did-key [-Dlws.keyFile=…]` | [Controlled identifier][s-cid] (JWT with a `did:key` subject) |
| **SAML 2.0** assertion | `-Dlws.auth=saml -Dlws.samlAssertion=<file>` | [SAML][s-saml] (assertion) |
| Pre-obtained access token | `-Dlws.tokenFile=…` (or env `LWS_TOKEN`) | — (sent as is, RFC 6750) |
| OpenID Connect — client credentials | `-Dlws.issuer=… -Dlws.clientId=… -Dlws.clientSecretFile=…` | none: no ID token, so only for earlier-draft servers |

Options common to the OpenID modes: `-Dlws.tokenEndpoint`, `-Dlws.scope`, `-Dlws.grant`, and
**DPoP** (RFC 9449, for servers that take provider tokens directly) via `-Dlws.dpop=true`.
`-Dlws.authServer=URI` restricts the token exchange to that one authorization server. Secrets are
read from files or environment variables (`LWS_TOKEN`, `LWS_CLIENT_SECRET`, `LWS_REFRESH_TOKEN`)
so they stay out of the process list; inline `-Dlws.token=…`-style values still work, with a
warning.

**Self-issued credentials** are signed JWTs (ES256 / P-256) whose `iss`, `sub`, and `client_id`
are the same identifier: an HTTPS controlled-identifier URI that resolves to your published public
key, or a `did:key:…` URI derived from a locally-held key (the controlled-identifier suite accepts
DID subjects). The JWT's `aud` is the authorization server it is exchanged at. The signing key is generated on first use
and stored at `~/.lws/<method>.jwk` (or `-Dlws.keyFile`).

Full details, DPoP, and refresh-token reuse are in the [usage guide](docs/usage.md#authentication).

### Reference specifications

- LWS core protocol — <https://w3c.github.io/lws-protocol/lws10-core/>
- LWS vocabulary — <https://w3c.github.io/lws-protocol/lws10-vocab/>
- LWS auth — OpenID Connect — <https://w3c.github.io/lws-protocol/lws10-authn-openid/>
- LWS auth — SSI Controlled Identifier — <https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/>
- LWS auth — SAML — <https://w3c.github.io/lws-protocol/lws10-authn-saml/>

[s-openid]: https://w3c.github.io/lws-protocol/lws10-authn-openid/
[s-cid]: https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/
[s-saml]: https://w3c.github.io/lws-protocol/lws10-authn-saml/

## Layout

```
pom.xml                         standalone Maven build (Jena + jnr-fuse + nimbus + jakarta.json + SLF4J)
src/main/java/com/ebremer/
  lws/fuse/                     LWSFileSystem, LWSClient, OpenFile, ReadAhead, ContainerListing, Links, …
  lws/fuse/auth/                LWS authorization (token exchange), OpenID / SSI / SAML credentials,
                                PKCE browser login, DPoP
  ns/                           project-local LWS vocabulary
src/main/resources/             log format and levels (simplelogger.properties), native-image args
src/test/java/…                 tests, with mock LWS and OpenID / authorization servers
docs/                           documentation site (GitHub Pages): home, usage guide, building
.github/workflows/              CI (ci.yml) and the documentation site's deployment (pages.yml)
TODO.md                         review findings: what is done, what is open
LICENSE                         Apache License 2.0
```

## Status & caveats

- The LWS client, auth flows and FUSE callbacks have unit tests against mock LWS/OpenID servers
  (`mvn test`). A **live mount on JDK 25 is verified on Windows (WinFsp)**; Linux and macOS mounts
  are not yet confirmed (jnr-fuse 0.5.8 predates JDK 25) — see
  [docs/building.md](docs/building.md#known-caveats).
- Not yet tested against a real LWS 1.0 server or authorization server; only against the mocks.
- An experimental GraalVM native-image profile (`mvn -Plws-native package`) exists; jnr-ffi limits
  it — see the [native-image note](docs/usage.md#native-image-experimental).

## License

Licensed under the [Apache License, Version 2.0](LICENSE).
