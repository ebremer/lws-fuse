---
title: Usage guide
nav_order: 2
---

# LWS FUSE Client

Mount a [W3C Linked Web Storage (LWS)](https://w3c.github.io/lws-protocol/) server as an
ordinary local drive and read and write it with any program — `ls`, `cat`, an editor,
`cp`, drag-and-drop in a file manager, and so on.

The client lives in the package `com.ebremer.lws.fuse` and is a **pure W3C LWS
client**: it speaks only HTTP and the W3C Linked Web Storage protocol and vocabulary
(`https://www.w3.org/ns/lws#`), over `java.net.http`, and carries no Solid-specific code and no
LDP (LWS defines its own containment model). It follows the
[LWS 1.0 core protocol](https://w3c.github.io/lws-protocol/lws10-core/) as of w3c/lws-protocol
`ef02548` (2026-10-05), and keeps working with servers that implement earlier drafts.

Access follows LWS authorization: the storage names an authorization server, where the client
exchanges an authentication credential (an OpenID Connect ID token, a self-issued
controlled-identifier JWT, or a SAML assertion) for an access token. All of it is standard
OAuth 2.0 / OpenID Connect, never Solid-OIDC. See [Authentication](#authentication).

---

## Contents

- [How it works](#how-it-works)
- [Prerequisites](#prerequisites)
- [Building](#building)
- [Running](#running)
- [Authentication](#authentication)
- [Everyday usage](#everyday-usage)
- [Configuration reference](#configuration-reference)
- [Behavior and limitations](#behavior-and-limitations)
- [Unmounting](#unmounting)
- [Troubleshooting](#troubleshooting)
- [Architecture](#architecture)
- [Native image (experimental)](#native-image-experimental)
- [A note on the LWS specification](#a-note-on-the-lws-specification)

---

## How it works

An LWS server is an HTTP store described with the W3C LWS vocabulary
(`https://www.w3.org/ns/lws#`). A **container** (`lws:Container`) is a directory; a
**data resource** (`lws:DataResource`) is a file. URIs are assigned by the server and need not
mirror the hierarchy, so the client navigates the way the protocol describes: from the storage root
(the URL you mount), through each container's listing, to the member with the wanted name. A
member's name is the last segment of its URI. The client maps filesystem operations onto that
model:

| Filesystem operation | LWS request |
|----------------------|-------------|
| `getattr` (stat)     | from the parent container's listing; `HEAD` only for the root, for a file whose size the listing omits, or at the hierarchical URI when the listing is forbidden |
| `readdir` (list dir) | `GET` the container as `application/lws+json`, read its `items`, following `Link: rel="next"` pages |
| `read`               | `GET` with an HTTP `Range` header, through a per-handle read-ahead |
| `write`              | buffer the whole resource in a temporary file, then upload it on close |
| `create`             | register a new empty file locally; on first close, `POST` it to the parent container, with a `Slug` header suggesting its name |
| save (existing file) | `PUT` to the resource, with `If-Match` on its `ETag` |
| `mkdir`              | `POST` to the parent with `Link: <https://www.w3.org/ns/lws#Container>; rel="type"` and a `Slug` name hint |
| `unlink`             | `DELETE` the resource |
| `rmdir`              | `DELETE` the container (the server refuses a non-empty one) |
| `rename` (file)      | `GET` the old resource, create or update the new name, `DELETE` the old |
| `rename` (directory) | the same for every entry in the tree, then `DELETE` the original entry by entry |
| `truncate`           | resize the buffer; truncating to zero needs no download |

If the URL you mount serves a **storage description** (`application/lws+cid`, or JSON typed
`Storage`), the client mounts the `StorageRoot` it names instead. If that check fails, the URL is
mounted as given, with a warning in the log.

Because HTTP has no random-access write, a resource opened for writing is buffered in full, in a
temporary *spool file* rather than in memory: its current content is downloaded once on the first
read-modify (not at all when the file is truncated to zero first), changed in place, and uploaded
once when a handle that wrote to it closes. The upload is conditional: a file that was downloaded
is sent with `If-Match` on its `ETag`, and a new one is only created if the name is still free, so
a change someone else made meanwhile is not overwritten (see
[Behavior and limitations](#behavior-and-limitations)).

Reads of a file that is not being written bypass the buffer and stream from the server with
`Range` requests. Each handle reads ahead: the first request fetches 128 KiB, and while the
reading stays sequential each further request doubles that, up to 4 MiB. Hashing a 3 MB file
through a WinFsp mount, which reads in 4 KiB pieces, took 7 `GET`s instead of about 770. A server
that ignores `Range` is
detected on the first read, and the file is then downloaded once instead of on every read. A
paginated container is walked to the end transparently, so `ls` shows all members.

Metadata comes from the listing: each member's `type`, `format` (media type), `size` and
`modified`. When a listing omits a file's size, a `HEAD` supplies `Content-Length` and
`Last-Modified`. A listing also answers lookups of names it does not contain, so the probes Windows
Explorer and editors make for `desktop.ini`, `Thumbs.db` or swap files cost nothing.

**Earlier drafts.** Servers that follow earlier LWS drafts still work. The client accepts Turtle
listings (`lws:contains` or `lws:items`, paged with in-body `lws:first`/`lws:next`), and creates
with `PUT` plus `If-None-Match: *` when the server answers `405` or `501` to `POST` and that
`PUT` works (from then on, every create uses `PUT`). Once a `POST` has created something, a
`405` only means that one container refuses, and it is reported as such.

---

## Prerequisites

1. **Java 25** or newer (the project targets `maven.compiler.release=25`).
2. **A user-space filesystem driver for your OS:**
   - **Windows** — [WinFsp](https://winfsp.dev/). Mount to an unused drive letter (e.g. `L:\`)
     or a non-existent directory.
   - **Linux** — libfuse (`libfuse2`/`fuse` via your package manager). Mount to an existing,
     empty directory.
   - **macOS** — [macFUSE](https://osxfuse.github.io/).
3. **A reachable LWS server** and the base URL of the container you want to mount, for example
   `https://example.org/alice/`.

The FUSE binding is provided by the project's existing dependency
`com.github.serceman:jnr-fuse`.

---

## Building

Build the shaded (fat) jar, which bundles every dependency:

```bash
mvn -Pjar package
```

This produces `target/lws-fuse-1.0.0.jar`. Its `Main-Class` is `LWSFileSystem`, so
`java -jar target/lws-fuse-1.0.0.jar …` launches the client directly.

For iterative development you can skip packaging and run straight from `target/classes`
after `mvn compile` (see the alternative under [Running](#running)).

---

## Running

The one required input is the LWS base URL. The mount point is optional and defaults to `L:\`
on Windows or `/tmp/lws` elsewhere.

```bash
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ L:\        # Windows
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ /tmp/lws   # Linux, macOS
```

Invoked with no arguments it prints its usage:

```
Usage: LWSFileSystem <lws-base-url> [mount-point]
  -Dlws.base=URL          LWS container base URL
  -Dlws.mount=PATH        mount point (default: L:\)
  Authentication (optional; pick one):
    Bearer token:         -Dlws.tokenFile=FILE  (or env LWS_TOKEN)
    Client credentials:   -Dlws.issuer=URL -Dlws.clientId=ID -Dlws.clientSecretFile=FILE
                          (or env LWS_CLIENT_SECRET)
    Browser login:        -Dlws.login=true -Dlws.issuer=URL -Dlws.clientId=ID
                          [-Dlws.clientSecretFile=FILE] [-Dlws.forceLogin=true]
    Common OpenID opts:   [-Dlws.tokenEndpoint=URL] [-Dlws.scope=...]
                          [-Dlws.grant=client_credentials|refresh_token]
                          [-Dlws.refreshTokenFile=FILE (or env LWS_REFRESH_TOKEN)]
                          [-Dlws.dpop=true]
    SSI did:key:          -Dlws.auth=did-key  [-Dlws.keyFile=PATH]
    SSI controlled id:    -Dlws.auth=cid -Dlws.cid=URI  [-Dlws.keyFile=PATH] [-Dlws.kid=ID]
    SAML assertion:       -Dlws.auth=saml -Dlws.samlAssertion=FILE
    Authorization server: [-Dlws.authServer=URI]  only exchange credentials there
  Self-issued JWTs presented directly to an earlier-draft server name the base
  URL as their audience; override with -Dlws.audience=URI.
  Secrets can also be given inline (-Dlws.token, -Dlws.clientSecret,
  -Dlws.refreshToken), but other local users can read the command line.
```

Every option can also be supplied as a system property, which takes precedence over the
positional arguments. System properties go before `-jar`:

```bash
java -Dlws.base=https://example.org/alice/ -Dlws.mount=/mnt/lws -jar target/lws-fuse-1.0.0.jar
```

The process **stays in the foreground** while mounted; stop it with `Ctrl-C` to unmount
(see [Unmounting](#unmounting)). On Linux and macOS a missing mount directory is created; a mount
point that exists but is not a directory stops the tool (exit code 2).

**Run from compiled classes (no fat jar).** The jar's manifest enables native access for jnr-ffi,
but a `-cp` launch ignores the manifest, so pass `--enable-native-access=ALL-UNNAMED` yourself
(otherwise JDK 25 prints a restricted-method warning):

```bash
mvn compile
mvn dependency:build-classpath -Dmdep.outputFile=target/cp.txt
# Linux/macOS (':' separator):
java --enable-native-access=ALL-UNNAMED -cp "target/classes:$(cat target/cp.txt)" \
     com.ebremer.lws.fuse.LWSFileSystem https://example.org/alice/ /tmp/lws
# Windows PowerShell (';' separator):
java --enable-native-access=ALL-UNNAMED -cp "target/classes;$(Get-Content target/cp.txt)" `
     com.ebremer.lws.fuse.LWSFileSystem https://example.org/alice/ L:\
```

---

## Authentication

**How LWS authorization works.** A storage does not accept your identity credential directly.
1. A request without a token is answered `401` with one or more challenges,
   `WWW-Authenticate: Bearer as_uri="<authorization server>", realm="<storage>"`. The client uses
   the first whose realm contains the request and whose authorization server it accepts.
2. The client reads the authorization server's metadata from `/.well-known/lws-configuration`,
   whose `issuer` must be `as_uri`.
3. It exchanges an **authentication credential** at that server's token endpoint
   (RFC 8693 token exchange, with `resource` = the realm). The credential is the one your chosen
   suite defines: an OpenID Connect **ID token**, a **self-issued JWT**
   (controlled identifier, including a `did:key` subject), or a **SAML assertion**. If the
   server's `subject_token_types_supported` leaves out that kind of credential, none is sent.
4. It sends the resulting access token as `Authorization: Bearer` on every request in that realm,
   and exchanges again shortly before it expires or when the storage rejects it. A token refused
   within seconds of being issued means "not permitted", so it is not replaced. A token of
   another type than `Bearer` is not used.

Authorization servers are only contacted over `https` (or `http` on a loopback address). To accept
only one, set `-Dlws.authServer=<URI>`. A server following earlier drafts sends no `as_uri`
challenge; it gets a credential directly, as before: the self-issued JWT or SAML assertion as a
`Bearer` token or, in the OpenID modes, the provider's access token (`Bearer`, or `DPoP` with
`-Dlws.dpop=true`). This is decided per server, and never happens for one that has sent an LWS
challenge, so a server cannot downgrade the client into handing over the credential.

The modes below are chosen by which `-Dlws.*` properties you set. All are standard
OAuth 2.0 / OpenID Connect — **not** Solid-OIDC — implemented in the
`com.ebremer.lws.fuse.auth` package with no `com.inrupt.*` dependency.

**1. Anonymous (default).** Set nothing; for public servers.

> **Keep secrets off the command line.** Other local users can read a process's arguments
> (`ps`, `/proc/<pid>/cmdline`, Task Manager), so give the token, client secret and refresh token
> as a file (`-Dlws.tokenFile`, `-Dlws.clientSecretFile`, `-Dlws.refreshTokenFile`) or an
> environment variable (`LWS_TOKEN`, `LWS_CLIENT_SECRET`, `LWS_REFRESH_TOKEN`). The inline
> properties (`-Dlws.token=…` etc.) still work but log a warning. A file wins over the inline
> property, which wins over the environment variable; surrounding whitespace in a file is ignored.

**2. Fixed bearer token.** Supply an access token you obtained elsewhere; it is sent verbatim as
`Authorization: Bearer <token>` on every request (no token exchange):

```bash
export LWS_TOKEN="ey…"              # or -Dlws.tokenFile=/path/to/token
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/
```

**3. Client credentials (machine login).** Give the client an issuer (or token endpoint), a
client id, and a secret; it acquires access tokens itself with the `client_credentials` grant and
refreshes them before they expire — no user interaction. That grant issues no ID token, so it is
**not** an LWS authentication suite: it only works with servers that accept the provider's access
tokens directly (earlier drafts). For LWS authorization use the browser login, a refresh token, or
a controlled identifier (mode 6), which is meant for bots and scripts:

```bash
java -Dlws.issuer=https://op.example.org \
     -Dlws.clientId=my-client -Dlws.clientSecretFile=$HOME/.lws/client-secret \
     -jar target/lws-fuse-1.0.0.jar https://example.org/alice/
```

The issuer's discovery document must name that same issuer (OpenID Connect Discovery §4.3; a
trailing `/` difference is tolerated), or it is rejected along with every endpoint in it.

**4. Browser login (interactive user login).** With `-Dlws.login=true`, the tool logs the *user*
in through their real browser — the RFC 8252 pattern of the system browser plus a loopback
redirect, with PKCE. It opens the authorization URL (and prints it on stdout, in case no browser
opens), catches the redirect on `127.0.0.1`, and exchanges the code for tokens. The **ID token** is the
credential of the [LWS OpenID suite](https://w3c.github.io/lws-protocol/lws10-authn-openid/): it is
exchanged at the storage's authorization server, and a refresh obtains a new one when it expires
(most providers return one on refresh; if yours does not, the log says to log in again). LWS
expects the client id, which appears as the ID token's `azp`, to be a URI, such as a Client ID
Metadata Document URL, and the ID token's subject to be a URI too. The client logs a warning when
the ID token has no `azp`, or its subject or the client id is not a URI, since the authorization
server may then refuse it; an unsigned ID token (`alg` `none`) is refused outright:

```bash
java -Dlws.login=true -Dlws.issuer=https://op.example.org -Dlws.clientId=https://app.example/client.json \
     -jar target/lws-fuse-1.0.0.jar https://example.org/alice/
```

The redirect URI is `http://127.0.0.1:<port>/callback` on a random free port, so the provider must
accept loopback redirects on any port, as RFC 8252 asks of it. The browser has to run on the same
machine (over SSH, forward that port), and the login is abandoned after 5 minutes without a
reply.

The refresh token is saved to `~/.lws/credentials.properties`, under the issuer and client id, so
you **log in once** and later mounts reuse it silently; changing either means logging in again.
The file is written atomically and is readable only by you from the
moment it exists (`rw-------` on POSIX, an owner-only ACL on Windows); a newly created `~/.lws` is
`rwx------`.
- Refresh tokens the server rotates are written back as they arrive, so the saved one is never a
  spent token.
- At startup the saved login is checked. If the server rejects it as `invalid_grant` (expired or
  revoked), the browser login simply runs again. Any other failure (provider unreachable, another
  error) stops the tool with `Interactive login failed: …`.
- Force a fresh login with `-Dlws.forceLogin=true`.

Because it uses the *system* browser, your existing SSO session, password manager, passkeys and MFA
all work, and the tool never sees your password.

The login is hardened against a hostile or compromised identity provider and against other local
processes:
- Only an `https` authorization endpoint (or `http` on a loopback address) is opened. The OS
  "open" commands launch any scheme, so a `file:` or custom-protocol URL is refused.
- The loopback listener ignores any request that does not carry this login's `state`. A stray or
  forged request can't end the login, and messages echoed back into the page are HTML-escaped.
- If the provider sends the RFC 9207 `iss` parameter, it must name the configured issuer. If the
  provider advertises `authorization_response_iss_parameter_supported`, the parameter is required.
- An `error_description` from the provider is shown along with the error.

**Common OpenID options** (modes 3 and 4):
- `-Dlws.tokenEndpoint=…` skips discovery for client credentials and refresh tokens. The browser
  login still discovers its authorization endpoint from `-Dlws.issuer` and only takes the token
  endpoint from this.
- `-Dlws.scope=…` sets the scope. The browser login defaults to `openid offline_access`. A custom
  scope still needs `openid`, without which no ID token is issued, and `offline_access` if the
  login is to be saved.
- `-Dlws.grant=refresh_token -Dlws.refreshTokenFile=…` uses a refresh token obtained elsewhere;
  its ID tokens are exchanged like the browser login's. If the server rotates that refresh token,
  the one you passed in is spent: the tool logs a warning once but cannot update your file, so
  use the browser login if your provider rotates. Any other `-Dlws.grant` value means client
  credentials.
- `-Dlws.dpop=true` asks for DPoP (RFC 9449) proof-of-possession tokens, for servers that take
  provider tokens directly. LWS access tokens are plain bearer tokens.

If no token can be obtained at all (token endpoint unreachable or refusing, token exchange
refused), operations fail with `EACCES` and the reason is logged once, not on every request.
Configuration mistakes stop the tool at startup instead:
- `-Dlws.login=true` without an issuer and client id;
- a `-D…File` that cannot be read;
- a missing `-Dlws.cid` or `-Dlws.samlAssertion`, or an unknown `-Dlws.auth` value;
- a corrupt key file.

**DPoP details.**
- Nonces are supported: when the token endpoint or the LWS server answers `use_dpop_nonce` with a
  `DPoP-Nonce`, the request is repeated once with the nonce in the proof. Nonces sent on other
  responses are remembered, per server.
- With the browser login, the authorization code and the issued tokens are bound to the DPoP key
  (`dpop_jkt` and a DPoP-proved code exchange). That key is kept at `~/.lws/dpop.jwk` (owner-only)
  because the saved refresh token only works with it. Client credentials and
  `-Dlws.grant=refresh_token` use a fresh key per run, so a refresh token bound to a DPoP key
  elsewhere cannot be used with `-Dlws.dpop=true`.
- If the server issues a plain `Bearer` token anyway, it is used, and a warning is logged once.

**5. Self-issued — did:key subject.** A *self-issued* signed JWT (ES256 / P-256) whose
`iss`/`sub`/`client_id` are a `did:key:…` URI derived from a locally-held key. This is the
[controlled-identifier suite](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/) with a DID
subject, so the authorization server must list `did:key` among its
`subject_identifier_types_supported` (the client warns if it does not):

```bash
java -Dlws.auth=did-key -jar target/lws-fuse-1.0.0.jar https://example.org/alice/
```

The key is generated on first use and saved, owner-only, to `~/.lws/did-key.jwk` (or
`-Dlws.keyFile`); the tool prints the resulting `did:key:…` on startup so you can authorize it on
the server. The key *is*
the identity, so an existing key file is never overwritten. If it is corrupt or not a private P-256
JWK, the tool stops with an error and leaves the file for you to repair or move. The JWT's `kid`
is the did:key's own verification method; `-Dlws.kid` does not apply.

**6. Self-issued — controlled identifier (CID).** The same self-issued JWT, but the identifier
is an HTTPS controlled-identifier URI resolving to a document that publishes your public key; the
JWT's `kid` (`-Dlws.kid`, default `<cid>#key-0`) names that key's verification method:

```bash
java -Dlws.auth=cid -Dlws.cid=https://id.example/agent \
     -jar target/lws-fuse-1.0.0.jar https://example.org/alice/
```

The signing key is generated on first use and saved, owner-only, to `~/.lws/cid.jwk` (or
`-Dlws.keyFile`). Unlike did:key, nothing is printed: publish the key's public part (the JWK
without its private `d` member) in your controlled-identifier document, under the verification
method that `kid` names.

**7. SAML.** A pre-obtained SAML 2.0 assertion, exchanged base64url-encoded (token type
`urn:ietf:params:oauth:token-type:saml2`):

```bash
java -Dlws.auth=saml -Dlws.samlAssertion=/path/to/assertion.xml \
     -jar target/lws-fuse-1.0.0.jar https://example.org/alice/
```

The assertion is read once, at startup. Once it expires, no new access token can be obtained;
restart the tool with a fresh assertion.

A self-issued JWT (5, 6) exchanged at an authorization server names that server as its `aud`,
as the suite requires. Presented directly to an earlier-draft server, it names the mount's base
URL, exactly as given, instead (override with `-Dlws.audience=URI`). Reference suites:
[OpenID](https://w3c.github.io/lws-protocol/lws10-authn-openid/),
[controlled identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/),
[SAML](https://w3c.github.io/lws-protocol/lws10-authn-saml/).

**Still out of scope** (extend the `auth` package as the suites firm up): publishing a Client ID
Metadata Document or OpenID Federation entity for the client, and the Device Authorization Grant
(RFC 8628) as a no-browser fallback. The suites are drafts, so the concrete flow may change.

---

## Everyday usage

Once mounted, use it like any folder. Assuming a Linux mount at `/tmp/lws`:

```bash
ls -l /tmp/lws                       # readdir  -> GET container (application/lws+json), its items
cat /tmp/lws/notes.txt               # read     -> GET (Range)
cp ./photo.jpg /tmp/lws/photo.jpg    # create+write -> POST to the container (name hint photo.jpg) on close
mkdir /tmp/lws/projects              # mkdir    -> POST to the container (Link: type Container)
mv /tmp/lws/a.txt /tmp/lws/b.txt     # rename (file) -> GET + POST/PUT + DELETE
mv /tmp/lws/projects /tmp/lws/old    # rename (directory) -> copy the tree, then delete it
rm /tmp/lws/old.bin                  # unlink   -> DELETE
rmdir /tmp/lws/projects              # rmdir    -> DELETE container (must be empty)
printf 'hello' > /tmp/lws/hi.txt     # create+write+truncate
```

Editors that write via a temporary file and rename into place also work, since rename is
implemented as copy-then-delete, but such a save replaces the file without the conflict check a
direct save gets (see [Behavior and limitations](#behavior-and-limitations)). Renaming a folder
works from Windows Explorer as well.

---

## Configuration reference

| Setting | System property | Positional arg | Environment | Default |
|--------|-----------------|----------------|-------------|---------|
| LWS base URL (required) | `-Dlws.base` | 1st | — | — |
| Mount point | `-Dlws.mount` | 2nd | — | `L:\` (Windows) / `/tmp/lws` (other) |
| Fixed bearer token | `-Dlws.tokenFile` (or `-Dlws.token`) | — | `LWS_TOKEN` | none (anonymous) |
| OpenID issuer (for discovery) | `-Dlws.issuer` | — | — | — |
| OpenID token endpoint (skips its discovery) | `-Dlws.tokenEndpoint` | — | — | — |
| OAuth client id | `-Dlws.clientId` | — | — | — |
| OAuth client secret | `-Dlws.clientSecretFile` (or `-Dlws.clientSecret`) | — | `LWS_CLIENT_SECRET` | — (public client) |
| OAuth scope(s) | `-Dlws.scope` | — | — | `openid offline_access` (browser login); none otherwise |
| Grant type (not used by the browser login) | `-Dlws.grant` | — | — | `client_credentials` (or `refresh_token`) |
| Refresh token | `-Dlws.refreshTokenFile` (or `-Dlws.refreshToken`) | — | `LWS_REFRESH_TOKEN` | — |
| Interactive browser login | `-Dlws.login` | — | — | `false` |
| Force fresh login (ignore saved token) | `-Dlws.forceLogin` | — | — | `false` |
| Use DPoP (RFC 9449) | `-Dlws.dpop` | — | — | `false` |
| SSI / SAML suite | `-Dlws.auth` | — | — | none (`did-key`, `cid` or `saml`) |
| Signing key file (did:key, CID) | `-Dlws.keyFile` | — | — | `~/.lws/did-key.jwk` / `~/.lws/cid.jwk` |
| Controlled-identifier URI (CID) | `-Dlws.cid` | — | — | — (required with `cid`) |
| Key id for the CID's JWT | `-Dlws.kid` | — | — | `<cid>#key-0` |
| SAML assertion file | `-Dlws.samlAssertion` | — | — | — (required with `saml`) |
| Only accept this authorization server | `-Dlws.authServer` | — | — | any the storage names, over `https` (or `http` on a loopback address) |
| Audience of self-issued JWTs presented directly (earlier drafts) | `-Dlws.audience` | — | — | the base URL, as given |

Mode selection: `-Dlws.auth` (`did-key`, `cid` or `saml`; `didkey`, `did:key`, `ssi-cid` and
`controlled-identifier` are accepted too, in any case) selects a self-issued or SAML credential
and takes precedence over everything else; otherwise `-Dlws.login=true` runs the interactive
browser login (it requires `-Dlws.issuer` and `-Dlws.clientId`); otherwise a client id **and** an
issuer or token endpoint select the non-interactive OpenID flow; otherwise the client falls back
to the bearer token, then to anonymous. The browser login persists its refresh token to
`~/.lws/credentials.properties` and reuses it on later mounts.

Fixed internal settings (in `LWSClient`, `LWSFileSystem`, `ReadAhead` and `LwsAuthProvider`):

| Setting | Value | Meaning |
|---------|-------|---------|
| Connect timeout | 30 s | TCP/TLS connection establishment |
| Request timeout | 60 s | per HTTP request (a timed-out request is not retried) |
| Retries | 3 attempts | for `429`/`503` (any request) and dropped connections (any request but a `POST`, which may already have created something), waiting 0.5 s then 1 s, or the server's `Retry-After` if that is at most 10 s |
| Attribute cache TTL | 1.5 s | how long a `getattr` result is reused to absorb stat storms |
| Listing TTL | 3 s / 2 s | how long a directory listing answers "no such file" (filesystem layer) / is reused for `stat` and name lookups (client) without asking the server |
| Resolved paths | 100,000 | paths whose URIs are remembered; an entry is dropped on a `404`/`410` or a local change, not after a fixed time |
| Access tokens | per realm | exchanged again 30 s before they expire (`expires_in`, else the JWT's `exp`, else 5 min) |
| Read-ahead | 128 KiB → 4 MiB | per handle; doubles while reads stay sequential |
| Deferred truncate | 2 s | how long a truncate-to-zero of a file nobody has open waits for the write that usually follows |
| Directory rename | 1000 entries | larger trees are refused with `EXDEV` |
| Redirects | `NORMAL` | followed automatically (except HTTPS→HTTP); `Authorization` is not sent to another origin |

The URL is used exactly as given: LWS URIs are opaque, so a container's need not end in `/`. If
nothing exists at a URL typed without a trailing `/`, the same URL with one is tried. The URL may
also be a storage description; then its storage root is mounted, exactly as the description
names it.

---

## Behavior and limitations

- **Whole-file writes.** Any write to a resource loads the entire object, applies the change
  locally, and re-uploads the whole thing with one `PUT` on close. Modifying one byte of a large
  file therefore downloads and re-uploads the whole file. This is inherent to HTTP storage.
- **Buffers live on local disk, not in memory.** A file being written is spooled to a temporary
  file under the system temporary directory (`lws-fuse-*`, owner-only on POSIX), so its size is
  limited by free disk space rather than the Java heap. A download larger than the free space
  fails up front with `ENOSPC`. The spool files are deleted when the file is closed and at
  unmount.
- **Names come from URIs.** A file or folder is shown under the last segment of its URI. LWS
  servers assign the URI of a new resource, and the protocol defines no way to ask for a name, so
  the client suggests yours with a `Slug` header, which many servers honor. If the server chooses
  otherwise, a warning is logged and the file appears under the server's name. A server that
  ignores `Slug` (opaque identifiers) therefore shows generated names.
- **Concurrent changes are not overwritten.** An upload is conditional on the version that was
  read (`If-Match`). A new file is only created if no member of that name exists (or, on an
  earlier-draft server, with `If-None-Match: *`). If someone else changed, deleted or created the
  file meanwhile, your version is **not** uploaded. It is
  saved to `~/.lws/recovery/<timestamp>-<path>`, an error is logged, and the mount shows the
  server's version again; merge by hand. Limits:
  - It only works if the server sends strong `ETag`s. LWS requires one only on `GET` and `HEAD`
    responses, so when a save's response carries none, a `HEAD` fetches it for the next save.
  - A file you overwrite without reading it first (truncate to zero, then write) is uploaded
    unconditionally. So is a rename onto an existing file, which is how many editors save.
  - The "name is free" check for a new file uses the latest listing, which may be up to 2 s old.
    If the name is taken in that window, the server stores the file under another name and a
    warning is logged.
- **A failed upload is kept, not dropped.** If the `PUT` on close fails for another reason
  (network error, `5xx`, `403`, …), the edited content stays in the mount: reads still see it, and
  the next open/close of that path retries the upload. A copy is also saved to
  `~/.lws/recovery/<timestamp>-<path>` so the edits survive even if the mount stops first; delete
  it once the file has been uploaded.
- **Pending changes are uploaded at unmount.** On unmount (and on `Ctrl-C`), files still open with
  unsaved changes are uploaded; any that still fail go to the recovery directory.
- **Saves are uploaded per close.** A program that clears a file, closes it, then reopens it to
  write (PowerShell's `Set-Content` does this) causes two uploads; the server briefly holds an
  empty file in between. An `fsync` uploads at once.
- **Directory rename copies the tree.** LWS has no move primitive, so renaming a directory copies
  every entry to the new name and then deletes the original. It is not atomic, and it costs one
  download and one upload per file. The original is then deleted entry by entry, never with one
  recursive `DELETE`: a listing shows only what you may access, so a recursive delete could remove
  members that were never copied (those make the container's `DELETE` fail instead). If copying
  fails part-way, the original is left intact, and the partial copy is left in place and
  reported. If deleting the original fails part-way, the copy is complete and the rest of the
  original stays where it was. Trees of more than 1000
  entries are refused with `EXDEV`; `mv` then copies them itself, but Windows programs report an
  error.
- **Permissions and ownership are not modeled.** `chmod`/`chown` are accepted as no-ops; files
  report `0644` and directories `0755`, owned by the mounting user.
- **No links, extended attributes or locks.** Symbolic and hard links, extended attributes and
  file locks are not implemented, so those calls fail.
- **Free space is not the server's.** The mount reports a very large volume (about 4 PiB free),
  not the storage's quota; a full server answers an upload with `ENOSPC`.
- **Sizes.** When neither the listing nor a `HEAD` states a file's size (both are optional), a
  one-byte `Range` request supplies it from `Content-Range`. Only if that fails too is the file
  shown as 0 bytes.
- **Timestamps are server-managed.** `utimens` is accepted as a no-op; the displayed
  modification time comes from the listing or the server's `Last-Modified` header. When neither
  gives one, the time the mount started is shown. A file with unsaved changes shows the time of
  its last change.
- **Brief staleness.** Attributes are cached for ~1.5 s, and a directory listing answers "no such
  file" for up to 3 s, so a file *another* client creates may take that long to appear. Your own
  changes invalidate these caches immediately. Expired entries are swept, so the caches stay
  small on long-running mounts.
- **Media types are kept.** Saving a file uploads it with the `Content-Type` the server reported
  when it was read. New files get a type guessed from the extension (`.ttl`→`text/turtle`,
  `.json`→`application/json`, `.png`→`image/png`, …), defaulting to
  `application/octet-stream`. Renaming re-guesses the type only when the old one was evidently
  the old extension's guess, so `photo.tmp` → `photo.png` becomes `image/png`, while an
  extensionless `text/markdown` file keeps its type.
- **Listings stay on the storage's origin.** Listing members and pages are only used on the
  mount's origin; a listing that pages elsewhere fails with `EIO`, and members on other origins
  are ignored. LWS access tokens are only sent within the realm they were issued for.
- **Metadata resources are not exposed.** Each resource's linkset (`rel="linkset"`, user-managed
  links such as a title or license) is not mapped onto the filesystem; changing a file's content
  leaves it alone.

---

## Unmounting

The client mounts in **blocking** mode, so it holds the terminal while running. To unmount,
stop the process (`Ctrl-C`); on the way out it uploads any changes still buffered for open files
(see [Behavior and limitations](#behavior-and-limitations)) and unmounts. Killing the process
outright (`kill -9`, Task Manager) skips that; buffered changes then remain only as `lws-*.buf`
files in the `lws-fuse-*` spool directory under the system temporary directory. Those files are
not named after the paths they belong to, and later mounts do not clean them up.

If a mount is left dangling after an abnormal exit:

- **Linux:** `fusermount -u /tmp/lws`
- **macOS:** `umount /tmp/lws`
- **Windows:** the mapped drive disappears when the process ends; if not, remove it from the
  WinFsp launcher / restart the WinFsp service.

---

## Troubleshooting

| Symptom | Likely cause and fix |
|---------|----------------------|
| Mount command exits immediately with `Can't find winfsp library` | WinFsp is not installed, or not where jnr-fuse looks. Install it, or point `-Djnrfuse.winfsp.path=` at its `winfsp-x64.dll`. On Linux or macOS, install libfuse 2 or macFUSE. |
| `Input/output error` (`EIO`) on most operations | Server unreachable, TLS failure, a `5xx` other than `501`/`503`/`507`, a `409` (other than on a create or a directory delete), or a container representation the client cannot parse. Check the base URL and network; the reason is logged as a warning. |
| `Permission denied` (`EACCES`) | Server returned `401`/`403`/`405`, or no token could be obtained (the log then says "Authentication failed" and why). Provide credentials — the browser login, a controlled identifier, SAML, or a pre-obtained `LWS_TOKEN`. If the log mentions the token exchange, check that the authorization server accepts your credential type and identifier (its `/.well-known/lws-configuration` lists `subject_token_types_supported` and `subject_identifier_types_supported`). A plain refusal (`401`/`403`), like a missing file or a non-empty directory, is only logged at `debug` level. |
| The log says "client-credentials grant yields no ID token" | LWS authorization needs an authentication credential; use the browser login, a refresh token, or a controlled identifier. |
| The log says the server "named the new resource … instead of …" | The server chose its own name for a new file or folder (LWS allows it); it is shown under that name. |
| Everything is empty, `No such file or directory` (`ENOENT`), or listing fails with `EIO` | Base URL wrong, or it points at a file rather than a container. At startup the log may say it "Could not check whether … is a storage description"; listing a file usually logs "Malformed container representation". Point the URL at a container or a storage description. |
| `mkdir` fails with `File exists` (`EEXIST`) | A resource or container already exists at that path. |
| `rmdir` fails with `Directory not empty` (`ENOTEMPTY`) | The container still has members; delete them first. |
| A save fails with `Stale file handle` (`ESTALE`), or for a new file `File exists` (`EEXIST`), or the log says the file "was changed on the server while it was open here" | Someone else changed, deleted or created the file after you opened it. Your version is in `~/.lws/recovery/`; merge it by hand. |
| `Resource temporarily unavailable` (`EAGAIN`) | The server kept answering `429`/`503` through the retries (or asked to wait more than 10 s). Try again later. |
| `No space left on device` (`ENOSPC`) / `File too large` (`EFBIG`) | The server is full (`507`) or refused the size (`413`), or there is no local room to buffer the file. |
| Listing fails and the log says a page is "outside the storage's origin" | The server's paging links point to another host; the client refuses to send your credentials there. |
| Writes seem to "disappear" until close | Expected — buffered writes are uploaded on close, not per `write` call. |
| Too much / too little log output | Logs go to stderr via `slf4j-simple` (bundled in the jar), at `info` by default. Adjust with `-Dorg.slf4j.simpleLogger.defaultLogLevel=debug` (or `warn`, …); `debug` also shows refused, missing and other quiet failures. |
| `WARNING: … sun.misc.Unsafe … terminally deprecated` at startup | Comes from jnr-ffi's `jffi` on JDK 24+. `LWSFileSystem.main` avoids it by setting `-Djffi.unsafe.disabled=true` (jffi then uses JNI for memory access); you only see it when embedding the classes in your own program — set that property there too. |

Errno mapping used by the client: `NOT_FOUND→ENOENT`, `FORBIDDEN→EACCES`, `EXISTS→EEXIST`,
`CHANGED→ESTALE`, `NOT_EMPTY→ENOTEMPTY`, `INVALID→EINVAL`, `TOO_LARGE→EFBIG`,
`NO_SPACE→ENOSPC`, `BUSY→EAGAIN`, `UNSUPPORTED→ENOSYS`, and `CONFLICT` (an HTTP `409`, e.g. a
missing parent container) and everything else `→EIO`. A `409` to a create is reported as
`EEXIST`, and to deleting a directory as `ENOTEMPTY`; a `410 Gone` answering a `DELETE` counts as
deleted. Renames add their own: `EXDEV` (a directory of more than 1000 entries), `EISDIR` (a
file onto a directory), `ENOTDIR` (a directory onto a file), `ENOTEMPTY` (a directory onto a
non-empty one) and `EINVAL` (a directory into its own subtree).

---

## Architecture

The core is a handful of small classes (RDF via Jena, FUSE via jnr-fuse), plus an `auth`
sub-package for OpenID, SSI and SAML. nimbus-jose-jwt (JOSE) signs the DPoP proofs and the
self-issued did:key / controlled-identifier JWTs, and holds their keys.

| Class | Responsibility |
|-------|----------------|
| `LWSFileSystem` | `FuseStubFS` subclass; maps FUSE callbacks to `LWSClient` calls, manages handles, write buffers, the attribute and listing caches, directory rename and the unmount flush, builds the `AuthProvider` from config, and provides `main`. |
| `LWSClient` | The LWS protocol client over `java.net.http`: navigation by containment (path → URI through listings, cached), `POST` create (with a `Slug` name hint), `PUT` update, `DELETE` (also `Depth: infinity`, for library use), `Range` reads, streamed downloads, storage discovery, conditional uploads, bounded retries, and authentication via an `AuthProvider` (401 → new credentials → retry). Thread-safe and FUSE-agnostic. |
| `ContainerListing` | Parses one listing page: `application/lws+json` as plain JSON, or Turtle from earlier-draft servers (Jena). |
| `Links` | Parses `Link` headers (RFC 8288); the client follows `next` pages and reads `type`. |
| `OpenFile` | A per-path, reference-counted write buffer spooled to a temporary file: lazy load, in-place edit/truncate, and a single conditional upload of a snapshot on flush (`PUT`, or `POST` for a new file). |
| `ReadAhead` | Per-handle read-ahead block with a window that grows on sequential reads. |
| `ResourceInfo` | Immutable stat record (`directory`, `size`, `mtimeSeconds`, `contentType`). |
| `LWSException` | Failure kinds (`NOT_FOUND`, `FORBIDDEN`, `CHANGED`, …) that the filesystem layer maps to errno values. |

The `com.ebremer.lws.fuse.auth` sub-package (standard OAuth 2.0 / OIDC, no Solid):

| Class | Responsibility |
|-------|----------------|
| `AuthProvider` | The seam: decorates each request with credentials and sees every response (and each `401`); `anonymous()` and `bearer(token)` factories. |
| `LwsAuthProvider` | LWS authorization: reads the `401` challenge (`as_uri`, `realm`), the authorization server's `lws-configuration`, exchanges a credential for an access token (RFC 8693), keeps one per realm; presents credentials directly to earlier-draft servers. |
| `CredentialSource` | An authentication suite's credential (ID token, self-issued JWT, SAML assertion) with its RFC 8693 token type. |
| `Challenges` | Parses `WWW-Authenticate` challenges. |
| `AuthException` | No credential could be obtained; the client reports it as `EACCES`. |
| `AnonymousAuthProvider` | No-op provider (public servers). |
| `OpenIdAuthProvider` | The OpenID suite: keeps the ID token (the LWS credential), refreshing for a new one; used directly, attaches the provider's access tokens as Bearer or DPoP. |
| `OpenIdDiscovery` | Fetches `.well-known/openid-configuration` for the token/authorization endpoints and checks its `issuer`. |
| `TokenEndpoint` | Token-endpoint requests: client authentication, DPoP proof, and the `use_dpop_nonce` retry. |
| `TokenCache` | Thread-safe access-token cache with pre-expiry refresh. |
| `AuthorizationCodeFlow` | Interactive login: system browser + loopback redirect + PKCE, exchanging the code for tokens (browser step injectable for testing). |
| `Pkce` | RFC 7636 `code_verifier`/`code_challenge` (S256) pair. |
| `BrowserLauncher` | Opens the authorization URL in the system browser (and prints it); only web URLs. |
| `CredentialStore` | Persists the refresh token (`~/.lws/credentials.properties`) for log-in-once reuse. |
| `PrivateFiles` | Writes secret files owner-only from creation (POSIX permissions or a Windows ACL), atomically. |
| `InteractiveLogin` | Log-in-once orchestration: checks the saved refresh token, re-runs the browser login if it is rejected, and saves rotated tokens. |
| `TokenEndpointException` | A token-endpoint refusal with its HTTP status and OAuth `error` code (e.g. `invalid_grant`). |
| `DPoP` | RFC 9449 proof-of-possession JWT generator (optional): ephemeral or persisted key, per-server nonces. |
| `SelfIssuedJwtAuthProvider` | The controlled-identifier suite (HTTPS or `did:key` subject): mints a self-issued ES256 JWT (`iss`=`sub`=`client_id`) whose audience is the authorization server it is exchanged at (minted fresh for each exchange), or `-Dlws.audience` when presented directly (cached). |
| `DidKey` | Derives a `did:key:` P-256 identifier (multicodec + base58btc). |
| `Keys` | Loads/generates and persists a P-256 key: the self-issued identity (`~/.lws/did-key.jwk`, `~/.lws/cid.jwk`) or the browser login's DPoP key (`~/.lws/dpop.jwk`). |
| `SamlAuthProvider` | The SAML suite: the base64url-encoded assertion as the credential. |
| `Base58` | base58btc encoder (used by `did:key`). |

`LWSClient` depends only on standard HTTP, `jakarta.json`, Jena (for Turtle listings), and the W3C LWS vocabulary
(`com.ebremer.ns.LWS`, namespace `https://www.w3.org/ns/lws#`); it can be reused on its own,
without FUSE, as a plain authenticated LWS client.

---

## Native image (experimental)

A GraalVM native-image build is wired up as a Maven profile (needs a GraalVM JDK with
`native-image`):

```bash
mvn -Plws-native package     # produces target/lws (target/lws.exe on Windows)
```

**Important caveat.** The FUSE binding, jnr-fuse, depends on **jnr-ffi**, which builds its native
call stubs by *generating bytecode at runtime* — something native-image's closed-world model does
not support. So a native binary is **not guaranteed to perform the actual mount** without upstream
jnr-ffi native-image support; the non-FUSE paths (the pure `LWSClient` and the login flows) are
unaffected. Treat the profile as scaffolding for experimentation, and use the JVM jar for real
mounting until jnr-ffi native support lands.

The other heavy dependencies (Jena, nimbus-jose-jwt with its shaded Gson, `jakarta.json`) are
reflection-heavy and need **reachability metadata**. None is checked in yet: the project's
`META-INF/native-image/com.ebremer/lws-fuse/` holds only `native-image.properties` with the build
arguments. Generate the metadata by running the tool once under the tracing agent from the
repository root; it writes the files next to `native-image.properties`, where the next build picks
them up:

```bash
java -agentlib:native-image-agent=config-output-dir=src/main/resources/META-INF/native-image/com.ebremer/lws-fuse \
     -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ /tmp/lws
```

Exercise the operations you care about (list, read, write, login) while the agent runs so it
records everything reachable.

---

## A note on the LWS specification

The LWS [core protocol](https://w3c.github.io/lws-protocol/lws10-core/),
[vocabulary](https://w3c.github.io/lws-protocol/lws10-vocab/) and authentication suites are W3C
drafts that still change. This client follows w3c/lws-protocol `ef02548` (2026-10-05):
- Containers are listed as `application/lws+json`: `id`, `type`, `totalItems`, and `items` whose
  members carry `id`, `type`, `format`, `size` and `modified`. The client follows
  `Link: rel="next"` from page to page. The JSON-LD context (`https://www.w3.org/ns/lws/v1`) is
  not published yet, and the specification advises against fetching contexts at runtime, so the
  listing is read as plain JSON with those property names.
- Resources are created with `POST` and a server-assigned URI, updated with `PUT`, and deleted
  with `DELETE`. The specification names no way to suggest a name; the client sends a `Slug`
  header, which servers may ignore. URIs are not assumed to mirror the hierarchy, and URIs the
  server gives (the storage root, pages) are used exactly as given; the hierarchical URI is only a
  fallback (a forbidden listing, a `POST` reply without `Location`, earlier-draft `PUT` creation).
- `ETag`s are only required on `GET` and `HEAD` responses, so the client reads one with `HEAD`
  after a write whose response has none, and keeps its saves conditional.
- Access tokens come from the LWS authorization flow (challenge → `lws-configuration` → token
  exchange). The OpenID, controlled-identifier and SAML suites supply the credentials. Where the
  specification spells something two ways, both are accepted: `id_token` and `id-token` token
  types, and `"https"` and `"https:"` identifier types.
- Not used by a filesystem: linkset metadata resources, `PATCH` (whose baseline format is now JSON
  Patch), notifications, the index services, and access requests and grants. Renaming a file
  copies only its content, so user-managed metadata in its linkset does not follow it.

Earlier drafts used `lws:contains`, in-body `lws:ContainerPage` paging, `PUT` creation and direct
credential presentation; the client still understands those (see
[How it works](#how-it-works)). The vocabulary constants live in the project-local
`com.ebremer.ns.LWS`.

`LWSClient` (storage) and `LwsAuthProvider` (authorization) are where to adjust as the specification firms up.
