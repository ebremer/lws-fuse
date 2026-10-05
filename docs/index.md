---
title: Home
nav_order: 1
permalink: /
---

# lws-fuse

Mount a [W3C Linked Web Storage (LWS)](https://w3c.github.io/lws-protocol/) server as a local
drive, then browse and edit your storage with `ls`, `cat`, an editor, `cp` or drag-and-drop, like
any folder.
{: .fs-6 .fw-300 }

[Get started](#quick-start){: .btn .btn-primary .fs-5 .mb-4 .mb-md-0 .mr-2 }
[Usage guide](usage.md){: .btn .fs-5 .mb-4 .mb-md-0 }

---

## Highlights

- **A drive letter or a directory.** Mounts a storage, or any container in it, through
  [WinFsp](https://winfsp.dev/) on Windows, libfuse 2 on Linux, or
  [macFUSE](https://osxfuse.github.io/) on macOS.
- **Current LWS, older servers too.** Follows the
  [LWS 1.0 core protocol](https://w3c.github.io/lws-protocol/lws10-core/) as of 2026-10-05:
  `application/lws+json` listings, `POST` creation, navigation by containment, storage
  discovery. Servers that implement earlier drafts keep working.
- **LWS authorization.** Exchanges an OpenID Connect ID token (from a browser login), a
  self-issued controlled-identifier JWT (including a `did:key` subject) or a SAML assertion for
  an access token at the storage's authorization server.
- **Edits are not silently lost.** A save is conditional on the version that was read, and one
  that conflicts with a change made elsewhere, or fails, is kept in `~/.lws/recovery/` rather than
  dropped.
- **Pure LWS/HTTP.** Depends only on the JDK, Apache Jena, jnr-fuse, nimbus-jose-jwt,
  `jakarta.json` and SLF4J — no Solid libraries and no server framework.

## Quick start

You need **Java 25** or newer, a user-space filesystem driver ([WinFsp](https://winfsp.dev/),
libfuse 2 or [macFUSE](https://osxfuse.github.io/)), Maven 3.9 or newer, and the URL of an LWS
storage or container.

```bash
mvn -Pjar package                                                         # -> target/lws-fuse-1.0.0.jar
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ L:\        # Windows
java -jar target/lws-fuse-1.0.0.jar https://example.org/alice/ /tmp/lws   # Linux, macOS
```

The mount runs in the foreground; `Ctrl-C` unmounts. On Linux and macOS the mount directory is
created if missing. To sign in, add the `-Dlws.*` options for your credential — see
[Authentication](usage.md#authentication).

## Documentation

| Page | What it covers |
|------|----------------|
| [Usage guide](usage.md) | How the mount maps onto LWS, running it, authentication, everyday use, the configuration reference, behavior and limitations, troubleshooting, and the architecture. |
| [Building from source](building.md) | Prerequisites, Maven profiles (fat jar, experimental native image), running the tests, mounting the mock server, and known caveats. |

## Project status

- The LWS client, the authentication flows and the FUSE callbacks have unit tests against mock
  LWS and OpenID / authorization servers (`mvn test`).
- A live mount on JDK 25 is verified on Windows (WinFsp). Linux and macOS mounts are not yet
  confirmed — see [Known caveats](building.md#known-caveats).
- Not yet tested against a real LWS 1.0 server or authorization server, only against the mocks.
- The GraalVM native image is experimental — see
  [Native image](usage.md#native-image-experimental).

## Specifications

- [LWS core protocol](https://w3c.github.io/lws-protocol/lws10-core/) and
  [vocabulary](https://w3c.github.io/lws-protocol/lws10-vocab/)
- Authentication suites:
  [OpenID Connect](https://w3c.github.io/lws-protocol/lws10-authn-openid/),
  [SSI controlled identifier](https://w3c.github.io/lws-protocol/lws10-authn-ssi-cid/),
  [SAML](https://w3c.github.io/lws-protocol/lws10-authn-saml/)
