---
title: Building from source
nav_order: 3
---

# Building lws-fuse from source

This page covers building the project and producing the runnable / native artifacts. For **using**
the mounted drive (commands, authentication, troubleshooting), see the [usage guide](usage.md).

---

## Prerequisites

- **JDK 25** or newer. The project sets `maven.compiler.release=25`, so a Java 25 toolchain is
  required. GraalVM CE 25 is recommended if you also want to try the native image.
- **Maven** 3.9 or newer. Both minimums are checked by the Maven Enforcer plugin before anything
  is compiled, and the build fails with a message otherwise.
- To run the `LWSFileSystemTest` tests or mount anything: a **FUSE driver** —
  [WinFsp](https://winfsp.dev/) (Windows), libfuse 2 (Linux), or [macFUSE](https://osxfuse.github.io/).
- For a **native image**: a GraalVM JDK that provides `native-image`.

The dependencies are Jena (RDF, for Turtle listings), jnr-fuse (FUSE), nimbus-jose-jwt (JOSE) and
`jakarta.json`, plus `slf4j-simple` for logging; all come from Maven Central. Every plugin version
is pinned in the POM's `<pluginManagement>`, and the enforcer rejects an unpinned one.

---

## Compile

```bash
mvn compile
```

## Build the runnable jar

```bash
mvn -Pjar package
```

This runs the Maven Shade plugin and produces **`target/lws-fuse-1.0.0.jar`** — a single fat jar
bundling every dependency.

## Run the FUSE tool

```bash
java -jar target/lws-fuse-1.0.0.jar <lws-base-url> [mount-point]
```

The jar's `Main-Class` is `LWSFileSystem`, so `java -jar` launches it directly. A `-cp` launch
(`java --enable-native-access=ALL-UNNAMED -cp target/lws-fuse-1.0.0.jar com.ebremer.lws.fuse.LWSFileSystem …`)
also works, but needs that flag, because the manifest's native-access entry only applies to
`java -jar` (see [Known caveats](#known-caveats)). Full command-line options, authentication
modes, and examples are in the [usage guide](usage.md). Running with no arguments prints the usage
banner.

---

## Maven profiles

| Profile | Command | Result |
|---------|---------|--------|
| `jar` | `mvn -Pjar package` | Shaded runnable fat jar → `target/lws-fuse-1.0.0.jar` |
| `lws-native` | `mvn -Plws-native package` | GraalVM native image of the FUSE tool → `target/lws` (`lws.exe` on Windows). **Experimental** — see below |

### Native image (`lws-native`)

Requires a GraalVM JDK with `native-image`. The reflection-heavy dependencies (Jena,
nimbus-jose-jwt with its shaded Gson, `jakarta.json`) need reachability metadata, and none is
checked in yet: `src/main/resources/META-INF/native-image/com.ebremer/lws-fuse/` holds only
`native-image.properties` with the build arguments. Generate the metadata by running the tool once
under the tracing agent; it is written next to that file, where the next build picks it up:

```bash
java -agentlib:native-image-agent=config-output-dir=src/main/resources/META-INF/native-image/com.ebremer/lws-fuse \
     -jar target/lws-fuse-1.0.0.jar <base> <mount>
```

**Caveat:** jnr-fuse depends on jnr-ffi, which builds native call stubs by generating bytecode at
runtime — unsupported by native-image's closed world. A native binary therefore may not perform the
actual FUSE mount without upstream jnr-ffi support; the non-FUSE paths are unaffected. See the
[native-image note](usage.md#native-image-experimental).

---

## Verifying a change

```bash
mvn test
```

Most tests run against in-JVM mocks: `MockLwsServer`, which follows the LWS 1.0 core protocol,
with switches for earlier-draft servers, URIs that don't mirror the hierarchy, and servers that
name new resources themselves; and `auth/MockOpenIdServer`, an OpenID provider that is also an
LWS authorization server. The rest are plain unit tests. They cover:
- the LWS client: `application/lws+json` and Turtle listings, `Link` and in-body paging, listing
  pages on another origin refused, navigation by containment, `stat` from the parent listing,
  sizes from a range request, `POST` creation (the `PUT` fallback, and a single container
  refusing `POST`), conditional updates (also when write responses carry no `ETag`), a
  `Location` on another origin, recursive delete, storage discovery (a root without a trailing
  `/`, a typed URL missing one), Range reads and streamed downloads, retries, status →
  error-kind mapping, and credential failures;
- path → URI mapping: percent-encoding, and paths that must never escape the mounted container;
- LWS authorization: the `401` challenge (several challenges, realm containment), authorization-
  server metadata and the credential types it accepts, token exchange and renewal, non-`Bearer`
  tokens refused, no direct credential for a server that speaks LWS authorization, and the
  credential of each suite (ID token, self-issued JWT, SAML);
- the FUSE callbacks: handles, file and directory rename (including the `EXDEV` limit), unlink,
  failed and conflicting uploads, truncation, the attribute cache, media types, read-ahead and
  servers that ignore `Range`, the unmount flush — against current, earlier-draft and
  non-hierarchical servers;
- the spooled write buffer and the read-ahead window;
- authentication: secret options (file, property, environment), token caching and refresh, the
  PKCE login and its hardening, DPoP nonces, log-in-once persistence, owner-only secret files, and
  key and did:key handling.

`LWSFileSystemTest` needs a FUSE library (WinFsp / libfuse / macFUSE) because jnr-fuse loads it
when the filesystem object is created; without one it is skipped. CI
(`.github/workflows/ci.yml`) runs the suite on Linux with libfuse installed.

To try a real mount without an LWS server, start the mock server from the test classes, then mount
it:

```bash
java -cp target/test-classes com.ebremer.lws.fuse.MockLwsServer 8765   # [flat] [legacy]
java -jar target/lws-fuse-1.0.0.jar http://127.0.0.1:8765/alice/ L:\        # Windows
java -jar target/lws-fuse-1.0.0.jar http://127.0.0.1:8765/alice/ /tmp/lws   # Linux, macOS
```

`flat` gives created resources URIs that don't mirror the hierarchy; `legacy` behaves like an
earlier draft (no `POST`, Turtle listings). Mounting `http://127.0.0.1:8765/storage` instead
exercises storage discovery.

---

## Known caveats

- **jnr-fuse 0.5.8 on JDK 25.** A live mount is verified on Windows 11 with WinFsp (GraalVM CE
  25.0.4). Verified operations:
  - listing, reads, writes, append, mkdir, delete, and Unicode names;
  - file and directory rename, including from PowerShell (`Rename-Item`);
  - a 3 MB binary round trip (7 GETs to read it back).

  **Linux (libfuse) and macOS (macFUSE) mounts are not yet verified.**
  - The fat jar's manifest sets `Enable-Native-Access: ALL-UNNAMED`, which silences JDK 25's
    restricted-method warning for jnr-ffi's native loading. When launching with `-cp` (from
    classes, or from the jar) instead of `java -jar`, pass `--enable-native-access=ALL-UNNAMED`
    yourself.
  - jnr-ffi's `jffi` uses terminally deprecated `sun.misc.Unsafe` memory access by default, which
    JDK 24+ warns about and a future JDK will remove. `LWSFileSystem.main` sets
    `jffi.unsafe.disabled=true` before jnr-fuse loads, so jffi uses its JNI implementation
    instead; the warning is gone on a live mount. Code that embeds the classes should set
    `-Djffi.unsafe.disabled=true` itself.

---

## Documentation site

The `docs/` folder is the project's [GitHub Pages](https://ebremer.github.io/lws-fuse/) site:
Jekyll with the [Just the Docs](https://just-the-docs.com/) theme, configured in
`docs/_config.yml`. A push to `main` that changes `docs/` runs `.github/workflows/pages.yml`,
which builds the site with GitHub's own Pages toolchain and publishes it. The repository's Pages
source has to be set to **GitHub Actions** once, under *Settings → Pages*.

Each page is plain Markdown with a short front-matter block (`title`, `nav_order`). Link between
pages by their `.md` file names, as before; the build rewrites them to `.html`. Links to files
outside `docs/` (the README, sources) must be full GitHub URLs, since only `docs/` is
published.

To preview a change locally, build with the image the workflow uses and serve the result:

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/docs:/site" -v "$PWD/target/site:/out" \
  -e PAGES_REPO_NWO=ebremer/lws-fuse --entrypoint sh ghcr.io/actions/jekyll-build-pages:v1.0.13 \
  -c 'cd "$BUNDLE_APP_CONFIG" && bin/github-pages build --source /site --destination /out/lws-fuse'
python3 -m http.server 4000 --directory target/site   # then open http://localhost:4000/lws-fuse/
```
