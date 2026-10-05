# lws-fuse — prioritized TODO

Code-review findings for the LWS FUSE mount tool, and their status. The review started on
2026-10-04, before lws-fuse moved to this repository on 2026-10-05. Notes written before the move
keep their original wording, so their commands (`mvn -pl lws-fuse …`), paths (`lws-fuse/…`,
`../docs/lws-fuse-client.md`, now [`docs/usage.md`](docs/usage.md)) and package names refer to
the earlier layout.

IDs keep the review's original numbering; findings that did not concern lws-fuse are not listed,
which is why the numbering has gaps.

**How this was verified**

- `mvn -pl lws-fuse compile` passes cleanly on JDK 25.0.4 (GraalVM CE) / Maven 3.9.16.
- Scratch probes (not committed) confirmed the `LWSClient.toUri` escape (P0-3) and that JDK 25's
  `HttpClient` strips `Authorization` on cross-origin redirects (relevant to P2-S1).
- jnr-fuse 0.5.8 bytecode inspected: it registers its own unmount shutdown hook and runs FUSE
  multi-threaded (no `-s`), so callbacks in `LWSFileSystem` really are concurrent.

**Paths.** Classes live in `src/main/java/com/ebremer/lws/fuse/` (auth classes in its `auth/`
subpackage); `File.java:N` references point into that tree. The package was
`is.halcyon.storage.fuse.lws` before P3-8. Docs live in [`docs/`](docs/).

**Priorities.** **P0** security exposure or silent data loss — do now · **P1** correctness ·
**P2** hardening, robustness, performance · **P3** docs and small cleanups.

---

## P0 — Do now

- [x] **P0-3 FUSE path → URI mapping can escape the mounted container.**
  *Fixed:* `toUri` now percent-encodes each segment itself and appends it to the base text, never
  resolving a relative reference. Dot and empty segments are rejected with `INVALID`, and a
  literal `%` is always encoded (previously a name like `a%41` was sent as `aA`).
  `LWSClientUriTest` covers it; 12 of its 17 cases fail against the old code.
  Original finding (code at `ddc3e8b`): `LWSClient.toUri`
  (`LWSClient.java:449-450`) builds `new URI(null, null, rel, null)`, so a first path segment
  containing `:` is parsed as a URI *scheme*. Verified with base `https://lws.example/alice/`:
  - `/x:/etc/passwd` resolves to `https://lws.example/etc/passwd`.
  - `/a:b.txt` throws an NPE, which surfaces as `EIO`.

  So a container named `x:` on the server (e.g. created by a collaborator) sends every
  `HEAD`/`GET`/`PUT`/`DELETE` beneath it to arbitrary paths on the origin, with the user's
  credentials. For example, `rm -rf` on that folder deletes data outside the base.
  Fix: percent-encode each segment explicitly (or prefix `./`), then assert the result is under
  `base` and fail with `EINVAL` otherwise. Add unit tests (P1-7).
- [x] **P0-4 A failed upload at close silently discards the file.**
  *Fixed:* when the final upload fails, `release` keeps the dirty `OpenFile` registered. Reads
  keep seeing the edits, and the next open/flush/release of the path retries the PUT. It also
  writes an owner-only copy to `~/.lws/recovery/<timestamp>-<path>` (configurable via the new
  `LWSFileSystem(client, recoveryDir)` constructor) and logs at ERROR, which stays invisible
  until P1-1 lands. A successful release now removes only its own entry
  (`openFiles.remove(path, f)`). `LWSFileSystemReleaseTest` covers the fail → retry → succeed
  path; the recovery directory is documented in `../docs/lws-fuse-client.md`.
  Original finding (code at `ddc3e8b`): `LWSFileSystem.release`
  (`LWSFileSystem.java:224-230`) removes the `OpenFile` in `finally` even when `flush` throws.
  `release`'s errno never reaches the application, so any transient 5xx or timeout at
  close loses the whole buffered file — and the error log is also discarded today (P1-1).
  Fix: keep dirty buffers alive for a later retry, or spool them to a local recovery
  directory, and log the loss loudly.

## P1 — Correctness

- [x] **P1-1 Ship a logging backend.**
  *Fixed:* `slf4j-simple` 2.0.17 (matching the `slf4j-api` that Jena brings) is now a runtime
  dependency, marked optional so code reusing `LWSClient` as a library keeps its own logging
  choice. It is bundled in the fat jar and configured by `src/main/resources/simplelogger.properties`
  (stderr, `info`, Jena at `warn`). The did:key identity is printed to stdout.
  Original finding (line numbers predate the fix): The only SLF4J artifacts on the `lws-fuse` classpath are
  `slf4j-api` and `jcl-over-slf4j` (via Jena), with no provider. SLF4J 2 therefore falls back
  to NOP, and every `log.error`/`log.info` in the fat jar is discarded. That includes I/O
  failures and the `did:key` identifier, which `../docs/lws-fuse-client.md` tells users to copy
  from the startup log. Fix: add `slf4j-simple` (or `slf4j-jdk14`) as a runtime dependency, and
  print the DID to stdout regardless.
- [ ] **P1-2 Prove a real mount works on JDK 25.** *Windows is done; Linux and macOS are still
  open.* (jnr-fuse 0.5.8 and jnr-ffi 2.2.16 predate JDK 25.)
  - *Done:* the fat jar's manifest sets `Enable-Native-Access: ALL-UNNAMED`. Verified: launched
    via `-cp` (manifest ignored), JDK 25 prints jffi's `System::load` restricted-method warning;
    via `-jar` it does not.
  - *Done:* live mount on Windows 11 + WinFsp with GraalVM CE 25.0.4, against `MockLwsServer`,
    mounted both at a drive letter and at a directory. Verified:
    - listing, read, write, append, mkdir, rename and Unicode names;
    - rmdir of a non-empty folder is refused, and delete works;
    - delete-while-open does not resurrect the file;
    - a 3 MB binary round trip has a matching SHA-256;
    - each saved file produces exactly one PUT.
  - *Open:* a live mount on Linux (libfuse 2) and macOS (macFUSE). The WSL Ubuntu on this machine
    has `/dev/fuse` but no JDK or `libfuse.so.2`.
  - JDK 25's warning about jffi's terminally deprecated `sun.misc.Unsafe` use is gone since
    P2-R16.
- [x] **P1-3 Persist rotated refresh tokens.**
  *Fixed:*
  - `OpenIdAuthProvider.Config.refreshTokenListener` receives every newly issued refresh token.
    The new `auth/InteractiveLogin` (moved out of `LWSFileSystem`) saves each one to the
    `CredentialStore`.
  - A saved token is checked at startup (`OpenIdAuthProvider.prefetch()`). On `invalid_grant`
    (new `TokenEndpointException`) the browser login runs again; other token-endpoint errors are
    reported, not masked.
  - With `-Dlws.refreshToken`, a rotation logs a one-time warning that the passed value is spent.

  Covered by `InteractiveLoginTest` and `OpenIdAuthProviderTest`.
  Original finding (line numbers predate the fix): `OpenIdAuthProvider.fetchToken` keeps a rotated
  `refresh_token` only in memory (`auth/OpenIdAuthProvider.java:138-140`). The
  `CredentialStore` is written once, at first login (`LWSFileSystem.java:603-605`).
  - With an IdP that rotates refresh tokens, the saved token is already spent at the next
    mount. Rotation is expected for public clients per RFC 9700, and the browser login is a
    public client by default.
  - Reuse detection can then revoke the whole token family, forcing `-Dlws.forceLogin=true`.

  Fix: give the provider a persistence callback. Also fall back to the browser flow
  automatically on `invalid_grant`.
- [x] **P1-4 Key open-file state by file handle, not by path.**
  *Fixed:*
  - `open`/`create` allocate a handle id, store it in `fi.fh`, and map it to the shared
    `OpenFile`; every file operation resolves its file through the handle.
  - The reference is taken inside the map update (`attach`), and cleanup after the last close is
    conditional (`forget`), so an open and a release can no longer interleave badly.
  - `unlink`, and a rename that replaces an open file, *detach* that file: its handles keep their
    data but never upload it. A renamed open file follows its new name (`OpenFile.moveTo`).
  - `write` without a handle returns `EBADF`, and unlinking a created-but-not-yet-uploaded file
    succeeds.

  Covered by `LWSFileSystemTest` and checked on a live WinFsp mount.
  Original finding (line numbers predate the fix): `openFiles` is a
  `Map<String, OpenFile>` (`LWSFileSystem.java:79`) and `fi.fh` is never used. As a result:
  - `unlink` drops the buffer of a still-open file (`:278`).
  - A `release` racing an `open` on the same path re-retains an object it then removes from the
    map (`:243`).
  - After unlink + recreate, a stale handle's `release` decrements the *new* file's refcount.
  - `rename` onto a dirty open target is later clobbered when that handle flushes.
  - A `write` without a matching `open` creates a refs=0 entry (`:203`).

  Fix: allocate an id in `open`/`create` and store it in `fi.fh`. Keep a path → handles index
  only for `getattr`/`read` coherence, and use `openFiles.remove(path, f)`-style conditional
  removal.
- [x] **P1-5 A corrupt key file silently replaces the user's identity.**
  *Fixed:* `Keys.loadOrGenerateP256` never overwrites. An unreadable, corrupt, public-only or
  non-P-256 key file now fails with a clear error and is left untouched. A new key is written with
  `CREATE_NEW`; if another process wins that race, its key is used. Covered by `KeysTest`. (The
  chmod-after-write window remains P2-S4.)
  Original finding (line numbers predate the fix): `Keys.loadOrGenerateP256` (`auth/Keys.java:30-33`) swallows any parse error, generates a new
  key, and overwrites the file (`:41`).
  - For did:key that is a new DID, which loses access to everything authorized for the old
    one.
  - For CID, the published key no longer matches.

  Fix: fail loudly and never overwrite an existing key file.
- [x] **P1-6 Every 401 forces a token refresh.**
  *Fixed:* `AuthProvider.onUnauthorized` now receives the rejected request. `OpenIdAuthProvider`
  refreshes only if the rejected token is still the cached one and at least 10 s old, and never on
  `insufficient_scope`. If another request has already replaced the token, it just retries.
  `TokenCache.invalidate(rejected, now, minAge)` is compare-and-clear. Covered by `TokenCacheTest`
  and `OpenIdAuthProviderTest`.
  Original finding (line numbers predate the fix): `OpenIdAuthProvider.onUnauthorized`
  (`auth/OpenIdAuthProvider.java:85-88`) always invalidates and returns `true`.
  - Every 401 costs a token-endpoint round-trip under the `TokenCache` lock, serializing all
    FUSE threads. This includes "authenticated but not permitted", which some servers send as
    401.
  - Browsing a folder of forbidden files hammers the IdP.
  - A concurrent 401 can also throw away a token another thread just fetched.

  Fix: refresh only if the rejected token is still the current one and not brand new (or the
  challenge says `error="invalid_token"`). Make `invalidate` compare-and-clear.
- [x] **P1-7 Add tests and CI.**
  *Done:* 73 tests in 10 test classes (`mvn -pl lws-fuse test`), built on in-JVM fakes:
  `MockLwsServer` (also runnable standalone for manual mounts), `auth/MockOpenIdServer` and
  `SimulatedBrowser`.
  - Coverage: URI mapping; listing, pagination and `lws:items`; Range 206/200/416; `OpenFile`
    buffering; the FUSE callbacks; `TokenCache`; the did:key spec vector; `Keys`;
    `OpenIdAuthProvider`; PKCE login; `InteractiveLogin`.
  - Deliberately re-breaking four of the P1 fixes made 7 tests fail, so the tests do guard them.
  - `.github/workflows/lws-fuse.yml` runs `mvn -pl lws-fuse verify` on JDK 25 with libfuse2
    installed. **It has not run yet**; it needs a push.

## P2 — Hardening, robustness, performance

All P2 items were addressed on 2026-10-05, except where noted. The suite has 141 tests
(`mvn -pl lws-fuse verify`), all passing.
- *Mutation check:* breaking eight of these fixes on purpose (S1, S2, S5, S6, S7c, R2, R4, R7)
  made 14 tests fail.
- *Live check:* a WinFsp mount on JDK 25 was re-run against `MockLwsServer`; the measurements are
  under each item.

Each original finding below is kept for reference; its line numbers predate the fix.

### Security hardening

- [x] **P2-S1 Don't hand credentials to foreign origins during pagination.**
  *Fixed:* `LWSClient.list` follows `lws:first`/`lws:next` only to URIs on the base's origin
  (scheme, host, effective port, no user-info) and under its base path, after normalizing dot
  segments. Any other link fails the listing with `EIO` and a clear message; the link is never
  requested. Covered by `LWSClientTest.listRefusesPageLinksOutsideTheMountedContainer` (another
  host, another path, `/alice/../bob/`, another scheme).
  Original finding: `LWSClient.list` follows any `lws:next`/`lws:first` URI the server returns
  (`LWSClient.java:182-186`), and `send` always calls `auth.authorize` (`:410`). A listing can
  therefore send the bearer, DPoP, or SAML credential to another origin. (Plain HTTP redirects
  are safe: JDK 25 strips `Authorization` cross-origin.) Fix: only follow pages on the base's
  origin, ideally under the base path.
- [x] **P2-S2 Validate the authorization URL before launching it.**
  *Fixed:* `BrowserLauncher.isSafeToLaunch` accepts only absolute `https` URLs, or `http` to a
  literal loopback host (`localhost`, `127.x.x.x`, `[::1]`), with no DNS lookup. Both
  `AuthorizationCodeFlow.login` (before starting the listener) and `BrowserLauncher.open` refuse
  anything else. Covered by `BrowserLauncherTest` and
  `AuthorizationCodeFlowTest.anAuthorizationEndpointThatIsNotAWebUrlIsNeverOpened`.
  Original finding: `BrowserLauncher.open` passes the discovered `authorization_endpoint` to
  `rundll32 url.dll,FileProtocolHandler`, `xdg-open`, or `open` (`auth/BrowserLauncher.java:31-37`).
  Those launch any scheme (`file:`, custom protocol handlers), so a hostile or compromised issuer
  gets a local-launch primitive. Fix: require `https`, allowing `http` only for loopback.
- [x] **P2-S3 Keep secrets off the command line.**
  *Fixed:* the token, client secret and refresh token are looked up in this order (`LWSFileSystem.secret`):
  1. a file named by `-Dlws.tokenFile`, `-Dlws.clientSecretFile` or `-Dlws.refreshTokenFile`
     (whitespace trimmed);
  2. the inline property, which still works but logs a warning that other users can see it;
  3. the environment variables `LWS_TOKEN`, `LWS_CLIENT_SECRET` and `LWS_REFRESH_TOKEN`.

  The usage text, README and `../docs/lws-fuse-client.md` lead with the file and environment
  forms. Covered by `SecretOptionsTest`.
  Original finding: `lws.clientSecret`, `lws.refreshToken` and `lws.token` are read as `-D`
  system properties (`LWSFileSystem.java:599, 625, 643`). Other local users can see those in the
  process list (`ps`, `/proc/<pid>/cmdline`). Fix: accept them from environment variables or
  files (e.g. `-Dlws.clientSecretFile=`), and say so in the docs.
- [x] **P2-S4 Create secret files owner-only from the start.**
  *Fixed:* the new `auth/PrivateFiles` applies permissions at creation, never with a chmod
  afterwards. It is used by `CredentialStore`, `Keys` and the recovery copies.
  - POSIX: files are created `rw-------` and new directories `rwx------`.
  - Windows: an owner-only ACL attribute is used. Checked with `icacls`: such a file inside a
    directory readable by `BUILTIN\Users` lists only its owner, while a default file there
    inherits `Users:(RX)`.
  - `CredentialStore` now writes a temporary file and moves it into place atomically; new keys
    are written with `CREATE_NEW`.
  - Existing directories are left alone.

  Covered by `PrivateFilesTest` (on Windows: the owner is the only principal granted anything).
  Original finding: `CredentialStore.saveRefreshToken` (`auth/CredentialStore.java:46-49`) and
  `Keys` (`auth/Keys.java:57, 64`) write with the default umask (typically 0644) and `chmod`
  afterwards. That leaves a window where the refresh token or private key is readable, and
  `~/.lws` itself is created 0755. Fix: create files with `PosixFilePermissions.asFileAttribute`
  (`rw-------`, directory `rwx------`), writing to a temp file and moving it into place
  atomically; on Windows, set an owner-only ACL or document the reliance on profile ACLs.
- [x] **P2-S5 Harden the loopback callback.**
  *Fixed:* `AuthorizationCodeFlow`'s listener now behaves as follows.
  - It answers only `GET /callback`, and a request with the wrong `state` gets a 400 and is
    otherwise ignored; the login keeps waiting.
  - Messages are HTML-escaped, and the page is served with a restrictive
    `Content-Security-Policy`.
  - `error_description` is shown alongside `error`.
  - An RFC 9207 `iss` parameter must match the issuer. It is required when the metadata
    advertises `authorization_response_iss_parameter_supported`.

  Covered by `AuthorizationCodeFlowTest`: forged callback, escaping, wrong/missing/right `iss`.
  Original finding: `AuthorizationCodeFlow` echoes the attacker-controllable `error` parameter into
  HTML unescaped (`auth/AuthorizationCodeFlow.java:111, 246`). It also completes the login on the
  *first* hit to `/callback` whatever its `state` (`:124`), so any stray request aborts the login.
  Fix: HTML-escape the message; ignore wrong-`state` requests and keep waiting; show
  `error_description`. Optionally check RFC 9207 `iss`.
- [x] **P2-S6 Check the discovered issuer.**
  *Fixed:* `OpenIdDiscovery.discover` rejects metadata whose `issuer` differs from the configured
  one; only a single trailing `/` difference is tolerated. Malformed metadata is reported as an
  `IOException` rather than a runtime error. Covered by
  `AuthorizationCodeFlowTest.discoveryRejectsMetadataForAnotherIssuer` /
  `discoveryToleratesATrailingSlash`.
  Original finding: `OpenIdDiscovery.discover` (`auth/OpenIdDiscovery.java:46`) never compares the
  returned `issuer` with the configured one, as OIDC Discovery §4.3 requires.
- [x] **P2-S7 Finish DPoP.**
  *Fixed:*
  - **(a) Nonces.** `DPoP` remembers the latest `DPoP-Nonce` per origin and puts it in later
    proofs; `AuthProvider.onResponse` feeds it every response.
    - A token-endpoint `use_dpop_nonce` is retried once. That logic lives in the new
      `auth/TokenEndpoint`, now shared by the code exchange and the refresh/client-credentials
      grants.
    - A resource-server `401` with `use_dpop_nonce` is retried with the nonce, without
      discarding the token.
    - **Signature change:** `AuthProvider.onUnauthorized` now takes the `HttpResponse`.
  - **(b) Binding.** With DPoP, the browser login sends `dpop_jkt` and a DPoP-proved code
    exchange, so the saved refresh token is bound to the key. That key is persisted
    owner-only at `~/.lws/dpop.jwk`; client credentials keep an ephemeral key.
  - **(c) `htu`.** `htu` is built from the raw (still-encoded) path.
  - **(d) Downgrade.** A `Bearer` token issued despite DPoP is used, and a warning is logged
    once.

  Covered by `OpenIdAuthProviderTest` (raw `htu`, resource-server nonce, token-endpoint nonce,
  downgrade) and `AuthorizationCodeFlowTest` (`dpop_jkt` and a proved exchange, nonce retry).
  Original finding:
  - **(a) No nonce support.** Nothing handles `DPoP-Nonce` / `use_dpop_nonce` from the token
    endpoint or the resource server, so servers that require nonces always fail.
  - **(b) The persisted refresh token is unbound.** The authorization-code exchange
    (`AuthorizationCodeFlow.exchangeCode`) isn't DPoP-bound, so the saved refresh token is a plain
    bearer credential. Binding it also requires persisting the DPoP key, which is per-process
    today (`auth/DPoP.java:43-53`, `LWSFileSystem.java:665-667`).
  - **(c) `htu` can mismatch.** It is rebuilt from the *decoded* path (`auth/DPoP.java:87`) and
    can differ from the wire URI for names containing `%XX`.
  - **(d) Silent downgrade.** A `Bearer` reply to a DPoP request is accepted without a warning
    (`auth/OpenIdAuthProvider.java:87`).

### Robustness and performance

- [x] **P2-R1 Servers that ignore `Range` make reads O(n²).**
  *Fixed:* `LWSClient.readRange` reads a `200` reply only up to the end of the requested range
  and then abandons the transfer. It reports `rangeIgnored`; the open file is then marked and read
  through its buffer, so it is downloaded once. Covered by
  `LWSFileSystemTest.aServerThatIgnoresRangeIsDownloadedOnlyOnce` (at most 2 GETs for 1 MB read
  in 4 KiB pieces).
  Original finding: on `200`, `LWSClient.read` downloads the full body and slices it
  (`LWSClient.java:303-313`), once per FUSE read (≤128 KiB). A 1 GB file is downloaded about
  8,000 times. Fix: detect this once and buffer the body (temp file) for the open handle.
- [x] **P2-R2 Sequential reads cost one HTTP round-trip each.**
  *Fixed:* each handle has a `ReadAhead`. It fetches at least 128 KiB, doubles the window on
  each sequential miss up to 4 MiB, resets it on a seek, and serves later reads from the block.
  *Measured on the live WinFsp mount:* hashing a 3 MB file the mount had not seen before took
  7 GETs, down from 771. Covered by `ReadAheadTest` and
  `LWSFileSystemTest.sequentialSmallReadsAreServedByReadAhead`.
  Original finding: measured on the live WinFsp mount, hashing a 3 MB file took 775 `GET`s,
  because WinFsp reads in 4 KiB pieces. There is no read-ahead (`LWSFileSystem.java:173`). Fix:
  add a per-handle read-ahead window that grows on sequential access.
- [x] **P2-R3 `ls -l` costs one `HEAD` per file, and every miss costs two.**
  *Fixed:*
  - Listings now yield each member's size, modification time and media type. They come from
    `schema:size`, `dcterms:modified` and `dcterms:format` (the current vocabulary), or the
    older `lws:sizeInBytes` / `lws:mediaType`.
  - `readdir` seeds the attribute cache with them.
  - The names in a listing are kept for 3 s. A lookup of any other name in that directory is
    answered `ENOENT` without a request.
  - Every local change invalidates the parent's listing.

  *Measured live:* `Get-ChildItem` of 21 files took 1 GET and 3 HEADs, and probes for
  `desktop.ini`, `Thumbs.db` and a swap file took none. Covered by
  `LWSClientTest.listStatesMemberSizeDateAndMediaType` and
  `LWSFileSystemTest.aListingSeedsAttributesAndAnswersForMissingNames`.
  Original finding: `readdir` seeds only directories (`LWSFileSystem.java:148-151`).
  `LWSClient.stat` tries the resource, then the container (`LWSClient.java:142-159`). Seed file
  attributes from the listing when the server provides `lws:sizeInBytes` and a modified date
  (the vocabulary is already in `com.ebremer.ns.LWS`), and answer ENOENT probes (Explorer's
  `desktop.ini`, editors' swap files) from the cached parent listing.
- [x] **P2-R4 No lost-update protection.**
  *Fixed:* an `OpenFile` keeps the `ETag` it was downloaded at, or the one its last upload
  returned.
  - It uploads with `If-Match`, or with `If-None-Match: *` if it was created locally. Weak or
    missing ETags give an unconditional `PUT`. `mkdir` also sends `If-None-Match: *`.
  - A `412` becomes `EXISTS` or `CHANGED` (`ESTALE`).
  - On the final close, a conflict saves the local version to the recovery directory, logs an
    error, and drops it from the mount, which then shows the server's version.

  *Deviation from the suggested fix:* the buffer is not kept for retries after a conflict. Every
  retry would fail with `412` again, and succeeding would overwrite the other writer. The local
  version lives on in the recovery copy instead.

  Covered by `OpenFileTest`: concurrent change, concurrent create, ETag after save.
  `LWSFileSystemTest.aConcurrentChangeOnTheServerIsNotOverwritten` and
  `LWSClientTest.conditionalPutsDetectConcurrentChanges` also cover it.
  Original finding: writes have no `ETag`/`If-Match`, creates have no `If-None-Match: *`, and
  `mkdir` is check-then-PUT (`LWSFileSystem.java:267-270`), so concurrent clients silently
  overwrite each other. Fix: capture the ETag when loading a buffer and send `If-Match` on
  flush; on `412`, keep the buffer (P0-4) and report the conflict.
- [x] **P2-R5 Saving a file rewrites its media type.**
  *Fixed:* an upload uses the `Content-Type` the server reported (when downloaded, or from `HEAD`
  or the listing when opened); only new files are guessed by extension. A rename keeps the
  server's type unless it equals the old name's guess, in which case the new name is guessed
  (`photo.tmp` → `photo.png` becomes `image/png`). Covered by
  `LWSFileSystemTest.savingKeepsTheServersMediaType` and
  `renamingRederivesAGuessedMediaTypeButKeepsAnExplicitOne`, plus `OpenFileTest`.
  Original finding: every flush PUTs with `guessContentType(path)` (`LWSClient.java:366-391`).
  Editing an extensionless or unusually typed resource turns it into `application/octet-stream`
  and flips the `lws:DataResource` Link header. Fix: remember the server's `Content-Type` for
  existing resources and reuse it.
- [x] **P2-R6 Whole files are buffered in heap.**
  *Fixed:* `OpenFile` spools to a temporary file in a per-mount `lws-fuse-*` directory, which is
  deleted at unmount. The 2 GiB cap is gone.
  - Downloads stream to disk (`LWSClient.download`). A `Content-Length` larger than the free
    space fails with `ENOSPC` before transferring.
  - Neither download nor upload holds the file's monitor. An upload sends a snapshot, and a
    change made meanwhile keeps the file dirty.
  - A file rename, a handle-less truncate and a directory rename stream through temporary
    files.
  - Spool files are deleted when the file is closed.

  Covered by `OpenFileTest.theBufferLivesInASpoolFileThatCloseDeletes` and
  `aChangeDuringAnUploadKeepsTheFileDirty`.
  Original finding: `OpenFile` keeps the full resource in a `byte[]` (2 GiB cap).
  `ensureLoaded` downloads without a size check while holding the object monitor
  (`OpenFile.java:94-107`), blocking `getattr`/`read` on that file for the whole transfer.
  `rename` and handle-less `truncate` also `readAll` into memory (`LWSFileSystem.java:338, 418`).
  Fix: spool to temp files, check `Content-Length` before loading, and don't hold the lock across
  network I/O.
- [x] **P2-R7 Truncate-to-zero does needless or risky I/O.**
  *Fixed:*
  - `OpenFile.truncate(…, 0)` resets the buffer without downloading.
  - A handle-less `truncate(path, 0)` registers a pending empty file. An open within 2 s picks
    it up, so the write that follows produces a single upload; otherwise a scheduled task
    uploads it.
  - A handle-less truncate to a non-zero size downloads, resizes and uploads conditionally.

  Covered by `OpenFileTest.truncatingToZeroDoesNotDownload` and `LWSFileSystemTest` (truncate
  then write: one PUT and no GET; a lone truncate is uploaded; a non-zero truncate).
  *Note:* WinFsp and Linux's `O_TRUNC` both truncate through an open handle (`ftruncate`), so the
  deferral only matters for path truncation such as `truncate(1)`.
  Original finding: `ftruncate(…, 0)` downloads the whole file first (`OpenFile.java:150`).
  Handle-less `truncate(…, 0)`, which is what an `O_TRUNC` save issues first, immediately PUTs an
  empty body (`LWSFileSystem.java:412-413`). That costs an extra round-trip and leaves an empty
  server copy if the save then fails. Fix: skip the load when `size == 0`, and defer the empty PUT
  into an `OpenFile`.
- [x] **P2-R8 Container listings must be Turtle.**
  *Fixed:* listings are requested with `Accept: text/turtle, application/ld+json;q=0.9`. They are
  parsed by the response `Content-Type`, falling back to Turtle when the type is missing or not an
  RDF triples syntax. Jena 6 bundles the Titanium JSON-LD parser, so no dependency was added.
  Covered by `LWSClientTest.listParsesJsonLd`. A listing whose JSON-LD `@context` is remote makes
  Jena fetch it; untested against a real server.
  Original finding: `fetchTurtle` always parses as `Lang.TURTLE` (`LWSClient.java:193, 203`),
  ignoring the response `Content-Type`. A server answering in JSON-LD makes every directory `EIO`.
  Fix: choose the parser via `RDFLanguages.contentTypeToLang` and send an `Accept` header listing
  both formats.
- [x] **P2-R9 Auth failures become `EIO` with a stack trace on every operation.**
  *Fixed:*
  - `TokenCache.get` throws the new `auth/AuthException`, keeping the interrupt flag when the
    fetch was interrupted.
  - `LWSClient.send` authorizes inside its handling and maps it to `FORBIDDEN` (`EACCES`).
  - The failure is logged once at ERROR, then at DEBUG until authentication works again, which
    is logged too. Nothing is sent without credentials.

  Covered by `LWSClientTest.failingToObtainCredentialsIsPermissionDenied`, `TokenCacheTest`, and
  `OpenIdAuthProviderTest.anUnreachableTokenEndpointIsAnAuthFailure`.
  Original finding: `TokenCache.get` wraps failures in `IllegalStateException`
  (`auth/TokenCache.java:52-53`), which also drops the interrupt flag. `LWSClient.send` calls
  `authorize` outside its `try` (`LWSClient.java:410`), so `LWSFileSystem` logs at ERROR and
  returns `EIO`. Fix: map these to `LWSException(FORBIDDEN)` (`EACCES`), log once, and restore
  the interrupt flag.
- [x] **P2-R10 Errno mapping gaps and no retry.**
  *Fixed:*
  - New kinds and their errnos: `413` → `EFBIG`, `507` → `ENOSPC`, `429`/`503` → `EAGAIN`, `412`
    → `ESTALE` (`EEXIST` for create-only requests), and `405` → `EACCES`.
  - A `409` is no longer `EEXIST`; it is `EIO`, with the reason logged.
  - `LWSClient.send` retries `429`/`503` and dropped connections up to 3 attempts. It waits for
    `Retry-After` when that is at most 10 s, otherwise uses 0.5 s / 1 s backoff. Timeouts are
    not retried, and each attempt is re-authorized so a DPoP proof is never replayed. The policy
    is adjustable via `LWSClient.retryPolicy`.
  - `LWSFileSystem` now logs failures a user would care about at WARN; it used to drop every
    `LWSException` silently.

  Covered by `LWSClientTest` (retry with `Retry-After`, bounded retries, a too-long `Retry-After`,
  the status table).
  Original finding: in `LWSException.fromStatus` (`LWSException.java:47-57`), map 413 → `EFBIG`,
  507 → `ENOSPC`, and 429/503 → `EAGAIN`; a 409 on PUT is not "already exists", so it shouldn't
  map to `EEXIST`; add bounded retry with `Retry-After`/backoff for idempotent requests.
- [x] **P2-R11 The attribute cache never evicts.**
  *Fixed:* once the attribute and listing caches together exceed 4096 entries, adding an entry
  sweeps out expired ones, at most once a second. Covered by
  `LWSFileSystemTest.expiredAttributesAreSwept` (5000 entries down to 1).
  Original finding: `attrCache` entries are only ever overwritten (`LWSFileSystem.java:87, 465`),
  so a long-running mount that walks a large tree grows without bound. Fix: bound the cache or
  sweep expired entries.
- [x] **P2-R12 Dirty buffers are lost at unmount.**
  *Fixed:* `LWSFileSystem.shutdown()` flushes every registered or open file and saves failures
  and conflicts to the recovery directory. It then deletes the spool directory and reports how
  many files could not be saved. It runs from `destroy()` (FUSE unmount) and from a JVM shutdown
  hook that `main` registers for Ctrl-C, and is idempotent. Covered by
  `LWSFileSystemTest.shutdownUploadsChangesStillOpen`.
  *Not live-verified:* I could not deliver a Ctrl-C to a background WinFsp mount from the test
  session (the console-attach attempt left the process running), so the hook path itself is
  untested. Killing the process outright still loses buffered changes; they remain in the spool
  directory.
  Original finding: there is no `destroy()` override; jnr-fuse's shutdown hook unmounts on Ctrl-C
  and drops still-open dirty buffers silently. Fix: flush them, or at least report them.
- [x] **P2-R13 The default Unix mount point doesn't exist.**
  *Fixed:* on Linux/macOS, `main` creates a missing mount directory, logging that it did. It exits
  with a clear message if the path exists but is not a directory. WinFsp creates its own mount
  point, so Windows is unchanged. Not exercised: no Linux mount yet (P1-2).
  Original finding: libfuse needs `/tmp/lws` (`LWSFileSystem.java:758`) to already exist, so a
  first run fails with an obscure error. Fix: create it, or print a clear message.
- [x] **P2-R14 Directory rename fails on Windows.**
  *Fixed:* `rename` of a directory now does the copy in the daemon.
  1. It walks the tree; more than 1000 entries returns `EXDEV`, as before.
  2. It flushes open files under the directory.
  3. It creates the new containers and copies each file, keeping media types.
  4. Only then does it delete the old tree bottom-up and re-map open files to their new paths.

  A failure part-way leaves the original intact and reports the partial copy. Renaming into its
  own subtree gives `EINVAL`, and onto a non-empty directory `ENOTEMPTY`. *Live:*
  `Rename-Item` of a folder with a subfolder works on WinFsp. Covered by `LWSFileSystemTest`
  (tree move with an open file, the guards, the size limit).
  Original finding: `rename` returns `EXDEV` for directories (`LWSFileSystem.java:330-333`). `mv`
  copes, but Explorer on WinFsp just fails. Consider a guarded recursive copy + delete inside the
  daemon.
- [x] **P2-R15 Minor attribute quirks.**
  *Fixed:*
  - `readdir` lists files created here but not yet uploaded.
  - A changed file reports the time of its last change, instead of "now" on every `getattr`.
  - An unknown modification time (seeded directories, servers without `Last-Modified`) is shown
    as the mount's start time, not 1970.

  Covered by `LWSFileSystemTest` (a created file is listed; the change time is stable).
  Original finding: a created-but-unflushed file doesn't appear in `readdir`; a dirty file reports
  `mtime = now` on every `getattr` (`LWSFileSystem.java:457`); directories seeded by `readdir`
  show `mtime 0` (`:150`).
- [x] **P2-R16 Plan for jffi's `sun.misc.Unsafe` use.**
  *Fixed:* jffi has a switch, `-Djffi.unsafe.disabled=true`, that selects its JNI memory
  implementation instead of `sun.misc.Unsafe`. It is present in jffi 1.3.13 and in the latest
  release, 1.4.3; jnr-ffi 2.3.3 still defaults to Unsafe.
  - `LWSFileSystem.main` sets the switch before jnr-fuse loads; jnr-fuse's static initializer
    doesn't touch jffi, so the setting takes effect.
  - *Live:* the WinFsp mount no longer prints the warning, and since the Unsafe path is never
    taken, a JDK that removes those methods won't break it.
  - Code that embeds the classes must set the property itself (documented).
  - Longer term, a FUSE binding on the FFM API would drop jnr entirely.

  Original finding: on JDK 25, every mount prints "A terminally deprecated method in
  sun.misc.Unsafe has been called" from `com.kenai.jffi.UnsafeMemoryIO$UnsafeMemoryIO64`
  (jnr-ffi 2.2.16). A future JDK will remove these memory-access methods. Track a jnr-ffi release
  that drops them; until then, document (or set via a launcher script)
  `--sun-misc-unsafe-memory-access=allow`, since a jar manifest cannot set it.
- [x] **P2-R17 Closing a handle that never wrote uploaded other handles' changes.**
  *Found and fixed during the P2 live test.* Windows opens a separate handle to delete a file, and
  closing it (FUSE `flush`) uploaded the shared dirty buffer just before the `DELETE`.
  - Now a handle records whether it wrote or truncated, and `flush` uploads only for such a
    handle.
  - `fsync` and the last handle's `release` still upload whatever is pending.
  - *Live:* deleting a file that another process holds open with unsaved data now sends only
    the `DELETE`.

  Covered by `LWSFileSystemTest.closingAHandleThatDidNotWriteUploadsNothing` /
  `closingAHandleThatWroteUploads`.
- [ ] **P2-R18 Every close uploads, so clear-then-write saves upload twice.** *Found during the P2
  live test.* PowerShell's `Set-Content` truncates the file and closes it, then reopens it to
  write. The mount uploads at each close, so the server briefly holds an empty file, and the
  content goes up twice. A short write-back delay after the last close (as in the deferred
  truncate) would merge the two. It would also weaken close-to-open visibility and the immediate
  error on close, so it is a design decision. Documented under "Behavior and limitations".

## LWS 1.0 conformance (2026-10-05)

The client was brought up to date with the LWS 1.0 drafts at w3c/lws-protocol `9b03b32`
(2026-09-28). Behavior for earlier drafts is kept as automatic fallbacks.
- *Verified:* 166 tests pass. The mocks now follow the current protocol, with switches for
  earlier-draft servers, non-hierarchical URIs and servers that rename new resources.
- *Mutation check:* breaking each of ten new behaviors fails at least one test.
- *Live:* WinFsp mounts of the mock, both the current protocol in non-hierarchical-URI mode
  (mounted through its storage description) and earlier-draft mode.

- [x] **C-1 Container listings are `application/lws+json`.** The client sends
  `Accept: application/lws+json, application/ld+json;q=0.9, application/json;q=0.8, text/turtle;q=0.5`.
  - The JSON shape (`items` with `id`, `type`, `format`, `size`, `modified`) is read as plain JSON
    (`ContainerListing`). A `type` may be a string or an array, compact or a full IRI; ids are
    resolved against the page.
  - The JSON-LD context URL returns 404, and the spec advises against runtime fetching, so it is
    never fetched.
  - Turtle from earlier drafts is still parsed with Jena: `lws:items`/`lws:contains`, `schema:size`
    over http or https, `dcterms:*`.
- [x] **C-2 Pagination by `Link` headers.** `rel="next"` is followed on the storage's origin;
  in-body `lws:first`/`lws:next` is kept for earlier drafts.
  *Change:* pages and members must be on the same origin as the storage. They no longer need to
  be under the mounted path, since LWS URIs are opaque.
- [x] **C-3 Navigation by containment.** URIs need not mirror the hierarchy, so a path is resolved
  from the root through each container's listing; a member's name is its URI's last segment.
  - Resolutions are cached (LRU, 100k paths), and listings are kept for 2 s.
  - A `404` drops the cached resolution.
  - If a listing is forbidden, the client probes the hierarchical URI instead.
  - `stat` is answered from the parent's listing, with a `HEAD` only when the listing omits a file's
    size.
- [x] **C-4 Create with `POST` + `Slug`.** (*Since corrected:* `Slug` is a hint, not LWS; see C-13.)
  - New files and folders are `POST`ed to the parent container with a `Slug` (and
    `Link: <lws:Container>; rel="type"` for folders); `Location` gives the new URI.
  - If the server picks another name, it is logged and the open file is re-registered under it.
  - A create-only upload first checks the name is free.
  - `PUT` only updates. A `404` on an `If-Match` update means the file was deleted meanwhile
    (→ conflict); without a precondition the file is created again.
  - Servers answering `405`/`501` to `POST` get `PUT` + `If-None-Match: *` (remembered after the
    first try).
  - `POST` is never retried after a dropped connection; only `429`/`503` are retried.
- [x] **C-5 Recursive delete.** Directory renames remove the old tree with one
  `DELETE` + `Depth: infinity`, falling back to bottom-up deletes when the server refuses.
  *Superseded by C-19:* renames now always delete bottom-up.
- [x] **C-6 Storage discovery.** If the mounted URL serves a storage description (`application/lws+cid`,
  or JSON typed `Storage`), its `StorageRoot` service endpoint is mounted.
- [x] **C-7 LWS authorization (token exchange).** The new `auth/LwsAuthProvider`:
  - parses the `401` challenge (`Bearer as_uri="…", realm="…"`) and checks that the request is in
    the realm;
  - reads the authorization server's `/.well-known/lws-configuration` (RFC 8414 path insertion,
    then appended), whose `issuer` must match;
  - exchanges the suite's credential at its token endpoint (RFC 8693: `resource` = realm,
    `subject_token`, `subject_token_type`), and keeps one access token per realm, renewed 30 s
    before expiry or when the storage rejects it (unless issued under 10 s ago);
  - only uses `https` (or loopback `http`) authorization servers; `-Dlws.authServer` pins one;
  - warns if the server's `subject_token_types_supported` / `subject_identifier_types_supported`
    leave out the credential.

  Servers whose `401` names no `as_uri` (earlier drafts) get the credential directly, as before.
- [x] **C-8 Credentials per suite.**
  - **OpenID:** the ID token (`…:token-type:id_token`); a refresh obtains a new one; the browser
    login seeds the provider with its tokens. Client credentials yield no ID token and fail with a
    clear message under LWS authorization.
  - **Controlled identifier:** a JWT with `aud` = the authorization server, cached per audience.
    Its subject is an HTTPS URI or a `did:key` (the suite accepts DID subjects).
  - **SAML:** the base64url assertion (`…:token-type:saml2`).
- [x] **C-9 Vocabulary.** `com.ebremer.ns.LWS` gains `StorageResource`, `Storage`, `StorageRoot`,
  `OpenIdProvider`, `capability` and `storage`; terms dropped from the vocabulary are kept,
  labelled as earlier-draft.
- [ ] **C-10 Not verified against a real server.** No public LWS 1.0 server or authorization server
  was available; every check above is against the mocks. The official test suite
  (`lws-contrib/lws-test-suite`) tests servers, not clients. Two places where it disagrees with
  the spec text:
  - Its token-type fixture uses `id-token`, where RFC 8693 and the OpenID suite use `id_token`.
    The client sends `id_token`, and since C-21 accepts `id-token` in metadata as the same type.
  - Its listing fixture uses `contentType`, where the spec uses `format`. The client accepts both.
- [ ] **C-11 Not implemented (not needed by a filesystem):** linkset metadata resources
  (`rel="linkset"`, `PATCH`, `Prefer: set-linkset`), `304` revalidation, notifications, the index
  services, and access requests and grants. A linkset could later back extended attributes.
  - *Spec change (w3c/lws-protocol `ef02548`, 2026-10-05):* the baseline `PATCH` format is now
    JSON Patch (RFC 6902, `application/json-patch+json`), advertised in `Accept-Patch`, for
    resources and linksets alike. JSON Merge Patch (`application/merge-patch+json`) is only an
    optional alternative. Any `PATCH` support should send JSON Patch.
- [ ] **C-12 Servers that ignore `Slug`.** They make the mount show generated names, since names
  come from URIs and the container representation has no title. Nothing to do on the client unless
  the spec adds a name property.

### Review against w3c/lws-protocol `ef02548` (2026-10-05)

The only spec change after `9b03b32` is `ef02548` (JSON Patch replaces JSON Merge Patch as the
baseline `PATCH` format), which the client does not use. A full review of the client against the
spec as of `ef02548` (core protocol, vocabulary and discovery, authorization and the three
authentication suites) found these. *Verified:* 187 tests pass, with 21 new ones; reverting each of
ten of the fixes below fails at least one of them.

- [x] **C-13 `Slug` is no longer part of LWS** (removed 2026-08-21, #224, before `9b03b32`; C-4
  predates that). The server assigns identifiers and the spec names no hint mechanism. The client
  still sends `Slug` as a common hint; code comments and docs no longer present it as LWS.
- [x] **C-14 The storage root is used exactly as named.** A discovered `serviceEndpoint`, or the
  URL a container answers at (after redirects), is no longer given a trailing `/`; URIs are
  opaque. Hierarchical fallback URIs add a `/` separator after a root that lacks one. A typed URL
  without a trailing `/` that answers `404` is retried with one. A storage description whose root
  is missing or malformed now stops the tool instead of being mounted as a container.
- [x] **C-15 `ETag`s are only required on `GET`/`HEAD`** (since 2026-09-14, #228). When a write
  response has none, a `HEAD` fetches it, so later saves of an open file stay conditional
  (previously every save after the first was unconditional on such servers).
- [x] **C-16 One `405` no longer switches creation to `PUT` for the session.** `PUT` creation is
  tried only while no `POST` has worked, and adopted only if it succeeds; otherwise the `POST`'s
  refusal is reported. (A read-only container used to make every later create fail with `ENOENT`.)
- [x] **C-17 Sizes from a range request.** When neither the listing nor `HEAD` gives a size, a
  one-byte `Range` request reads it from `Content-Range` (servers must support ranges); such files
  used to show as empty.
- [x] **C-18 Smaller core fixes.**
  - A `Location` on another origin is not followed (credentials would go there); the resource is
    found through the listing, if at all.
  - `409` on a create → `EEXIST`; `409` on deleting a file → `EIO` (was `ENOTEMPTY`); `410` on
    `DELETE` counts as deleted.
  - Pagination URIs are used as given (no normalization).
  - Member names are decoded per segment, so `%2F` no longer splits a name.
  - A storage description with a single `service` object (not an array) is understood.
- [x] **C-19 Directory renames delete the original bottom-up.** A listing need only show what the
  client may access, so `Depth: infinity` could remove members that were never copied. Unseen
  members now make the container's `DELETE` fail, and the rest of the original is kept.
- [x] **C-20 Authorization hardening.**
  - Every conforming challenge in a `401` is considered; the first with a containing realm and an
    acceptable authorization server is used (one that is not pinned no longer blocks the rest).
  - The earlier-draft fallback is decided per origin, and never used for an origin that has sent
    an LWS challenge, so a storage cannot downgrade the client into presenting the credential.
  - A credential type the server's `subject_token_types_supported` omits is not sent.
  - A non-`Bearer` access token is refused (RFC 6749 §7.1).
  - The credential is addressed to the metadata's `issuer` (a self-issued JWT's `aud`), and each
    exchange mints a new self-issued JWT, so no `jti` is reused.
- [x] **C-21 Spec ambiguities handled both ways.** `id-token` and `id_token` token types;
  `"https"` and `"https:"` identifier types; metadata at the origin root as a third candidate.
- [x] **C-22 ID token diagnostics.** An unsigned (`alg: none`) ID token is refused; a missing `azp`,
  a non-URI `sub` or a non-URI client id is warned about once.
- [ ] **C-23 Audience restriction of OpenID and SAML credentials.** Any `https` authorization server
  a storage names receives the ID token or SAML assertion, which another server could replay
  (Security Considerations; the OpenID suite suggests audience-restricted credentials, RFC 8707).
  `-Dlws.authServer` pins one server. Options: ask the provider for an ID token whose `aud`
  includes the server, refuse credentials whose `aud` does not, or pin the first server per
  storage.
- [ ] **C-24 Renames lose linkset metadata.** Copy-then-delete moves only content; user-managed
  links (title, license, …) stay with the deleted original. Could read the linkset and send it as
  `Link` headers on the creating `POST`. The old file's `DELETE` is also not conditional.
- [ ] **C-25 Name collisions.** Two members whose URIs end in the same segment show as one (the
  first wins), and a URI with an empty last segment is not shown. Could disambiguate.
- [ ] **C-26 Weak `ETag`s.** With only weak validators, saves are unconditional; `If-Unmodified-Since`
  on the `Last-Modified` would still catch most conflicts. Range reads could also use `If-Range`.

## P3 — Docs and small cleanups

- [x] **P3-6 Docs have drifted from the code.**
  *Fixed:*
  - In `../docs/lws-fuse-client.md`, the configuration table now lists `lws.auth`, `lws.keyFile`,
    `lws.cid`, `lws.kid`, `lws.samlAssertion` and `lws.audience` with their defaults. The
    mode-selection paragraph says `lws.auth` takes precedence. The usage block was updated with
    P2-S3.
  - The Architecture section says nimbus-jose-jwt signs both the DPoP proofs and the self-issued
    SSI JWTs.
  - Both docs give the same tracing-agent command, run from the repository root with
    `config-output-dir=lws-fuse/src/main/resources/META-INF/native-image/generated` and
    `-jar lws-fuse/target/lws-fuse-1.0.0.jar`.
  - The `LWSClient` class javadoc was fixed with P2.

  Original finding: the client doc's usage block and configuration table omitted the SSI/SAML
  options; its Architecture section said nimbus-jose-jwt is "used only for DPoP"; the
  tracing-agent output path differed between the two docs; the `LWSClient` javadoc described a
  fixed bearer token "supplied to the constructor".
- [x] **P3-8 Small cleanups.**
  *Done:*
  - `LWSClient.LWS_ITEMS` went with P2.
  - `DidKey.generate()` is deleted; its one caller, a test, now uses
    `Keys.loadOrGenerateP256(null)`.
  - The packages are renamed `is.halcyon.storage.fuse.lws(.auth)` → `com.ebremer.lws.fuse(.auth)`,
    main and test, with imports re-sorted. The POM's `exec.mainClass`, the shade and native
    `mainClass`, and every command in README and `../docs/` follow. The jar's `Main-Class` is
    `com.ebremer.lws.fuse.LWSFileSystem`. A WinFsp smoke test of the renamed jar (list, read,
    write, directory rename) passed.
  - `experimental` keeps its `is.halcyon.*` packages (P4-16).

  The old paths show as deleted and the new ones as untracked until committed; `git add -A`
  records them as renames.
  Original finding: `LWSClient.LWS_ITEMS` duplicates `LWS.items`; `DidKey.generate()` is unused;
  the `is.halcyon.*` package names outlived the Halcyon dependency.
