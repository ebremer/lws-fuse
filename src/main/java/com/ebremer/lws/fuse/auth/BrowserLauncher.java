package com.ebremer.lws.fuse.auth;

import java.net.URI;
import java.util.Locale;

/**
 * Opens a URL in the user's default system browser — the external user-agent that RFC 8252
 * ("OAuth 2.0 for Native Apps") recommends over an embedded web-view. The URL is always printed
 * as well, so login still works over SSH/headless sessions or if auto-open fails.
 *
 * <p>Uses the OS "open" command (no AWT/Desktop dependency, which keeps the tool headless-friendly
 * and lighter for native-image). Those commands launch <em>any</em> scheme — {@code file:},
 * custom protocol handlers — so only web URLs are passed to them: {@code https}, or {@code http}
 * to a loopback address (see {@link #isSafeToLaunch}). The URL comes from the identity provider's
 * discovery document, which must not be able to start local programs.
 *
 * @author Erich Bremer
 */
public final class BrowserLauncher {

    private BrowserLauncher() {
    }

    /**
     * Best-effort open of {@code uri} in the system browser; always prints it for manual use.
     *
     * @throws IllegalArgumentException if {@code uri} is not one {@link #isSafeToLaunch} accepts
     */
    public static void open(URI uri) {
        if (!isSafeToLaunch(uri)) {
            throw new IllegalArgumentException("Refusing to open " + uri
                    + ": only https (or http to a loopback address) URLs are launched");
        }
        System.out.println();
        System.out.println("Open this URL in your browser to log in:");
        System.out.println("  " + uri);
        System.out.println();
        try {
            String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
            ProcessBuilder pb;
            if (os.contains("win")) {
                pb = new ProcessBuilder("rundll32", "url.dll,FileProtocolHandler", uri.toString());
            } else if (os.contains("mac") || os.contains("darwin")) {
                pb = new ProcessBuilder("open", uri.toString());
            } else {
                pb = new ProcessBuilder("xdg-open", uri.toString());
            }
            pb.inheritIO().start();
        } catch (Exception e) {
            // The URL was printed above; the user can open it manually.
        }
    }

    /** An absolute {@code https} URL with a host, or an {@code http} one whose host is loopback. */
    public static boolean isSafeToLaunch(URI uri) {
        if (uri == null || !uri.isAbsolute() || uri.isOpaque() || uri.getHost() == null) {
            return false;
        }
        String scheme = uri.getScheme().toLowerCase(Locale.ROOT);
        return scheme.equals("https") || (scheme.equals("http") && isLoopback(uri.getHost()));
    }

    /** A loopback host by its literal name; no DNS lookup is made. */
    static boolean isLoopback(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        return h.equals("localhost") || h.equals("[::1]") || h.matches("127(\\.\\d{1,3}){3}");
    }
}
