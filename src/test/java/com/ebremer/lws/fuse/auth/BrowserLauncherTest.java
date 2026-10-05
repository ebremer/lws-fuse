package com.ebremer.lws.fuse.auth;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.util.List;
import org.junit.jupiter.api.Test;

class BrowserLauncherTest {

    @Test
    void webUrlsMayBeLaunched() {
        for (String ok : List.of("https://idp.example/authorize?x=1", "HTTPS://IDP.EXAMPLE/a",
                "http://127.0.0.1:8080/authorize", "http://localhost/authorize", "http://[::1]:9000/a")) {
            assertTrue(BrowserLauncher.isSafeToLaunch(URI.create(ok)), ok);
        }
    }

    @Test
    void anythingElseIsRefused() {
        for (String bad : List.of("http://idp.example/authorize", "file:///etc/passwd", "file://server/share/x.exe",
                "javascript:alert(1)", "ms-settings:privacy", "smb://host/share", "https:/no-host", "/relative",
                "http://127.0.0.1.evil.example/")) {
            assertFalse(BrowserLauncher.isSafeToLaunch(URI.create(bad)), bad);
        }
        assertThrows(IllegalArgumentException.class, () -> BrowserLauncher.open(URI.create("file:///etc/passwd")));
    }
}
