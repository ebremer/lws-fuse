package com.ebremer.lws.fuse.auth;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parses {@code WWW-Authenticate} headers (RFC 9110 §11.6.1) into challenges: an auth scheme and
 * its parameters, e.g. {@code Bearer as_uri="https://as.example", realm="https://storage.example/s1"}.
 * One header may carry several comma-separated challenges, and a server may send several headers.
 *
 * @author Erich Bremer
 */
public final class Challenges {

    /** One challenge; parameter names are lower-cased. */
    public record Challenge(String scheme, Map<String, String> params) {
        public String param(String name) {
            return params.get(name.toLowerCase(Locale.ROOT));
        }
    }

    private Challenges() {
    }

    public static List<Challenge> parse(List<String> headerValues) {
        List<Challenge> out = new ArrayList<>();
        for (String v : headerValues) {
            parse(v, out);
        }
        return out;
    }

    private static void parse(String s, List<Challenge> out) {
        int[] pos = {0};
        Challenge current = null;
        while (true) {
            skip(s, pos, " \t,");
            if (pos[0] >= s.length()) {
                return;
            }
            String token = token(s, pos);
            if (token.isEmpty()) {
                pos[0]++;   // unexpected character: skip it
                continue;
            }
            skip(s, pos, " \t");
            boolean isParam = pos[0] < s.length() && s.charAt(pos[0]) == '=' && current != null
                    && !(pos[0] + 1 < s.length() && s.charAt(pos[0] + 1) == '=');   // "==" ends a token68
            if (isParam) {
                pos[0]++;
                skip(s, pos, " \t");
                current.params().putIfAbsent(token.toLowerCase(Locale.ROOT), value(s, pos));
            } else if (pos[0] < s.length() && s.charAt(pos[0]) == '=' && current != null) {
                skip(s, pos, "=");   // token68 padding, e.g. "Basic dXNlcjpw=="
            } else {
                current = new Challenge(token, new LinkedHashMap<>());
                out.add(current);
            }
        }
    }

    private static void skip(String s, int[] pos, String chars) {
        while (pos[0] < s.length() && chars.indexOf(s.charAt(pos[0])) >= 0) {
            pos[0]++;
        }
    }

    private static String token(String s, int[] pos) {
        int start = pos[0];
        while (pos[0] < s.length()) {
            char c = s.charAt(pos[0]);
            if (c == ' ' || c == '\t' || c == ',' || c == '=' || c == '"') {
                break;
            }
            pos[0]++;
        }
        return s.substring(start, pos[0]);
    }

    private static String value(String s, int[] pos) {
        if (pos[0] < s.length() && s.charAt(pos[0]) == '"') {
            StringBuilder v = new StringBuilder();
            pos[0]++;
            while (pos[0] < s.length() && s.charAt(pos[0]) != '"') {
                if (s.charAt(pos[0]) == '\\' && pos[0] + 1 < s.length()) {
                    pos[0]++;
                }
                v.append(s.charAt(pos[0]++));
            }
            pos[0]++;   // closing quote
            return v.toString();
        }
        return token(s, pos);
    }
}
