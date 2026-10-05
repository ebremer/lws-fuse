package com.ebremer.lws.fuse;

import java.net.URI;
import java.net.http.HttpHeaders;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Parses HTTP {@code Link} headers (RFC 8288), which LWS uses for pagination
 * ({@code rel="next"}), resource types ({@code rel="type"}), containment ({@code rel="up"}) and
 * the storage ({@code rel="https://www.w3.org/ns/lws#storage"}). The client follows {@code next}
 * and reads {@code type}.
 *
 * @author Erich Bremer
 */
final class Links {

    /** One link: its target (resolved against the response URI), relation types and other parameters. */
    record Link(URI target, List<String> rels, Map<String, String> params) {
        boolean hasRel(String rel) {
            for (String r : rels) {
                if (r.equalsIgnoreCase(rel)) {
                    return true;
                }
            }
            return false;
        }
    }

    private Links() {
    }

    /** Every link in every {@code Link} header of a response to {@code requestUri}. */
    static List<Link> parse(HttpHeaders headers, URI requestUri) {
        List<Link> out = new ArrayList<>();
        for (String value : headers.allValues("Link")) {
            parseValue(value, requestUri, out);
        }
        return out;
    }

    /** The target of the first link with relation {@code rel}, or {@code null}. */
    static URI first(HttpHeaders headers, URI requestUri, String rel) {
        for (Link l : parse(headers, requestUri)) {
            if (l.hasRel(rel)) {
                return l.target();
            }
        }
        return null;
    }

    /** Whether any {@code rel="type"} link targets {@code typeIri}. */
    static boolean hasType(HttpHeaders headers, URI requestUri, String typeIri) {
        for (Link l : parse(headers, requestUri)) {
            if (l.hasRel("type") && l.target() != null && l.target().toString().equals(typeIri)) {
                return true;
            }
        }
        return false;
    }

    private static void parseValue(String s, URI base, List<Link> out) {
        int i = 0;
        int n = s.length();
        while (i < n) {
            int lt = s.indexOf('<', i);
            if (lt < 0) {
                return;
            }
            int gt = s.indexOf('>', lt + 1);
            if (gt < 0) {
                return;
            }
            URI target = resolve(base, s.substring(lt + 1, gt).trim());
            Map<String, String> params = new LinkedHashMap<>();
            i = gt + 1;
            // parameters: ; name=value | ; name="quoted value" | ; name — up to the next top-level ','
            while (i < n) {
                char c = s.charAt(i);
                if (c == ',') {
                    i++;
                    break;
                }
                if (c != ';') {
                    i++;
                    continue;
                }
                i++;
                int nameStart = i;
                while (i < n && s.charAt(i) != '=' && s.charAt(i) != ';' && s.charAt(i) != ',') {
                    i++;
                }
                String name = s.substring(nameStart, i).trim().toLowerCase(Locale.ROOT);
                String value = "";
                if (i < n && s.charAt(i) == '=') {
                    i++;
                    while (i < n && s.charAt(i) == ' ') {
                        i++;
                    }
                    if (i < n && s.charAt(i) == '"') {
                        StringBuilder v = new StringBuilder();
                        i++;
                        while (i < n && s.charAt(i) != '"') {
                            if (s.charAt(i) == '\\' && i + 1 < n) {
                                i++;
                            }
                            v.append(s.charAt(i++));
                        }
                        i++;   // closing quote
                        value = v.toString();
                    } else {
                        int vs = i;
                        while (i < n && s.charAt(i) != ';' && s.charAt(i) != ',') {
                            i++;
                        }
                        value = s.substring(vs, i).trim();
                    }
                }
                if (!name.isEmpty()) {
                    params.putIfAbsent(name, value);
                }
            }
            String rel = params.getOrDefault("rel", "");
            out.add(new Link(target, rel.isBlank() ? List.of() : Arrays.asList(rel.trim().split("\\s+")), params));
        }
    }

    private static URI resolve(URI base, String ref) {
        try {
            return base == null ? URI.create(ref) : base.resolve(URI.create(ref));
        } catch (IllegalArgumentException malformed) {
            return null;
        }
    }
}
