package com.ebremer.lws.fuse;

import com.ebremer.ns.LWS;
import jakarta.json.Json;
import jakarta.json.JsonArray;
import jakarta.json.JsonNumber;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonString;
import jakarta.json.JsonValue;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.LocalDateTime;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import org.apache.jena.rdf.model.Literal;
import org.apache.jena.rdf.model.Model;
import org.apache.jena.rdf.model.ModelFactory;
import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.RDFNode;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;
import org.apache.jena.rdf.model.Statement;
import org.apache.jena.rdf.model.StmtIterator;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.riot.RDFLanguages;
import org.apache.jena.riot.RiotException;
import org.apache.jena.vocabulary.RDF;

/**
 * Parses one page of a container listing.
 *
 * <p>The LWS container representation (media type {@code application/lws+json}, equivalently
 * {@code application/ld+json} or {@code application/json}) is a fixed JSON-LD shape:
 * <pre>
 * { "@context": "https://www.w3.org/ns/lws/v1", "id": "…", "type": "Container", "totalItems": 2,
 *   "items": [ { "id": "…", "type": "DataResource", "format": "text/plain", "size": 47,
 *                "modified": "2025-11-24T12:00:00Z" }, … ] }
 * </pre>
 * It is read as plain JSON with those property names: the context document is not published, and
 * the specification advises clients not to fetch contexts at runtime. A {@code type} may be a
 * string or an array, in compact ({@code Container}), prefixed ({@code lws:Container}) or full
 * IRI form; {@code id}s are resolved against the page URI.
 *
 * <p>Servers following earlier drafts send Turtle (or other RDF) instead; that is parsed with Jena,
 * accepting {@code lws:items} or the older {@code lws:contains}, member metadata as
 * {@code schema:size}/{@code dcterms:modified}/{@code dcterms:format} (or the older
 * {@code lws:sizeInBytes}/{@code lws:mediaType}), and in-body {@code lws:first}/{@code lws:next}
 * paging links.
 *
 * @author Erich Bremer
 */
final class ContainerListing {

    /** A member as listed: URI, kind, and the metadata the listing stated ({@code -1}/{@code 0}/{@code null} if not). */
    record Entry(URI uri, boolean container, long size, long mtimeSeconds, String format) {}

    /**
     * @param entries    the members on this page
     * @param bodyNext   a next/first page linked from an RDF body (earlier drafts), or {@code null}
     */
    record Page(List<Entry> entries, URI bodyNext) {}

    static final String CONTAINER_IRI = LWS.NS + "Container";
    static final String DATA_RESOURCE_IRI = LWS.NS + "DataResource";

    private static final Property[] MEMBERSHIP = {LWS.items, LWS.contains};
    private static final Property[] SIZE = {
        ResourceFactory.createProperty("https://schema.org/size"),
        ResourceFactory.createProperty("http://schema.org/size"),
        LWS.sizeInBytes};
    private static final Property[] MODIFIED = {
        ResourceFactory.createProperty("http://purl.org/dc/terms/modified"),
        ResourceFactory.createProperty(LWS.NS + "modified")};
    private static final Property[] FORMAT = {
        ResourceFactory.createProperty("http://purl.org/dc/terms/format"),
        LWS.mediaType};

    private ContainerListing() {
    }

    /** Whether a response with this {@code Content-Type} carries the JSON container representation. */
    static boolean isJson(String contentType) {
        if (contentType == null) {
            return false;
        }
        String mt = mediaType(contentType);
        return mt.equals("application/json") || mt.endsWith("+json");
    }

    static Page parse(byte[] body, String contentType, URI pageUri) {
        if (isJson(contentType) || (contentType == null && looksLikeJson(body))) {
            return parseJson(body, pageUri);
        }
        return parseRdf(body, contentType, pageUri);
    }

    // ------------------------------------------------------------------ JSON (application/lws+json)

    private static Page parseJson(byte[] body, URI pageUri) {
        JsonObject root;
        try (JsonReader r = Json.createReader(new ByteArrayInputStream(body))) {
            JsonValue v = r.readValue();
            if (v.getValueType() != JsonValue.ValueType.OBJECT) {
                throw new LWSException(LWSException.Kind.IO, "Container representation is not a JSON object: " + pageUri);
            }
            root = v.asJsonObject();
        } catch (RuntimeException e) {
            if (e instanceof LWSException le) {
                throw le;
            }
            throw new LWSException(LWSException.Kind.IO, "Malformed container representation (JSON): " + pageUri, e);
        }
        JsonValue items = first(root, "items", "lws:items", LWS.NS + "items", "contains", "lws:contains");
        List<Entry> entries = new ArrayList<>();
        if (items != null && items.getValueType() == JsonValue.ValueType.ARRAY) {
            for (JsonValue item : (JsonArray) items) {
                Entry e = jsonEntry(item, pageUri);
                if (e != null) {
                    entries.add(e);
                }
            }
        }
        return new Page(entries, null);
    }

    private static Entry jsonEntry(JsonValue item, URI pageUri) {
        if (item.getValueType() == JsonValue.ValueType.STRING) {
            URI uri = resolve(pageUri, ((JsonString) item).getString());
            return uri == null ? null : new Entry(uri, uri.getPath() != null && uri.getPath().endsWith("/"), -1, 0, null);
        }
        if (item.getValueType() != JsonValue.ValueType.OBJECT) {
            return null;
        }
        JsonObject o = item.asJsonObject();
        URI uri = resolve(pageUri, string(first(o, "id", "@id")));
        if (uri == null) {
            return null;
        }
        Boolean container = jsonKind(first(o, "type", "@type"));
        boolean isContainer = container != null ? container : (uri.getPath() != null && uri.getPath().endsWith("/"));
        long size = -1;
        JsonValue s = first(o, "size", "schema:size", "sizeInBytes");
        if (s instanceof JsonNumber num) {
            size = Math.max(-1, num.longValue());
        } else if (s instanceof JsonString str) {
            size = parseLong(str.getString());
        }
        long mtime = epochSeconds(string(first(o, "modified", "dcterms:modified")));
        String format = string(first(o, "format", "dcterms:format", "contentType", "mediaType"));
        return new Entry(uri, isContainer, isContainer ? 0 : size, mtime, isContainer ? null : blankToNull(format));
    }

    /** {@code true} for a container type, {@code false} for a data resource, {@code null} if neither is stated. */
    private static Boolean jsonKind(JsonValue type) {
        List<String> types = new ArrayList<>();
        if (type instanceof JsonString s) {
            types.add(s.getString());
        } else if (type instanceof JsonArray a) {
            for (JsonValue v : a) {
                if (v instanceof JsonString s) {
                    types.add(s.getString());
                }
            }
        }
        Boolean kind = null;
        for (String t : types) {
            if (t.equals("Container") || t.equals("lws:Container") || t.equals(CONTAINER_IRI)) {
                return true;
            }
            if (t.equals("DataResource") || t.equals("lws:DataResource") || t.equals(DATA_RESOURCE_IRI)) {
                kind = false;
            }
        }
        return kind;
    }

    private static JsonValue first(JsonObject o, String... keys) {
        for (String k : keys) {
            JsonValue v = o.get(k);
            if (v != null && v.getValueType() != JsonValue.ValueType.NULL) {
                return v;
            }
        }
        return null;
    }

    private static String string(JsonValue v) {
        return v instanceof JsonString s ? s.getString() : null;
    }

    private static boolean looksLikeJson(byte[] body) {
        for (byte b : body) {
            if (b == '{') {
                return true;
            }
            if (!Character.isWhitespace(b)) {
                return false;
            }
        }
        return false;
    }

    // ------------------------------------------------------------------ RDF (earlier drafts)

    private static Page parseRdf(byte[] body, String contentType, URI pageUri) {
        Lang lang = Lang.TURTLE;
        if (contentType != null) {
            Lang l = RDFLanguages.contentTypeToLang(mediaType(contentType));
            if (l != null && RDFLanguages.isTriples(l)) {
                lang = l;
            }
        }
        Model model = ModelFactory.createDefaultModel();
        try {
            RDFDataMgr.read(model, new ByteArrayInputStream(body), pageUri.toString(), lang);
        } catch (RiotException e) {
            throw new LWSException(LWSException.Kind.IO, "Malformed container representation ("
                    + lang.getName() + "): " + pageUri, e);
        }
        List<Entry> entries = new ArrayList<>();
        for (Property p : MEMBERSHIP) {
            StmtIterator it = model.listStatements(null, p, (RDFNode) null);
            try {
                while (it.hasNext()) {
                    Statement st = it.next();
                    if (!st.getObject().isURIResource()) {
                        continue;
                    }
                    Resource member = st.getObject().asResource();
                    URI uri = resolve(pageUri, member.getURI());
                    if (uri == null) {
                        continue;
                    }
                    boolean container = member.hasProperty(RDF.type, LWS.Container)
                            || (!member.hasProperty(RDF.type, LWS.DataResource) && uri.getPath() != null && uri.getPath().endsWith("/"));
                    entries.add(new Entry(uri, container,
                            container ? 0 : longValue(member, SIZE),
                            epochSeconds(lexical(member, MODIFIED)),
                            container ? null : blankToNull(lexical(member, FORMAT))));
                }
            } finally {
                it.close();
            }
        }
        URI next = firstUri(model, LWS.next, pageUri);
        if (next == null && entries.isEmpty()) {
            next = firstUri(model, LWS.first, pageUri);   // the container only links its first page
        }
        return new Page(entries, next);
    }

    private static String lexical(Resource subject, Property[] predicates) {
        for (Property p : predicates) {
            Statement st = subject.getProperty(p);
            if (st != null && st.getObject().isLiteral()) {
                Literal l = st.getObject().asLiteral();
                return l.getLexicalForm();
            }
        }
        return null;
    }

    private static long longValue(Resource subject, Property[] predicates) {
        String s = lexical(subject, predicates);
        return s == null ? -1 : parseLong(s);
    }

    private static URI firstUri(Model model, Property predicate, URI pageUri) {
        StmtIterator it = model.listStatements(null, predicate, (RDFNode) null);
        try {
            while (it.hasNext()) {
                RDFNode obj = it.next().getObject();
                if (obj.isURIResource()) {
                    URI u = resolve(pageUri, obj.asResource().getURI());
                    if (u != null) {
                        return u;
                    }
                }
            }
        } finally {
            it.close();
        }
        return null;
    }

    // ------------------------------------------------------------------ helpers

    static String mediaType(String contentType) {
        return contentType.split(";", 2)[0].trim().toLowerCase(Locale.ROOT);
    }

    private static URI resolve(URI base, String ref) {
        if (ref == null || ref.isBlank()) {
            return null;
        }
        try {
            return base.resolve(new URI(ref.trim())).normalize();
        } catch (URISyntaxException | IllegalArgumentException e) {
            return null;
        }
    }

    private static long parseLong(String s) {
        try {
            long v = Long.parseLong(s.trim());
            return v >= 0 ? v : -1;
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** An ISO 8601 / {@code xsd:dateTime} timestamp in epoch seconds; one without a zone is taken as UTC; 0 if absent. */
    static long epochSeconds(String s) {
        if (s == null || s.isBlank()) {
            return 0;
        }
        String t = s.trim();
        try {
            return OffsetDateTime.parse(t).toEpochSecond();
        } catch (RuntimeException notOffset) {
            try {
                return LocalDateTime.parse(t).toEpochSecond(ZoneOffset.UTC);
            } catch (RuntimeException unparseable) {
                return 0;
            }
        }
    }

    private static String blankToNull(String s) {
        return s == null || s.isBlank() ? null : s.trim();
    }
}
