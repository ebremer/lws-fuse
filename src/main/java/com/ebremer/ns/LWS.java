package com.ebremer.ns;

import org.apache.jena.rdf.model.Property;
import org.apache.jena.rdf.model.Resource;
import org.apache.jena.rdf.model.ResourceFactory;

/**
 * W3C Linked Web Storage vocabulary — {@code https://www.w3.org/ns/lws#}.
 *
 * <p>Project-local vocabulary constants (a drop-in for the terms formerly provided by
 * {@code halcyon-core}), so the LWS client depends only on Jena, not on that artifact. Current as
 * of the LWS 1.0 vocabulary at w3c/lws-protocol {@code ef02548} (2026-10-05); member metadata
 * now reuses {@code schema:size}, {@code dcterms:modified} and {@code dcterms:format}.
 *
 * @see <a href="https://w3c.github.io/lws-protocol/lws10-vocab/">LWS vocabulary</a>
 */
public final class LWS {

    private LWS() {
    }

    public static final String NS = "https://www.w3.org/ns/lws#";

    public static String getURI() {
        return NS;
    }

    // Classes
    public static final Resource StorageResource = ResourceFactory.createResource(NS + "StorageResource");
    public static final Resource Container = ResourceFactory.createResource(NS + "Container");
    public static final Resource DataResource = ResourceFactory.createResource(NS + "DataResource");
    public static final Resource Storage = ResourceFactory.createResource(NS + "Storage");
    public static final Resource StorageRoot = ResourceFactory.createResource(NS + "StorageRoot");
    public static final Resource OpenIdProvider = ResourceFactory.createResource(NS + "OpenIdProvider");

    // Properties
    public static final Property items = ResourceFactory.createProperty(NS + "items");
    public static final Property totalItems = ResourceFactory.createProperty(NS + "totalItems");
    public static final Property capability = ResourceFactory.createProperty(NS + "capability");
    /** Also the link relation that points from any storage resource to its storage. */
    public static final Property storage = ResourceFactory.createProperty(NS + "storage");

    // Terms of earlier drafts, read only for compatibility with servers that still use them.
    /** Earlier drafts' membership predicate; now {@link #items}. */
    public static final Property contains = ResourceFactory.createProperty(NS + "contains");
    /** Earlier drafts' in-body paging; pages are now linked with {@code Link: rel="first"/"next"} headers. */
    public static final Resource ContainerPage = ResourceFactory.createResource(NS + "ContainerPage");
    public static final Property first = ResourceFactory.createProperty(NS + "first");
    public static final Property last = ResourceFactory.createProperty(NS + "last");
    public static final Property next = ResourceFactory.createProperty(NS + "next");
    public static final Property prev = ResourceFactory.createProperty(NS + "prev");
    /** Earlier drafts' size and media type; now {@code schema:size} and {@code dcterms:format}. */
    public static final Property sizeInBytes = ResourceFactory.createProperty(NS + "sizeInBytes");
    public static final Property mediaType = ResourceFactory.createProperty(NS + "mediaType");
    public static final Resource MetadataResource = ResourceFactory.createResource(NS + "MetadataResource");
    public static final Resource Representation = ResourceFactory.createResource(NS + "Representation");
    public static final Property tag = ResourceFactory.createProperty(NS + "tag");
    public static final Property partOf = ResourceFactory.createProperty(NS + "partOf");
    public static final Property representation = ResourceFactory.createProperty(NS + "representation");
}
