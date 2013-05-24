package com.vegaasen.playhouse.run.performance;

import org.w3c.dom.Document;

/**
 * Simple class used to perform copy of an existing document, without ruining its content.
 * I.e: Working on a new instance, not the reference..
 *
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public class PerfDocument {

    private Document document;

    public PerfDocument(Document d) {
        this.document = d;
    }

    public Document getDocument() {
        return document;
    }
}
