package com.vegaasen.playhouse.utils.abs;

import com.vegaasen.playhouse.utils.KeyStoreUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.X509Certificate;

/**
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public abstract class AbstractTest {

    protected static X509Certificate getCertificateFromLocalKeyStore(String alias) throws KeyStoreException {
        KeyStoreUtils.setKeystoreType("JKS");
        final KeyStore keyStore = getKeyStoreByName("fun_certificates.jks", "telenor");
        return KeyStoreUtils.getCertificate(keyStore, alias);
    }

    protected static Key getAESKeyFromLocalKeyStore(String alias, String password) throws KeyStoreException {
        KeyStoreUtils.setKeystoreType("JCEKS");
        final KeyStore keyStore = getKeyStoreByName("fun.jceks", "vegard");
        return KeyStoreUtils.getKey(keyStore, alias, password);
    }

    protected static KeyStore getKeyStoreByName(String name, String password) {
        final KeyStore keystore = KeyStoreUtils.load(name, password, true);
        if (keystore != null) {
            return keystore;
        }
        throw new IllegalArgumentException("Unable to load KeyStoreByName.");
    }

    protected static Document getDocumentFromInputStream(final InputStream is) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        try {
            return builder.parse(is);
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    protected static Document getDocumentFromFile(final File file) {
        if (file != null) {
            try {
                return getDocumentFromInputStream(new FileInputStream(file));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    protected static String convertDocumentToString(final Document doc) throws Exception {
        try {
            StringWriter sw = new StringWriter();

            TransformerFactory tf = TransformerFactory.newInstance();
            Transformer transformer = tf.newTransformer();

            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "no");
            transformer.setOutputProperty(OutputKeys.METHOD, "xml");
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty(OutputKeys.ENCODING, "UTF-8");

            transformer.transform(new DOMSource(doc), new StreamResult(sw));
            return sw.toString();
        } catch (Exception ex) {
            throw new Exception("Oops, unable to transform :-]");
        }
    }

}
