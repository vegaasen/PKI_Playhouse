package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.types.HashType;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.IOException;
import java.io.StringWriter;
import java.security.Key;
import java.security.KeyStore;
import java.security.SignatureException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public class XmlSigningUtilsTest {

    private static Key someKey;
    private static Key someOtherKey;

    @Before
    public void setUp() {
        HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
        KeyStoreUtils.setKeystoreType("JCEKS");
        someKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");
        someOtherKey = getAESKeyFromLocalKeyStore("my-second-secret", "vegard");
    }

    @Test
    public void shouldSignDocumentBasedOnHMacKey() throws Exception {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = someKey;
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_1);
        assertNotNull(document);
        final String expectedSignatureValue = "O3FtmZSNYAv1Gzcp408sJHe3Rog=";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length()>0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac() throws Exception {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_512);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_1);
        assertNotNull(document);
        final String expectedSignatureValue = "O3FtmZSNYAv1Gzcp408sJHe3Rog=";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String expectedDigestValue = "g6uRSxiw7ZEth0KnfHf1RPr0fk0=";
        final String digestValue = ((document.getElementsByTagName("ds:DigestValue").item(0))).getTextContent();
        assertNotNull(digestValue);
        assertTrue(!digestValue.isEmpty());
        assertEquals(expectedDigestValue, digestValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length()>0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac_using_sha256() throws Exception {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_256);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_256);
        assertNotNull(document);
        final String expectedSignatureValue = "R03Q5C0uBaDyu4ExNiQTS+/mQ/gLWy0AFpTVW8ruNu8=";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length()>0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac_using_sha384() throws Exception {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_384);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_384);
        assertNotNull(document);
        final String expectedSignatureValue = "XEav8ZcTucG4in19SsuUTtNF8ASJENKt9H4/p4pu9TCR9iS2Ydjha773Or34Ldww";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length()>0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac_using_sha512() throws Exception {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_512);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_512);
        assertNotNull(document);
        final String expectedSignatureValue = "4ntN/ugQD8lT/mpqttcC7TRBA/2vEICaItatHVmhd8SCV1Uj7AC6iDQ0JaPOi6DKejB3lZ/x76cf\n" +
                "x6OAjd2eEA==";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length()>0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentWithAnotherHmacKey() throws Exception {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_1);
        assertNotNull(document);
        final String expectedSignatureValue = "O3FtmZSNYAv1Gzcp408sJHe3Rog=";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length()>0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailSigningDocument_missingKey() throws SignatureException {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, null, HashType.HMAC_SHA_1);
    }

    @Test(expected = SignatureException.class)
    public void shouldFailSigningDocument_wrong_HashType() throws SignatureException {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.AES);
    }

    @Test(expected = SignatureException.class)
    public void shouldFailSigningDocument_no_such_element() throws SignatureException {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#ThereIsNoElementNamedThis", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_1);
    }

    @Test
    public void shouldFailSigningDocument_missing_Signature_Id() throws SignatureException {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", null, hmacKey, HashType.HMAC_SHA_1);
        final Node signature = ((document.getElementsByTagName("ds:Signature").item(0)));
        assertNotNull(signature);
        final Node id = signature.getAttributes().getNamedItem("Id");
        assertNotNull(id);
        assertNotNull(id.getTextContent());
        assertEquals(XmlSigningUtils.DEFAULT_SIGNATURE_ID, id.getTextContent());
    }

    @Test
    public void shouldFailSigningDocument_specific_Signature_Id() throws SignatureException {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        final Document document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length>0);
        final String signatureId = "vegardIsOhSoCool";
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", signatureId, hmacKey, HashType.HMAC_SHA_1);
        final Node signature = ((document.getElementsByTagName("ds:Signature").item(0)));
        assertNotNull(signature);
        final Node id = signature.getAttributes().getNamedItem("Id");
        assertNotNull(id);
        assertNotNull(id.getTextContent());
        assertEquals(signatureId, id.getTextContent());
    }

    private static Key getAESKeyFromLocalKeyStore(String alias, String password) {
        final KeyStore keyStore = KeyStoreUtils.load("fun.jceks", "vegard");
        return KeyStoreUtils.getKey(keyStore, alias, password);
    }

    private static Document getDocumentFromFile(final File file) {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = null;
        try {
            builder = factory.newDocumentBuilder();
        } catch (ParserConfigurationException e) {
            e.printStackTrace();
        }
        try {
            return builder.parse(file);
        } catch (SAXException | IOException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static String convertDocumentToString(final Document doc) throws Exception {
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
