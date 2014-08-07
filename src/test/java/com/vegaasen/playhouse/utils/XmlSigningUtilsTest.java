package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.types.HashType;
import com.vegaasen.playhouse.utils.abs.AbstractTest;
import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

import java.io.File;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public class XmlSigningUtilsTest extends AbstractTest {

    private static Key someKey;
    private static Key someOtherKey;

    private Document document;

    @Before
    public void setUp() {
        HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
        KeyStoreUtils.setKeystoreType("JCEKS");
        try {
            someKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");
            someOtherKey = getAESKeyFromLocalKeyStore("my-second-secret", "vegard");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        assertNotNull(documentAsFile);
        assertTrue(documentAsFile.exists());
        document = getDocumentFromFile(documentAsFile);
        assertNotNull(document);
    }

    @Test
    public void shouldSignDocumentBasedOnHMacKey() throws Exception {
        final Key hmacKey = someKey;
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
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
        assertTrue(convertedSignedDocument.length() > 0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac() throws Exception {
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_512);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
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
        assertTrue(convertedSignedDocument.length() > 0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac_using_sha256() throws Exception {
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_256);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
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
        assertTrue(convertedSignedDocument.length() > 0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac_using_sha384() throws Exception {
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_384);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
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
        assertTrue(convertedSignedDocument.length() > 0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentBasedOnAESKey_converted_to_hmac_using_sha512() throws Exception {
        final Key hmacKey = HMacUtils.getHMacKey(someKey, HashType.HMAC_SHA_512);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
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
        assertTrue(convertedSignedDocument.length() > 0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test
    public void shouldSignDocumentWithAnotherHmacKey() throws Exception {
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_1);
        assertNotNull(document);
        final String expectedSignatureValue = "jicjvwpiHrnDj7LG5i2uvhjKh/o=";
        final String signatureValue = ((document.getElementsByTagName("ds:SignatureValue").item(0))).getTextContent();
        assertNotNull(signatureValue);
        assertTrue(!signatureValue.isEmpty());
        assertEquals(expectedSignatureValue, signatureValue);
        final String convertedSignedDocument = convertDocumentToString(document);
        assertNotNull(convertedSignedDocument);
        assertTrue(!convertedSignedDocument.isEmpty());
        assertTrue(convertedSignedDocument.length() > 0);
        assertTrue(convertedSignedDocument.contains(XmlSigningUtils.DEFAULT_SIGNATURE_ID));
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldFailSigningDocument_missingKey() throws SignatureException {
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, null, HashType.HMAC_SHA_1);
    }

    @Test(expected = SignatureException.class)
    public void shouldFailSigningDocument_wrong_HashType() throws SignatureException {
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.AES);
    }

    @Test(expected = SignatureException.class)
    public void shouldFailSigningDocument_no_such_element() throws SignatureException {
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
        XmlSigningUtils.signDocumentByKey(document, "#ThereIsNoElementNamedThis", XmlSigningUtils.DEFAULT_SIGNATURE_ID, hmacKey, HashType.HMAC_SHA_1);
    }

    @Test
    public void shouldFailSigningDocument_missing_Signature_Id() throws SignatureException {
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
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
        final Key hmacKey = HMacUtils.getHMacKey(someOtherKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
        final String signatureId = "vegardIsOhSoCool";
        XmlSigningUtils.signDocumentByKey(document, "#allTheCarsInTheWorld", signatureId, hmacKey, HashType.HMAC_SHA_1);
        final Node signature = ((document.getElementsByTagName("ds:Signature").item(0)));
        assertNotNull(signature);
        final Node id = signature.getAttributes().getNamedItem("Id");
        assertNotNull(id);
        assertNotNull(id.getTextContent());
        assertEquals(signatureId, id.getTextContent());
    }

    @Test
    public void shouldSignDocumentAndValidate_x509certificate() throws GeneralSecurityException, IOException {
        final Map<String, Object> keyPair = KeyStoreUtils.getKeyPair(
                getKeyStoreByName("fun_certificates.jks", "telenor"),
                "signing:idp.telenor.no(pwd:vegard)",
                "vegard"
        );
        assertNotNull(keyPair);
        assertTrue(!keyPair.isEmpty());
        assertTrue(keyPair.size() == 2);
        final String signatureId = "MorDi";
        final X509Certificate certificate = (X509Certificate) keyPair.get(KeyStoreUtils.KEY_PUBLIC);
        final PrivateKey privateKey = (PrivateKey) keyPair.get(KeyStoreUtils.KEY_PRIVATE);
        XmlSigningUtils.signDocumentByCertificate(
                document,
                "#allTheCarsInTheWorld",
                signatureId,
                privateKey,
                certificate
        );
        assertNotNull(document);
        final String expectedSignatureValue = "nKNtj4GGfnJoPdI6UxI+AUq+gKh2+wV50UMHXlDaS9qxrNnXPv48vSc9l5XLp37JI7vXMPKjM/PD\n" +
                "pcRYOBpzCKLMIWP9g4i8ke/7OML9fjDHFW3dD5G4UcX6fW8uDsZNZL/JbeygiSd2JAyv0oGBC0Qs\n" +
                "VA2BTZTilYpsWknuoiQ=";
        final Node signatureValue = document.getElementsByTagName("ds:SignatureValue").item(0);
        assertNotNull(signatureValue);
        assertEquals(expectedSignatureValue, signatureValue.getTextContent());
        final X509Certificate validatorCertificate = getCertificateFromLocalKeyStore("saml:idp.telenor.no");
        assertNotNull(validatorCertificate);
        assertTrue(XmlSigningUtils.validateDocumentByCertificate(document, validatorCertificate));
    }

}
