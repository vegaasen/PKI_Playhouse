package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.types.HashType;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public class HMacUtilsTest {

    private static final String MESSAGE = "VegardOnTheRocks j jsdjdas jiaj ijijsda ijij ";
    private static final String DIGESTED_VALUE = "zCjXj/dv/RFaYuVeb7T8+rYhtB1qRbj55JIG6IGfhhloL6oLUZe4v3QxkEB+k3fOAay4HGkbcEhiWztCdnE3dlI=";
    private static final String SIGNATURE_VALUE = "9eaz9B9cBA697H/CBg9qqjpgEUE=";
    private static Key validVerificationKey;
    private static Key invalidVerificationKey;

    @Before
    public void setUp() {
        HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
        KeyStoreUtils.setKeystoreType("JCEKS");
        validVerificationKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");
        invalidVerificationKey = getAESKeyFromLocalKeyStore("my-second-secret", "vegard");
    }

    @Test
    public void testSetAlgorithm() {
        HMacUtils.setHashType(HashType.HMAC_MD_5);
        assertEquals(HMacUtils.getHashType(), HashType.HMAC_MD_5);
        HMacUtils.setHashType(HashType.HMAC_SHA_1);
        assertEquals(HMacUtils.getHashType(), HashType.HMAC_SHA_1);
        HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
        assertEquals(HMacUtils.getHashType(), HMacUtils.DEFAULT_HASH_TYPE);
    }

    @Test
    public void shouldGenerateHMacString_specified_valid_key() {
        final String expectedSignatureValue = SIGNATURE_VALUE;
        final String expectedDigestedValue = DIGESTED_VALUE;
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(validVerificationKey, MESSAGE);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        final String actualDigValue = result.get(HMacUtils.KEY_DIGEST_VALUE);
        final String actualSignValue = result.get(HMacUtils.KEY_SIGNATURE_VALUE);
        assertEquals(actualDigValue, expectedDigestedValue);
        assertEquals(actualSignValue, expectedSignatureValue);
    }

    @Test
    public void shouldGenerateHMacString_invalid_key_for_verification() {
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(validVerificationKey, MESSAGE);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        final boolean expectedResult = false;
        final boolean verificationResult = HMacUtils.verifyIntegrity(
                invalidVerificationKey,
                "9eaz9B9cBA697H/CBg9qqjpgEUE=",
                "zCjXj/dv/RFaYuVeb7T8+rYhtB1qRbj55JIG6IGfhhloL6oLUZe4v3QxkEB+k3fOAay4HGkbcEhiWztCdnE3dlI=",
                MESSAGE
        );
        assertNotNull(verificationResult);
        assertEquals(expectedResult, verificationResult);
    }

    @Test
    public void shouldGenerateHMacString_valid_key_for_verification() {
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(validVerificationKey, MESSAGE);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        final boolean expectedResult = true;
        final boolean verificationResult = HMacUtils.verifyIntegrity(
                validVerificationKey,
                "9eaz9B9cBA697H/CBg9qqjpgEUE=",
                "zCjXj/dv/RFaYuVeb7T8+rYhtB1qRbj55JIG6IGfhhloL6oLUZe4v3QxkEB+k3fOAay4HGkbcEhiWztCdnE3dlI=",
                MESSAGE
        );
        assertNotNull(verificationResult);
        assertEquals(expectedResult, verificationResult);
    }

    @Test
    public void shouldGenerateHMacString() {
        final String expectedSignatureValue = SIGNATURE_VALUE;
        final String expectedDigestedValue = DIGESTED_VALUE;
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(MESSAGE);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        final String actualDigValue = result.get(HMacUtils.KEY_DIGEST_VALUE);
        final String actualSignValue = result.get(HMacUtils.KEY_SIGNATURE_VALUE);
        assertEquals(actualDigValue, expectedDigestedValue);
        assertEquals(actualSignValue, expectedSignatureValue);
    }

    @Test
    public void shouldVerifyIntegrityOfGeneratedHMacString() {
        final boolean expectedResult = true;
        final boolean result = HMacUtils.verifyIntegrity(
                SIGNATURE_VALUE,
                DIGESTED_VALUE,
                MESSAGE
        );
        assertEquals(expectedResult, result);
    }

    @Test
    public void shouldNotVerifyIntegrityOfGeneratedStuff() {
        final boolean expectedResult = false;
        final boolean result = HMacUtils.verifyIntegrity(
                SIGNATURE_VALUE,
                DIGESTED_VALUE,
                MESSAGE + "error"
        );
        assertEquals(expectedResult, result);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotVerifyIntegrityOfGeneratedStuff_digestIsWrong() {
        HMacUtils.verifyIntegrity(
                SIGNATURE_VALUE,
                DIGESTED_VALUE + "error",
                MESSAGE
        );
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldNotVerifyIntegrityOfGeneratedStuff_signatureIsWrong() {
        HMacUtils.verifyIntegrity(
                SIGNATURE_VALUE + "error",
                DIGESTED_VALUE,
                MESSAGE
        );
    }

    @Test
    public void shouldGenerateHMacString_fromAesUtilsGeneratedKey()
            throws NoSuchProviderException, NoSuchAlgorithmException {
        final Key aesKey = KeyUtils.generateAESKey(KeyUtils.AES_KEY_SIZE_192);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        assertTrue(aesKey.getEncoded().length > 0);
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(aesKey, MESSAGE);
        assertNotNull(result);
        assertTrue(result.size() == 3);
        final boolean expectedResult = true;
        final boolean verificationResult = HMacUtils.verifyIntegrity(
                aesKey,
                result.get(HMacUtils.KEY_SIGNATURE_VALUE),
                result.get(HMacUtils.KEY_DIGEST_VALUE),
                MESSAGE
        );
        assertNotNull(verificationResult);
        assertEquals(expectedResult, verificationResult);
    }

    @Test
    public void shouldGenerateHMacString_fromPortableFormatFromAesUtilsGeneratedKey()
            throws Exception {
        final String portableFormat = "5I3efrQWPlpv9IUegrHcq+QEfmqEP2p+";
        final Key aesKey = KeyUtils.convertFromPortableToKey(portableFormat, HashType.AES);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        assertTrue(aesKey.getEncoded().length > 0);
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(aesKey, MESSAGE);
        assertNotNull(result);
        assertTrue(result.size() == 3);
        final boolean expectedResult = true;
        final boolean verificationResult = HMacUtils.verifyIntegrity(
                aesKey,
                result.get(HMacUtils.KEY_SIGNATURE_VALUE),
                result.get(HMacUtils.KEY_DIGEST_VALUE),
                MESSAGE
        );
        assertNotNull(verificationResult);
        assertEquals(expectedResult, verificationResult);
    }

    @Test
    public void shouldGenerateHMacString_fromPortableFormatFromAesUtilsGeneratedKey_from_xml_signing_utils()
            throws Exception {
        final String portableFormat = "ea2d84110583e3a80070ea76446425d6";
        final Key aesKey = KeyUtils.convertFromPortableToKey(portableFormat, HashType.AES);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        assertTrue(aesKey.getEncoded().length > 0);
        final Map<String, String> result = HMacUtils.generateIntegrityContainer(aesKey, MESSAGE);
        assertNotNull(result);
        assertTrue(result.size() == 3);
        final boolean expectedResult = true;
        final boolean verificationResult = HMacUtils.verifyIntegrity(
                aesKey,
                result.get(HMacUtils.KEY_SIGNATURE_VALUE),
                result.get(HMacUtils.KEY_DIGEST_VALUE),
                MESSAGE
        );
        assertNotNull(verificationResult);
        assertEquals(expectedResult, verificationResult);
    }

    @Test
    public void shouldGenerateSomeHmacKeyFromTheAESValidVerificationKey() throws Exception {
        final String expectedBase64Hmac = "fcTTs5MqglRj4b0b7hRKtGTyoSVJhCN3";
        final Key hmacKey = HMacUtils.getHMacKey(validVerificationKey, HashType.HMAC_SHA_1);
        assertNotNull(hmacKey);
        assertNotNull(hmacKey.getEncoded());
        assertTrue(hmacKey.getEncoded().length > 0);
        final String result = KeyUtils.convertKeyToPortableFormat(hmacKey);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(expectedBase64Hmac, result);
    }

    private static Key getAESKeyFromLocalKeyStore(String alias, String password) {
        final KeyStore keyStore = KeyStoreUtils.load("fun.jceks", "vegard");
        return KeyStoreUtils.getKey(keyStore, alias, password);
    }

    @After
    public void tearDown() {
        HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
    }

}
