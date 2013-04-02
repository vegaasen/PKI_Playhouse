package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.types.HashType;
import org.junit.Test;

import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public class KeyUtilsTest {

    @Test
    public void shouldGenerateAESSecretKey() throws NoSuchProviderException, NoSuchAlgorithmException {
        final Key aesKey = KeyUtils.generateAESKey(KeyUtils.AES_KEY_SIZE_192);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        assertTrue(aesKey.getEncoded().length > 0);
    }

    @Test
    public void shouldConvertAESKeyToPortableFormat() throws Exception {
        final Key aesKey = KeyUtils.generateAESKey(KeyUtils.AES_KEY_SIZE_192);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        assertTrue(aesKey.getEncoded().length > 0);
        final String result = KeyUtils.convertKeyToPortableFormat(aesKey);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
    }

    @Test
    public void shouldConvertBackToAESKeyFromPortableFormat() throws Exception {
        final String portableFormatRepresentation = "5I3efrQWPlpv9IUegrHcq+QEfmqEP2p+";
        final Key aesKey = KeyUtils.convertFromPortableToKey(portableFormatRepresentation, HashType.AES);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        assertTrue(aesKey.getEncoded().length > 0);
    }

    @Test
    public void shouldConvertBackToByteArrayFromPortableFormat() throws Exception {
        final String portableFormatRepresentation = "5I3efrQWPlpv9IUegrHcq+QEfmqEP2p+";
        final byte[] aesKey = KeyUtils.convertFromPortableFormatToByteArray(portableFormatRepresentation);
        assertNotNull(aesKey);
        assertTrue(aesKey.length > 0);
    }

    @Test(expected = Exception.class)
    public void shouldNotConvertBackToAESKeyFromPortableFormat() throws Exception {
        final String kaput = "æøå";
        final Key aesKey = KeyUtils.convertFromPortableToKey(kaput, HashType.AES);
        assertNotNull(aesKey);
    }

    @Test
    public void shouldGenerateKey_ConvertToPortable_ThenConvertBackToKey_should_be_the_same() throws Exception {
        final Key aesKey = KeyUtils.generateAESKey(KeyUtils.AES_KEY_SIZE_192);
        assertNotNull(aesKey);
        assertNotNull(aesKey.getEncoded());
        final String portableFormat = KeyUtils.convertKeyToPortableFormat(aesKey);
        assertNotNull(portableFormat);
        assertTrue(!portableFormat.isEmpty());
        final byte[] keyAsBytes = KeyUtils.convertFromPortableFormatToByteArray(portableFormat);
        assertNotNull(keyAsBytes);
        assertTrue(keyAsBytes.length>0);
        final Key aesKeyBackConverted = KeyUtils.convertFromByteArrayToKey(HashType.AES, keyAsBytes);
        assertNotNull(aesKeyBackConverted);
        assertNotNull(aesKeyBackConverted.getEncoded());
        assertTrue(aesKeyBackConverted.getEncoded().length>0);
        assertEquals(aesKey, aesKeyBackConverted);
        assertTrue(Arrays.equals(aesKey.getEncoded(), aesKeyBackConverted.getEncoded()));
    }

}
