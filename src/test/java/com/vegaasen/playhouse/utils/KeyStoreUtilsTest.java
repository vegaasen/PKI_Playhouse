package com.vegaasen.playhouse.utils;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public class KeyStoreUtilsTest {

    @Test
    public void testLoadKeyFromKeyStore() throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException {
        InputStream is = KeyStoreUtilsTest.class.getResourceAsStream("/telenor-systest-symkey.jceks");
        assertNotNull(is);
        KeyStoreUtils.setKeystoreType(KeyStoreUtils.KEY_STORE_TYPE_JCEKS);
        KeyStore ks = KeyStoreUtils.load(is, "telenor");
        assertNotNull(ks);
        assertTrue(ks.size()>0);
        assertTrue(ks.containsAlias("saml_symmetric_key"));
        Key key = KeyStoreUtils.getKey(ks, "saml_symmetric_key", "telenor");
        assertNotNull(key);
        assertTrue(key.getEncoded().length>0);
    }
    
}
