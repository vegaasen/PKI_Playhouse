package com.vegaasen.playhouse.utils;

import org.junit.After;
import org.junit.Test;

import java.io.File;
import java.security.KeyStore;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:vegard.aasen@telenor.com">Vegard Aasen</a>
 * @since 9:40 AM
 */
public final class CertificateImportUtilsTest {

    private static final String DEFAULT_PASSWORD = "telenor";
    private static final String WWW_TELENOR_NO = "www.telenor.no";
    private static final String WWW_TELENORFUSION_NO = "www.telenorfusion.no";

    private File writtenToFile;

    @Test
    public void shouldGetDefaultPathForCaCerts() {
        final String result = CertificateImportUtils.getDefaultOutLocation();
        assertNotNull(result);
        assertFalse(result.isEmpty());
        assertTrue(result.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
    }

    @Test
    public void shouldGetCertificateFromHostName_telenor_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                WWW_TELENOR_NO,
                "",
                null,
                DEFAULT_PASSWORD
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, DEFAULT_PASSWORD);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetCertificateFromHostNameParamsNull_telenor_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                WWW_TELENOR_NO,
                null,
                null,
                DEFAULT_PASSWORD
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, DEFAULT_PASSWORD);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetCertificateFromHostNameParamsNull_telenorfusion_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                WWW_TELENORFUSION_NO,
                null,
                null,
                DEFAULT_PASSWORD
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, DEFAULT_PASSWORD);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetCertificateFromHostNameParamsNull_no_password_telenor_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                WWW_TELENORFUSION_NO,
                null,
                null,
                null
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, "");
        assertNotNull(keyStore);
    }

    @Test(expected = IllegalArgumentException.class)
    public void shouldThrowExceptionWhenNoHostSpecified() throws Exception {
        CertificateImportUtils.downloadAndImportCertificates(null, null, null, null);
    }

    @After
    public void tearDown() {
        if (writtenToFile != null && writtenToFile.exists()) {
            boolean result = writtenToFile.delete();
            assertNotNull(result);
            assertTrue(result);
        }
    }

}
