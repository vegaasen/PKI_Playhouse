package com.vegaasen.playhouse.utils;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.File;
import java.security.KeyStore;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:vegard.aasen@telenor.com">Vegard Aasen</a>
 * @since 9:40 AM
 */
public final class CertificateImportUtilsTest {

    private static final String EMPTY = "";

    private String defaultPassword = "telenor";
    private File writtenToFile;

    @Before
    public void setUp() throws Exception {

    }

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
                "www.telenor.no",
                "",
                null,
                defaultPassword
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, defaultPassword);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetCertificateFromHostNameParamsNull_telenor_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                "www.telenor.no",
                null,
                null,
                defaultPassword
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, defaultPassword);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetCertificateFromHostNameParamsNull_telenorfusion_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                "www.telenorfusion.no",
                null,
                null,
                defaultPassword
        );
        assertNotNull(writtenToLocation);
        assertFalse(writtenToLocation.isEmpty());
        assertTrue(writtenToLocation.length() > 1);
        assertTrue(writtenToLocation.contains(CertificateImportUtils.DEFAULT_FILE_NAME));
        writtenToFile = new File(writtenToLocation);
        assertNotNull(writtenToLocation);
        assertTrue(writtenToFile.exists());
        assertTrue(writtenToFile.isFile());
        KeyStore keyStore = KeyStoreUtils.load(writtenToFile, defaultPassword);
        assertNotNull(keyStore);
    }

    @Test
    public void shouldGetCertificateFromHostNameParamsNull_no_password_telenor_no() throws Exception {
        String writtenToLocation = CertificateImportUtils.downloadAndImportCertificates(
                "www.telenorfusion.no",
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
