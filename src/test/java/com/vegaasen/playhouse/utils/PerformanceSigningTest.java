package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.model.Result;
import com.vegaasen.playhouse.types.HashType;
import com.vegaasen.playhouse.utils.abs.AbstractTest;
import org.junit.*;
import org.w3c.dom.Document;

import java.io.File;
import java.security.Key;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Map;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * This class uses the XmlSigningUtils-class for performance testing
 * The main purposes of this class is to just check how fast the different variations of signing/validating is.
 * E.g Symmetric-key vs PKI Signing / Validation
 * <p/>
 * TODO: Run with different JVM-Arguments?
 *
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public class PerformanceSigningTest extends AbstractTest {

    private static String reference_id;

    private static volatile int NUMBER_OF_ITERATIONS = 1_0;

    private static Document document;
    private static Document greaterDocument, smallDocument;
    private static Key preloadedHMacKey;
    private static X509Certificate preloadedCertificate;
    private static PrivateKey preloadedPrivateKey;
    private static X509Certificate preloadedClientCertificate;

    @BeforeClass
    public static void onlyOnce() {
        try {
            KeyStoreUtils.setKeystoreType("JKS");
            final Map<String, Object> keyPair;
            keyPair = KeyStoreUtils.getKeyPair(
                    getKeyStoreByName("fun_certificates.jks", "telenor"),
                    "signing:idp.telenor.no(pwd:vegard)",
                    "vegard"
            );
            assertNotNull(keyPair);
            assertTrue(!keyPair.isEmpty());
            assertTrue(keyPair.size() == 2);
            HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
            KeyStoreUtils.setKeystoreType("JCEKS");
            preloadedHMacKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");
            preloadedCertificate = (X509Certificate) keyPair.get(KeyStoreUtils.KEY_PUBLIC);
            preloadedPrivateKey = (PrivateKey) keyPair.get(KeyStoreUtils.KEY_PRIVATE);
            preloadedClientCertificate = getCertificateFromLocalKeyStore("saml:idp.telenor.no");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Before
    public void setUp() {
        final File documentAsFile = FileUtils.getInstance().getFileFromClassPath("signing-document.xml");
        smallDocument = getDocumentFromFile(documentAsFile);
        final File largerDocumentAsFile = FileUtils.getInstance().getFileFromClassPath("samlv2_unsigned.xml");
        greaterDocument = getDocumentFromFile(largerDocumentAsFile);

        //Set this to whatever document you'd like to test.
        document = getGreaterDocument();
    }

    @Test
    public void runPerformanceTesting_SIGNING_CERTIFICATE() {
        final Date now = new Date();
        warmUpJVM();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int c = 0;
                do {
                    @SuppressWarnings("unused") Document document = getSignedDocumentByCertificate();
                    c++;
                } while (c < NUMBER_OF_ITERATIONS);
            }
        });
        long start = System.nanoTime();
        thread.run();
        long stop = System.nanoTime();
        long resultInNanos = stop - start;
        outputResult(now, resultInNanos);
    }

    @Test
    public void runPerformanceTesting_SIGNING_CERTIFICATE_USING_STATIC() {
        final Date now = new Date();
        warmUpJVM();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int c = 0;
                do {
                    @SuppressWarnings("unused") Document document = getSignedDocumentByCertificate_STATIC_PKI();
                    c++;
                } while (c < NUMBER_OF_ITERATIONS);
            }
        });
        long start = System.nanoTime();
        thread.run();
        long stop = System.nanoTime();
        long resultInNanos = stop - start;
        outputResult(now, resultInNanos);
    }

    @Test
    public void runPerformanceTesting_SIGNING_HMAC() {
        final Date now = new Date();
        warmUpJVM();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int c = 0;
                do {
                    @SuppressWarnings("unused") Document document = getSignedDocumentByHMac();
                    c++;
                } while (c < NUMBER_OF_ITERATIONS);
            }
        });
        long start = System.nanoTime();
        thread.run();
        long stop = System.nanoTime();
        long resultInNanos = stop - start;
        outputResult(now, resultInNanos);
    }

    @Test
    public void runPerformanceTesting_SIGNING_HMAC_USING_STATIC() {
        final Date now = new Date();
        warmUpJVM();
        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int c = 0;
                do {
                    @SuppressWarnings("unused") Document document = getSignedDocumentByHMac_STATIC_KEY();
                    c++;
                } while (c < NUMBER_OF_ITERATIONS);
            }
        });
        long start = System.nanoTime();
        thread.run();
        long stop = System.nanoTime();
        long resultInNanos = stop - start;
        outputResult(now, resultInNanos);
    }

    @Test
    public void runPerformanceTesting_VALIDATING_CERTIFICATE() {
        final Date now = new Date();
        final Document signedDocument = getSignedDocumentByCertificate();
        assertNotNull(signedDocument);
        try {
            final X509Certificate validatorCertificate = getCertificateFromLocalKeyStore("saml:idp.telenor.no");
            assertNotNull(validatorCertificate);

            warmUpJVM();

            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    int c = 0;
                    do {
                        try {
                            XmlSigningUtils.validateDocumentByCertificate(signedDocument, validatorCertificate);
                        } catch (SignatureException | CertificateException e) {
                            e.printStackTrace();
                        }
                        c++;
                    } while (c < NUMBER_OF_ITERATIONS);
                }
            });

            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void runPerformanceTesting_VALIDATING_CERTIFICATE_USING_STATIC() {
        final Date now = new Date();
        final Document signedDocument = getSignedDocumentByCertificate_STATIC_PKI();
        assertNotNull(signedDocument);
        warmUpJVM();

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int c = 0;
                do {
                    try {
                        XmlSigningUtils.validateDocumentByCertificate(signedDocument, preloadedClientCertificate);
                    } catch (SignatureException | CertificateException e) {
                        e.printStackTrace();
                    }
                    c++;
                } while (c < NUMBER_OF_ITERATIONS);
            }
        });

        long start = System.nanoTime();
        thread.run();
        long stop = System.nanoTime();
        long resultInNanos = stop - start;
        outputResult(now, resultInNanos);
    }

    @Test
    public void runPerformanceTesting_VALIDATING_HMAC() {
        final Date now = new Date();
        final Document signedDocument = getSignedDocumentByHMac();
        assertNotNull(signedDocument);
        try {
            HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
            KeyStoreUtils.setKeystoreType("JCEKS");
            final Key hmacKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");

            assertNotNull(hmacKey);

            warmUpJVM();

            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    int c = 0;
                    do {
                        try {
                            XmlSigningUtils.validateDocumentByKey(signedDocument, hmacKey);
                        } catch (SignatureException e) {
                            e.printStackTrace();
                        }
                        c++;
                    } while (c < NUMBER_OF_ITERATIONS);
                }
            });

            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
    }

    @Test
    public void runPerformanceTesting_VALIDATING_HMAC_USING_STATIC() {
        final Date now = new Date();
        final Document signedDocument = getSignedDocumentByHMac_STATIC_KEY();
        assertNotNull(signedDocument);
        warmUpJVM();

        Thread thread = new Thread(new Runnable() {
            @Override
            public void run() {
                int c = 0;
                do {
                    try {
                        XmlSigningUtils.validateDocumentByKey(signedDocument, preloadedHMacKey);
                    } catch (SignatureException e) {
                        e.printStackTrace();
                    }
                    c++;
                } while (c < NUMBER_OF_ITERATIONS);
            }
        });

        long start = System.nanoTime();
        thread.run();
        long stop = System.nanoTime();
        long resultInNanos = stop - start;
        outputResult(now, resultInNanos);
    }

    @After
    public void tearDown() {
        document = null;
    }

    @AfterClass
    public static void tearDownClass() {
        document = null;
        greaterDocument = null;
        smallDocument = null;
        preloadedHMacKey = null;
        preloadedCertificate = null;
        preloadedPrivateKey = null;
        preloadedClientCertificate = null;
    }

    /**
     * Get the document using a static HMac Key
     *
     * @return signedDocument
     */
    private static Document getSignedDocumentByHMac_STATIC_KEY() {
        try {
            XmlSigningUtils.signDocumentByKey(
                    document,
                    reference_id,
                    XmlSigningUtils.DEFAULT_SIGNATURE_ID,
                    preloadedHMacKey,
                    HashType.HMAC_SHA_1);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return document;
    }

    private static Document getSignedDocumentByHMac() {
        Key hmacKey = null;
        try {
            HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
            KeyStoreUtils.setKeystoreType("JCEKS");
            hmacKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        try {
            XmlSigningUtils.signDocumentByKey(
                    document,
                    reference_id,
                    XmlSigningUtils.DEFAULT_SIGNATURE_ID,
                    hmacKey,
                    HashType.HMAC_SHA_1);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        return document;
    }

    /**
     * Get the document a static x509Certificate and PrivateKey
     *
     * @return signedDocument
     */
    private static Document getSignedDocumentByCertificate_STATIC_PKI() {
        try {
            XmlSigningUtils.signDocumentByCertificate(
                    document,
                    reference_id,
                    XmlSigningUtils.DEFAULT_SIGNATURE_ID,
                    preloadedPrivateKey,
                    preloadedCertificate
            );
        } catch (CertificateException | SignatureException e) {
            e.printStackTrace();
        }
        return document;
    }

    private static Document getSignedDocumentByCertificate() {
        final Map<String, Object> keyPair;
        try {
            keyPair = KeyStoreUtils.getKeyPair(
                    getKeyStoreByName("fun_certificates.jks", "telenor"),
                    "signing:idp.telenor.no(pwd:vegard)",
                    "vegard"
            );
            assertNotNull(keyPair);
            assertTrue(!keyPair.isEmpty());
            assertTrue(keyPair.size() == 2);
            final X509Certificate certificate = (X509Certificate) keyPair.get(KeyStoreUtils.KEY_PUBLIC);
            final PrivateKey privateKey = (PrivateKey) keyPair.get(KeyStoreUtils.KEY_PRIVATE);
            XmlSigningUtils.signDocumentByCertificate(
                    document,
                    reference_id,
                    XmlSigningUtils.DEFAULT_SIGNATURE_ID,
                    privateKey,
                    certificate
            );
            return document;
        } catch (KeyStoreException | CertificateException | SignatureException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * Use this simple method to warm up the JVM for compilation..
     */
    private static void warmUpJVM() {
        @SuppressWarnings("unused") double sum = 0;
        for (int i = 0; i < 1000; i++) {
            for (int j = 0; j < 1000; j++) {
                sum += (double) i + (double) j % i * 1;
            }
        }
    }

    /**
     * Fugly outputter of results..
     *
     * @param initiated  date of initiated
     * @param nanoResult results in nanoseconds
     */
    private static void outputResult(final Date initiated, final long nanoResult) {
        String methodCallingMe = "";
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        if (stackTrace != null && stackTrace.length >= 2) {
            StackTraceElement fromMethod = stackTrace[2];
            if (fromMethod != null) {
                methodCallingMe = fromMethod.getMethodName();
            }
        }
        System.out.println(Result.generateResultSetString(new Result.Builder()
                .nanoResult(nanoResult)
                .callingMethod(methodCallingMe)
                .documentUsed(document.getBaseURI())
                .finished(new Date())
                .numOfIterations(NUMBER_OF_ITERATIONS)
                .initiated(initiated)
                .build(), 0));
    }

    private static Document getGreaterDocument() {
        reference_id = "#" + greaterDocument.getElementsByTagName("saml:Assertion").item(0).getAttributes().getNamedItem("ID").getTextContent();
        return greaterDocument;
    }

    private static Document getSmallDocument() {
        reference_id = "#allTheCarsInTheWorld";
        return smallDocument;
    }

}
