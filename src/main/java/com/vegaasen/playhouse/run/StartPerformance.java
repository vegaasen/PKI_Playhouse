package com.vegaasen.playhouse.run;

import com.google.common.base.Strings;
import com.vegaasen.playhouse.model.Result;
import com.vegaasen.playhouse.types.HashType;
import com.vegaasen.playhouse.utils.FileUtils;
import com.vegaasen.playhouse.utils.HMacUtils;
import com.vegaasen.playhouse.utils.KeyStoreUtils;
import com.vegaasen.playhouse.utils.XmlSigningUtils;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Simple class that is doing the same thing as
 *
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 * @link com.vegaasen.playhouse.utils.PerformanceSigningTest
 * is doing.. OMG stupid me, copying everything from that test-class. Yeah, I know - but it was needed for a test-case..
 */
public final class StartPerformance {

    private static final String DEFAULT_DOCUMENT = "samlv2_unsigned.xml";
    private static final List<Result> results;

    private static int numOfIterations;
    private static String reference_id;
    private static Document document;
    private static Key preloadedHMacKey;
    private static X509Certificate preloadedCertificate;
    private static PrivateKey preloadedPrivateKey;
    private static X509Certificate preloadedClientCertificate;
    private static String documentLocation = "";

    static {
        try {
            KeyStoreUtils.setKeystoreType("JKS");
            final Map<String, Object> keyPair;
            keyPair = KeyStoreUtils.getKeyPair(
                    getKeyStoreByName("fun_certificates.jks", "telenor"),
                    "signing:idp.telenor.no(pwd:vegard)",
                    "vegard"
            );
            HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
            KeyStoreUtils.setKeystoreType("JCEKS");
            preloadedHMacKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");
            preloadedCertificate = (X509Certificate) keyPair.get(KeyStoreUtils.KEY_PUBLIC);
            preloadedPrivateKey = (PrivateKey) keyPair.get(KeyStoreUtils.KEY_PRIVATE);
            preloadedClientCertificate = getCertificateFromLocalKeyStore("saml:idp.telenor.no");
        } catch (KeyStoreException e) {
            e.printStackTrace();
            System.exit(-1);
        }
        results = new ArrayList<>();
    }

    public static void main(String... args) {
        if (args == null || args.length == 0) {
            System.out.println("ERROR: Usage; com.vegaasen.playhouse.run.StartPerformance <numOfIterations> (opt)\"<filePath\" (opt)\"#<elementId>\"");
            System.out.println("INFO: Example; com.vegaasen.playhouse.run.StartPerformance 100 \"C:\\_dev\\workspace_github\\PKI_Playhouse\\src\\test\\resources\\signing-document.xml\" \"#allTheCarsInTheWorld\"");
            System.exit(-1);
        }
        System.out.println("INFO: Can be runned with; -Xms256m -Xmx256m -server -XX:+CMSIncrementalMode -XX:+UseConcMarkSweepGC -XX:+PrintGCDetails -XX:+PrintGCTimeStamps -XX:MaxPermSize=128m");
        numOfIterations = Integer.parseInt(args[0]);
        if (args.length > 1) {
            documentLocation = args[1];
            if (args.length > 2) {
                reference_id = args[2];
            }
        }
        configure();
        runAllTests();
        System.exit(1);
    }

    private static void configure() {
        resetDocument();
    }

    private static void runAllTests() {
        runPerformanceTesting_SIGNING_CERTIFICATE();
        runPerformanceTesting_SIGNING_CERTIFICATE_USING_STATIC();
        runPerformanceTesting_SIGNING_HMAC();
        runPerformanceTesting_SIGNING_HMAC_USING_STATIC();
        runPerformanceTesting_VALIDATING_CERTIFICATE();
        runPerformanceTesting_VALIDATING_CERTIFICATE_USING_STATIC();
        runPerformanceTesting_VALIDATING_HMAC();
        runPerformanceTesting_VALIDATING_HMAC_USING_STATIC();
        writeResultSet();
    }

    private static void runPerformanceTesting_SIGNING_CERTIFICATE() {
        try {
            final Date now = new Date();
            warmUpJVM();
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    int c = 0;
                    do {
                        @SuppressWarnings("unused") Document document = getSignedDocumentByCertificate();
                        c++;
                    } while (c < numOfIterations);
                }
            });
            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_SIGNING_CERTIFICATE_USING_STATIC() {
        try {
            final Date now = new Date();
            warmUpJVM();
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    int c = 0;
                    do {
                        @SuppressWarnings("unused") Document document = getSignedDocumentByCertificate_STATIC_PKI();
                        c++;
                    } while (c < numOfIterations);
                }
            });
            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_SIGNING_HMAC() {
        try {
            final Date now = new Date();
            warmUpJVM();
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    int c = 0;
                    do {
                        @SuppressWarnings("unused") Document document = getSignedDocumentByHMac();
                        c++;
                    } while (c < numOfIterations);
                }
            });
            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_SIGNING_HMAC_USING_STATIC() {
        try {
            final Date now = new Date();
            warmUpJVM();
            Thread thread = new Thread(new Runnable() {
                @Override
                public void run() {
                    int c = 0;
                    do {
                        @SuppressWarnings("unused") Document document = getSignedDocumentByHMac_STATIC_KEY();
                        c++;
                    } while (c < numOfIterations);
                }
            });
            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_VALIDATING_CERTIFICATE() {
        final Date now = new Date();
        final Document signedDocument = getSignedDocumentByCertificate();
        try {
            final X509Certificate validatorCertificate = getCertificateFromLocalKeyStore("saml:idp.telenor.no");

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
                    } while (c < numOfIterations);
                }
            });

            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_VALIDATING_CERTIFICATE_USING_STATIC() {
        try {
            final Date now = new Date();
            final Document signedDocument = getSignedDocumentByCertificate_STATIC_PKI();
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
                    } while (c < numOfIterations);
                }
            });

            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_VALIDATING_HMAC() {
        final Date now = new Date();
        final Document signedDocument = getSignedDocumentByHMac();
        try {
            HMacUtils.setHashType(HMacUtils.DEFAULT_HASH_TYPE);
            KeyStoreUtils.setKeystoreType("JCEKS");
            final Key hmacKey = getAESKeyFromLocalKeyStore("my-secret", "vegard");

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
                    } while (c < numOfIterations);
                }
            });

            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } finally {
            resetDocument();
        }
    }

    private static void runPerformanceTesting_VALIDATING_HMAC_USING_STATIC() {
        try {
            final Date now = new Date();
            final Document signedDocument = getSignedDocumentByHMac_STATIC_KEY();
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
                    } while (c < numOfIterations);
                }
            });

            long start = System.nanoTime();
            thread.run();
            long stop = System.nanoTime();
            long resultInNanos = stop - start;
            outputResult(now, resultInNanos);
        } finally {
            resetDocument();
        }
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

    private static void warmUpJVM() {
        @SuppressWarnings("unused") double sum = 0;
        for (int i = 0; i < 1000; i++) {
            for (int j = 0; j < 1000; j++) {
                sum += (double) i + (double) j % i * 1;
            }
        }
    }

    private static void outputResult(final Date initiated, final long nanoResult) {
        String methodCallingMe = "";
        StackTraceElement[] stackTrace = Thread.currentThread().getStackTrace();
        if (stackTrace != null && stackTrace.length >= 2) {
            StackTraceElement fromMethod = stackTrace[2];
            if (fromMethod != null) {
                methodCallingMe = fromMethod.getMethodName();
            }
        }
        results.add(new Result.Builder()
                .nanoResult(nanoResult)
                .callingMethod(methodCallingMe)
                .documentUsed((Strings.isNullOrEmpty(documentLocation)) ?
                        String.format("Loaded from classpath (%s)", DEFAULT_DOCUMENT) :
                        documentLocation)
                .finished(new Date())
                .numOfIterations(numOfIterations)
                .initiated(initiated)
                .build()
        );
    }

    private static void resetDocument() {
        document = null;
        if (Strings.isNullOrEmpty(documentLocation)) {
            document = getDocumentFromInputStream(FileUtils.getInstance().getFileAsInputStreamFromClassPath(DEFAULT_DOCUMENT));
        } else {
            document = getDocumentFromFile(FileUtils.getInstance().getFileFromFileSystem(documentLocation));
        }
        if (Strings.isNullOrEmpty(reference_id)) {
            reference_id = "#" + document.getElementsByTagName("saml:Assertion").item(0).getAttributes().getNamedItem("ID").getTextContent();
        }
    }

    private static Key getAESKeyFromLocalKeyStore(String alias, String password) throws KeyStoreException {
        KeyStoreUtils.setKeystoreType("JCEKS");
        final KeyStore keyStore = getKeyStoreByName("fun.jceks", "vegard");
        return KeyStoreUtils.getKey(keyStore, alias, password);
    }

    private static KeyStore getKeyStoreByName(String name, String password) {
        final KeyStore keystore = KeyStoreUtils.load(name, password, true);
        if (keystore != null) {
            return keystore;
        }
        throw new IllegalArgumentException("Unable to load KeyStoreByName.");
    }

    private static X509Certificate getCertificateFromLocalKeyStore(String alias) throws KeyStoreException {
        KeyStoreUtils.setKeystoreType("JKS");
        final KeyStore keyStore = getKeyStoreByName("fun_certificates.jks", "telenor");
        return KeyStoreUtils.getCertificate(keyStore, alias);
    }

    private static Document getDocumentFromInputStream(final InputStream is) {
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

    private static Document getDocumentFromFile(final File file) {
        if (file != null) {
            try {
                return getDocumentFromInputStream(new FileInputStream(file));
            } catch (FileNotFoundException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    private static void writeResultSet() {
        System.out.println(Result.generateResultSetString(results));
    }

}
