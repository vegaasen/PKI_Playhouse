package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.utils.cert.ReloadTrustStoreManager;

import javax.net.ssl.*;
import java.io.*;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.logging.Logger;

/**
 * @author <a href="mailto:vegard.aasen@telenor.com">Vegard Aasen</a>
 * @since 9:28 AM
 */
public final class CertificateImportUtils {

    public static final String DEFAULT_FILE_NAME = "cacerts.jks";

    private static final Logger LOG = Logger.getLogger(CertificateImportUtils.class.getName());
    private static final String DEFAULT_FILE_TMP_NAME = "cacerts.tmp.jks";
    private static final String DEFAULT_FILE_FOLDER = System.getProperty("java.io.tmpdir");
    private static final String PORT_IDENTIFIER = ":";
    private static final int DEFAULT_TIMEOUT = 10000;
    private static final int DEFAULT_HTTPS_PORT = 443;
    private static final String EMPTY = "";

    /**
     * Tries to get all untrusted CAs from fullHostName and adds these to a new TrustStore
     * The new TrustStore needs to be reloaded by the application itself further on.
     *
     * @param fullHostName hostname (e.g www.telenor.no, www.telenor.no:8081)
     * @throws Exception _
     */
    public static String downloadAndImportCertificates(
            String fullHostName,
            String pathToExistingKeystore,
            final String keystoreOutputLocation,
            String keystorePassword
    ) throws Exception {
        if (fullHostName == null || fullHostName.isEmpty()) {
            throw new IllegalArgumentException("Hostname cannot be null or empty.");
        }
        if (keystorePassword == null) {
            keystorePassword = EMPTY;
            LOG.warning("Password not set. Setting password to empty-string.");
        }
        int port = DEFAULT_HTTPS_PORT;

        if (fullHostName.contains(":")) {
            String[] c = fullHostName.split(PORT_IDENTIFIER);
            if (c.length > 1) port = Integer.parseInt(c[1]);
            fullHostName = c[0];
        }

        if (pathToExistingKeystore == null) {
            LOG.info("No existing keystore defined. Will create a new keystore instead.");
            pathToExistingKeystore = getDefaultOutLocation();
        }

        InputStream in = null;
        try {
            in = new FileInputStream(pathToExistingKeystore);
        } catch (FileNotFoundException fe) {
            LOG.warning("The file that was supposed to be loaded was not found");
        }
        KeyStore ks;
        if (in != null) {
            ks = KeyStoreUtils.load(in, keystorePassword);
            in.close();
        } else {
            ks = KeyStoreUtils.createEmpty(keystorePassword);
        }

        final SSLContext context = SSLContext.getInstance("TLS");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ks);
        X509TrustManager defaultTrustManager = (X509TrustManager) tmf.getTrustManagers()[0];
        SavingTrustManager tm = new SavingTrustManager(defaultTrustManager);
        context.init(null, new TrustManager[]{tm}, null);
        SSLSocketFactory factory = context.getSocketFactory();

        LOG.info("Opening connection to " + fullHostName + ":" + port);
        SSLSocket socket = (SSLSocket) factory.createSocket(fullHostName, port);
        socket.setSoTimeout(DEFAULT_TIMEOUT);
        try {
            socket.startHandshake();
            socket.close();
            LOG.info("Already trusted.");
        } catch (SSLException e) {
            LOG.info("Not trusted, will try to fetch CAs");
        }

        X509Certificate[] chain = tm.chain;
        if (chain == null) {
            LOG.warning("Could not obtain server certificate chain");
            return EMPTY;
        }

        MessageDigest sha1 = MessageDigest.getInstance("SHA1");
        MessageDigest md5 = MessageDigest.getInstance("MD5");
        for (X509Certificate cert : chain) {
            sha1.update(cert.getEncoded());
            md5.update(cert.getEncoded());
        }

        final int k = 0;
        X509Certificate cert = chain[k];
        String alias = fullHostName + "-" + (1);
        ks.setCertificateEntry(alias, cert);

        String outPutLocation;
        if (keystoreOutputLocation == null || keystoreOutputLocation.isEmpty()) {
            outPutLocation = getDefaultOutLocation();

            File file = new File(outPutLocation);
            int i = 0;
            while (file.exists()) {
                i++;
                outPutLocation = String.format("%s.%s", getDefaultOutLocation(), i);
                LOG.info(String.format("File exists. Setting location to {%s} instead", outPutLocation));
                file = new File(outPutLocation);
            }
        } else {
            outPutLocation = keystoreOutputLocation;
        }
        try (final OutputStream out = new FileOutputStream(outPutLocation)) {
            ks.store(out, keystorePassword.toCharArray());
            LOG.info(String.format("File saved to the following location {%s}", outPutLocation));
        } catch (Exception e) {
            LOG.severe(String.format("Unable to write file to location {%s}", outPutLocation));
        }
        return outPutLocation;
    }

    public static String getDefaultOutLocation() {
        return String.format("%s/%s", DEFAULT_FILE_FOLDER, DEFAULT_FILE_NAME);
    }

    public static String getDefaultOutTmpLocation() {
        return String.format("%s/%s", DEFAULT_FILE_FOLDER, DEFAULT_FILE_TMP_NAME);
    }

    public static SSLContext getSSLContext(final String trustStorePath) throws Exception {
        TrustManager[] trustManagers = new TrustManager[]{new ReloadTrustStoreManager(trustStorePath)};

        SSLContext sslContext = SSLContext.getInstance("SSL");
        sslContext.init(null, trustManagers, new SecureRandom());

        return sslContext;
    }

    private static class SavingTrustManager implements X509TrustManager {

        private final X509TrustManager tm;
        private X509Certificate[] chain;

        SavingTrustManager(X509TrustManager tm) {
            this.tm = tm;
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return null;
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {

        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType)
                throws CertificateException {
            this.chain = chain;
            tm.checkServerTrusted(chain, authType);
        }
    }

}
