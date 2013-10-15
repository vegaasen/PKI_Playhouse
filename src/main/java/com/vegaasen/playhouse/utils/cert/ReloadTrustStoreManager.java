package com.vegaasen.playhouse.utils.cert;

import com.vegaasen.playhouse.utils.CertificateImportUtils;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Class that implements TrustManager. We will use this class to reload the TrustManager during runtime
 * to be able to reflect all changes that has been made by e.g InstallUnknownCertificateUtils..
 *
 * @author <a href="mailto:vegard.aasen@telenor.com">Vegard Aasen</a>
 * @version 0.1.a
 * @since 0.1-SNAPSHOT
 */
public final class ReloadTrustStoreManager implements X509TrustManager {

    private final String trustStorePath;
    private X509TrustManager trustManager;
    private List<Certificate> tempCertList = new ArrayList<>();

    public ReloadTrustStoreManager(String trustStorePath) {
        if (trustStorePath != null && !trustStorePath.isEmpty()) {
            trustStorePath = CertificateImportUtils.getDefaultOutLocation();
        }
        this.trustStorePath = trustStorePath;
        try {
            reloadTrustManager();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private void reloadTrustManager() throws Exception {
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        try (InputStream in = new FileInputStream(trustStorePath)) {
            ts.load(in, null);
        }

        for (Object cert : tempCertList) {
            Certificate certificate = (Certificate) cert;
            ts.setCertificateEntry(UUID.randomUUID().toString(), certificate);
        }

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);

        TrustManager tms[] = tmf.getTrustManagers();
        for (TrustManager tm : tms) {
            if (tm instanceof X509TrustManager) {
                trustManager = (X509TrustManager) tm;
                return;
            }
        }
        throw new NoSuchAlgorithmException(
                "No X509TrustManager in TrustManagerFactory");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        trustManager.checkClientTrusted(x509Certificates, s);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
        try {
            trustManager.checkServerTrusted(x509Certificates, s);
        } catch (CertificateException cx) {
            trustManager.checkServerTrusted(x509Certificates, s);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return trustManager.getAcceptedIssuers();
    }
}
