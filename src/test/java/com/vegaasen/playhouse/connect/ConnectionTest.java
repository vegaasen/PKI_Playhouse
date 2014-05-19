package com.vegaasen.playhouse.connect;

import com.vegaasen.playhouse.utils.KeyStoreUtils;
import org.junit.Before;
import org.junit.Test;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.InputStream;
import java.net.URL;
import java.security.KeyStore;
import java.util.Scanner;

import static org.junit.Assert.*;

/**
 * @author <a href="mailto:vegard.aasen@telenor.com">Vegard Aasen</a>
 * @since 1:52 PM
 */
public final class ConnectionTest {

    private URL to;
    private SSLSocketFactory socketFactory;

    @Before
    public void setUp() throws Exception {
        configureKeyStore();
        to = new URL("https://laasekode.kjedehuset.no");
    }

    @Test
    public void shouldBeAbleToConnectToSite() {
        try {
            HttpsURLConnection connection = (HttpsURLConnection) to.openConnection();
            assertNotNull(connection);
            connection.setSSLSocketFactory(socketFactory);
            connection.setDoOutput(true);
            connection.connect();
            assertNotNull(connection.getResponseCode());
            assertTrue(connection.getResponseCode() > 0);
            connection.connect();
            assertNotNull(connection.getServerCertificates());
            InputStream stream = connection.getInputStream();
            assertNotNull(stream);
            Scanner s = new java.util.Scanner(stream);
            while (s.hasNext()) {
                System.out.print(s.next());
            }
        } catch (Exception e) {
            fail();
        }
    }

    private void configureKeyStore() throws Exception {
        KeyStore keyStore = KeyStoreUtils.load(ConnectionTest.class.getResourceAsStream("/crap.jks"), "telenor");
        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(keyStore);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tmf.getTrustManagers(), null);
        socketFactory = ctx.getSocketFactory();
    }

}
