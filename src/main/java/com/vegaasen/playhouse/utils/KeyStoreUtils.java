package com.vegaasen.playhouse.utils;

import com.google.common.collect.Lists;
import com.google.common.io.Closeables;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.X500Name;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Enumeration;
import java.util.List;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class KeyStoreUtils {

    public static final String DEFAULT_KEYSTORE_PASSWORD;
    public static final File DEFAULT_KEYSTORE_FILE;

    public static String keystoreType = "JKS"; //default

    static {
        DEFAULT_KEYSTORE_FILE = FileUtils.getInstance().getFileFromClassPath(
                PropertiesUtils.getInstance().getProperty("keystore.name")
        );
        DEFAULT_KEYSTORE_PASSWORD =
                PropertiesUtils.getInstance().getProperty("keystore.password");
    }

    public static KeyStore load(final String keyStoreName, final String keyStorePassword) {
        File keyStoreFile = FileUtils.getInstance().getFileFromClassPath(keyStoreName);
        try {
            final KeyStore ks = load(keyStoreFile, keyStorePassword);
            if (ks != null) {
                return ks;
            }
            throw new KeyStoreException("Unable to load KeyStore.");
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;
    }

    public static KeyStore load() throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException {
        return load(DEFAULT_KEYSTORE_FILE, DEFAULT_KEYSTORE_PASSWORD);
    }

    public static KeyStore load(File storeFile) throws KeyStoreException, IOException, NoSuchAlgorithmException,
            CertificateException {
        return load(storeFile, DEFAULT_KEYSTORE_PASSWORD);
    }

    public static KeyStore load(File storeFile, String storePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        InputStream is = null;
        try {
            is = new FileInputStream(storeFile);
            return load(is, storePassword);
        } finally {
            Closeables.closeQuietly(is);
        }
    }

    public static KeyStore load(byte[] data, String storePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        InputStream is = null;

        try {
            is = new ByteArrayInputStream(data);
            return load(is, storePassword);
        } finally {
            Closeables.closeQuietly(is);
        }
    }

    public static KeyStore load(InputStream is, String storePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        KeyStore keystore = create();
        if (storePassword == null || storePassword.isEmpty()) {
            storePassword = DEFAULT_KEYSTORE_PASSWORD;
        }
        keystore.load(is, storePassword.toCharArray());
        return keystore;
    }

    public static List<String> getAliases(KeyStore keystore) throws KeyStoreException {
        List<String> ret = Lists.newArrayList();

        Enumeration<String> aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            ret.add(alias);
        }

        return ret;
    }

    private static KeyStore create() {
        KeyStore keystore;
        try {
            keystore = KeyStore.getInstance(keystoreType);
        } catch (KeyStoreException e) {
            throw new IllegalStateException("Error building keystore", e);
        }
        return keystore;
    }

    public static KeyStore createEmpty(String storePassword) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, IOException {
        return load((InputStream) null, storePassword);
    }

    public static List<X509Certificate[]> getCertificateChains(KeyStore keystore) throws KeyStoreException {
        List<X509Certificate[]> chains = Lists.newArrayList();

        for (String alias : getAliases(keystore)) {
            X509Certificate[] certificateChain = (X509Certificate[]) keystore.getCertificateChain(alias);
            if (certificateChain == null) {
                continue;
            }
            chains.add(certificateChain);
        }
        return chains;
    }

    public static List<String> getKeyAliases(KeyStore keystore) throws KeyStoreException {
        List<String> ret = Lists.newArrayList();

        for (String alias : getAliases(keystore)) {
            if (keystore.isKeyEntry(alias)) {
                ret.add(alias);
            }
        }

        return ret;
    }

    public static Key getKey(final KeyStore keystore, final String alias, final String password) {
        if (keystore != null) {
            try {
                Key key = keystore.getKey(alias, password.toCharArray());
                if (key != null) {
                    return key;
                }
                throw new KeyStoreException(
                        String.format(
                                "Key not found with alias %s and password %s.",
                                alias,
                                password
                        )
                );
            } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
        }
        return null;
    }

    public static void createSelfSigned(KeyStore keystore, String alias, String keyPassword, X500Name x500Name,
                                        int validityDays, String keyAlgorithmName, int keySize, String signatureAlgName)
            throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, CertificateException,
            SignatureException, KeyStoreException {

        String providerName = null;
        CertAndKeyGen keypair = new CertAndKeyGen(keyAlgorithmName, signatureAlgName, providerName);

        keypair.generate(keySize);
        PrivateKey privKey = keypair.getPrivateKey();

        X509Certificate[] chain = new X509Certificate[1];

        Date startDate = new Date(System.currentTimeMillis() - 24L * 60L * 60L);
        chain[0] = keypair.getSelfCertificate(x500Name, startDate, (validityDays + 1) * 24L * 60L * 60L);

        keystore.setKeyEntry(alias, privKey, keyPassword.toCharArray(), chain);
    }

    public static void createSelfSigned(KeyStore keystore, String alias, String keyPassword, X500Name x500Name,
                                        int validity) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException,
            CertificateException, SignatureException, KeyStoreException {
        createSelfSigned(keystore, alias, keyPassword, x500Name, validity, "RSA", 2048, "SHA1WithRSA");
    }

    public static byte[] serialize(KeyStore keystore, String storePassword) throws KeyStoreException,
            NoSuchAlgorithmException, CertificateException, IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        try {
            keystore.store(baos, storePassword.toCharArray());
            return baos.toByteArray();
        } finally {
            Closeables.closeQuietly(baos);
        }
    }

    public static String getKeystoreType() {
        return keystoreType;
    }

    public static void setKeystoreType(final String type) {
        if (type != null && !type.isEmpty()) {
            keystoreType = type;
        }
    }

}