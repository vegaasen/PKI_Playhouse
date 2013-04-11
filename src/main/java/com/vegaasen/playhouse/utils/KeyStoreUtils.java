package com.vegaasen.playhouse.utils;

import com.google.common.base.Strings;
import com.google.common.collect.Lists;
import com.google.common.io.Closeables;
import sun.security.x509.*;

import java.math.BigInteger;
import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class KeyStoreUtils {

    public static final String
            KEY_PRIVATE = "KEY_PRIVATE",
            KEY_PUBLIC = "KEY_PUBLIC";
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

    public static KeyStore load(final String keyStoreName, final String keyStorePassword, final boolean useInputStream) {
        try {
            if (useInputStream) {
                final InputStream is = FileUtils.getInstance().getFileAsInputStreamFromClassPath(keyStoreName);
                if (is != null) {
                    return load(is, keyStorePassword);
                }
                return null;
            }
            final File keyStoreFile = FileUtils.getInstance().getFileFromClassPath(keyStoreName);
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
            Closeables.close(is, true);
        }
    }

    public static KeyStore load(byte[] data, String storePassword) throws KeyStoreException, IOException,
            NoSuchAlgorithmException, CertificateException {
        InputStream is = null;

        try {
            is = new ByteArrayInputStream(data);
            return load(is, storePassword);
        } finally {
            Closeables.close(is, true);
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

    public static X509Certificate getCertificate(final KeyStore keyStore, final String alias) throws KeyStoreException {
        if (keyStore != null && !Strings.isNullOrEmpty(alias)) {
            try {
                return (X509Certificate) keyStore.getCertificate(alias);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }
        throw new KeyStoreException(
                String.format(
                        "The key {%s} is not a valid KeyPair.",
                        alias
                )
        );
    }

    public static Key getKey(final KeyStore keyStore, final String alias, final String password) throws KeyStoreException {
        if (keyStore != null && !Strings.isNullOrEmpty(alias) && !Strings.isNullOrEmpty(password)) {
            try {
                Key key = keyStore.getKey(alias, password.toCharArray());
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
        throw new KeyStoreException(
                String.format(
                        "The key {%s} is not a valid KeyPair.",
                        alias
                )
        );
    }

    public static Map<String, Object> getKeyPair(final KeyStore keyStore, final String alias, final String password)
            throws KeyStoreException {
        if (keyStore != null && !Strings.isNullOrEmpty(alias) && !Strings.isNullOrEmpty(password)) {
            try {
                final KeyStore.Entry entry;
                try {
                    KeyStore.PasswordProtection protection = null;
                    if (password != null) {
                        protection = new KeyStore.PasswordProtection(password.toCharArray());
                    }
                    entry = keyStore.getEntry(alias, protection);
                } catch (final Exception e) {
                    throw new KeyStoreException(e);
                }
                if (entry == null) {
                    throw new KeyStoreException("Unable to load trusted certificate: Entry `" + alias + "' not found");
                }
                final X509Certificate certificate;
                PrivateKey privateKey = null;
                if (entry instanceof KeyStore.PrivateKeyEntry) {
                    certificate = (X509Certificate) ((KeyStore.PrivateKeyEntry) entry).getCertificate();
                    privateKey = ((KeyStore.PrivateKeyEntry) entry).getPrivateKey();
                } else if (entry instanceof KeyStore.TrustedCertificateEntry) {
                    certificate = (X509Certificate) ((KeyStore.TrustedCertificateEntry) entry).getTrustedCertificate();
                } else {
                    throw new RuntimeException("KeyStore entry of unexpected type `" + entry.getClass().getName() + "'");
                }
                if (certificate == null) {
                    throw new KeyStoreException("Unable to load trusted certificate: Entry doesn't contain a certificate");
                }
                final Map<String, Object> certificates = new HashMap<>();
                certificates.put(KEY_PUBLIC, certificate);
                certificates.put(KEY_PRIVATE, privateKey);
                return certificates;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        throw new KeyStoreException(
                String.format(
                        "The key {%s} is not a valid KeyPair.",
                        alias
                )
        );
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
            Closeables.close(baos, true);
        }
    }

    public static X509Certificate getCertificateFromByteArray(final byte[] bytes, String algorithm) {
        if (bytes != null) {
            algorithm = (!algorithm.equals("") ? algorithm : "X509");
            try {
                CertificateFactory certificateFactory = CertificateFactory.getInstance(algorithm);
                X509Certificate generatedCertificate = (X509Certificate) certificateFactory.generateCertificate(new ByteArrayInputStream(bytes));
                if (generatedCertificate != null) {
                    return generatedCertificate;
                }
            } catch (CertificateException e) {
                e.getStackTrace();
            }
        }
        return null;
    }

    public static X509Certificate generateCertificate(String dn, KeyPair pair, int days, String algorithm)
            throws GeneralSecurityException, IOException {
        PrivateKey privateKey = pair.getPrivate();
        X509CertInfo info = new X509CertInfo();
        Date from = new Date();
        Date to = new Date(from.getTime() + days * 86400000l);
        CertificateValidity interval = new CertificateValidity(from, to);
        BigInteger sn = new BigInteger(64, new SecureRandom());
        X500Name owner = new X500Name(dn);
        info.set(X509CertInfo.VALIDITY, interval);
        info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(sn));
        info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(owner));
        info.set(X509CertInfo.ISSUER, new CertificateIssuerName(owner));
        info.set(X509CertInfo.KEY, new CertificateX509Key(pair.getPublic()));
        info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
        AlgorithmId algo = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);
        info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(algo));
        X509CertImpl cert = new X509CertImpl(info);
        cert.sign(privateKey, algorithm);
        algo = (AlgorithmId) cert.get(X509CertImpl.SIG_ALG);
        info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, algo);
        cert = new X509CertImpl(info);
        cert.sign(privateKey, algorithm);

        return cert;
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