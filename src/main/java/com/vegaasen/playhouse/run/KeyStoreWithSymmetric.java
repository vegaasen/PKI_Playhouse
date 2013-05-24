package com.vegaasen.playhouse.run;

import com.vegaasen.playhouse.types.HashType;
import com.vegaasen.playhouse.utils.KeyStoreUtils;
import com.vegaasen.playhouse.utils.KeyUtils;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.KeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

/**
 * This is used to generate a KeyStore with a symmetric key that is loaded through input.
 * It will then try to save the keystore to a given path/location on the drive
 *
 * @author <a href="vegard.aasen@telenor.com">Vegard Aasen</a>
 */
public class KeyStoreWithSymmetric {

    private static final int
            ARG_KEY = 0,
            ARG_LOCATION = 1,
            ARG_ALIAS = 2,
            ARG_PASSWORD = 3;

    private static KeyStore keyStore;

    public static void main(String... args) {
        if (args != null && args.length > 2) {
            final String keyInHex = args[ARG_KEY];
            final String location = args[ARG_LOCATION];
            final String alias = args[ARG_ALIAS];
            if (keyInHex != null && !keyInHex.isEmpty() && alias != null &&
                    !alias.isEmpty() && location != null && !location.isEmpty()) {
                try {
                    byte[] symmetricKeyAsByte = KeyUtils.convertFromPortableHexFormatToByteArray(keyInHex);
                    if (symmetricKeyAsByte != null && symmetricKeyAsByte.length > 0) {
                        final SecretKey secretKey = KeyUtils.convertFromByteArrayToSecretKey(HashType.AES, symmetricKeyAsByte);
                        if (secretKey != null) {
                            String password = "";
                            if (args.length > 3) {
                                password = args[ARG_PASSWORD];
                            }
                            keyStore = getNewOrExistingKeyStore(password, location);
                            if (keyStore != null) {
                                addKeyToKeyStore(secretKey, alias, password);
                                saveKeyStore(alias, password, location);
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
            System.exit(1);
        }
        System.out.println("Usage: KeyStoreWithSymmetric <theKeyInHexFormat> <location> <alias> <(optional) password>");
        System.exit(-1);
    }

    private static void addKeyToKeyStore(SecretKey secretKey, String alias, String password) {
        try {
            KeyStoreUtils.addKey(keyStore, secretKey, alias, password);
        } catch (KeyException | KeyStoreException e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

    private static KeyStore getNewOrExistingKeyStore(final String password, final String location) {
        KeyStoreUtils.setKeystoreType(KeyStoreUtils.KEY_STORE_TYPE_JCEKS);
        KeyStore keyStore = null;
        try {
            File keyStoreFile = new File(location);
            if (!keyStoreFile.exists()) {
                System.out.println("Will create an empty keyStore.");
                keyStore = KeyStoreUtils.createEmpty(password);
            } else {
                System.out.println("Will load existing keyStore.");
                keyStore = KeyStoreUtils.load(keyStoreFile, password);
            }
        } catch (KeyStoreException | NoSuchAlgorithmException | CertificateException | IOException e) {
            e.printStackTrace();
        }
        return keyStore;
    }

    private static void saveKeyStore(final String alias, final String password, String location) {
        try {
            if (keyStore.containsAlias(alias)) {
                try {
                    KeyStoreUtils.saveKeyStore(keyStore, password, location);
                    System.out.println(String.format("Saved to: {%s} ", location));
                } catch (IOException e) {
                    e.printStackTrace();
                }
            } else {
                System.out.println(String.format("Unable to find alias %s", alias));
            }
        } catch (KeyStoreException e) {
            e.printStackTrace();
            System.exit(-1);
        }
    }

}
