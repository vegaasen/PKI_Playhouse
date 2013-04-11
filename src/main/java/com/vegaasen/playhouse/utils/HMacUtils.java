package com.vegaasen.playhouse.utils;

import com.google.common.base.Strings;
import com.google.common.io.BaseEncoding;
import com.vegaasen.playhouse.types.HashType;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Todo: There is something strange happening when calling hmac.doFinal()! Different on 2nd try..? w.t.f
 *
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class HMacUtils {

    public static final String KEY_SIGNATURE_VALUE = "key_signValueHmac";
    public static final String KEY_DIGEST_VALUE = "key_digestedValue";
    public static final String KEY_ALGORITHM_USED = "key_algorithmUsed";
    public static final HashType DEFAULT_HASH_TYPE = HashType.HMAC_SHA_1;

    private static final String PSEUDO_RANDOM_IVSPEC = "1234567812345678";
    private static final String SUN_JCE_PROVIDER_ABBR = "SunJCE";

    private static HashType hashType = DEFAULT_HASH_TYPE;
    private static Cipher cipher = null;

    private HMacUtils() {
    }

    /**
     * This will generate a Map (hence the Container-name) that contains three elements.
     * These are:
     *  -digested value
     *  -signature value
     *  -hashType used (e.g sha-1)
     *
     * @param aesKey They key to sign with
     * @param message The message to generate hmac for
     * @return container with lots of stuff
     */
    public static Map<String, String> generateIntegrityContainer(final Key aesKey, final String message) {
        configureSecurity();
        if (aesKey != null) {
            final IvParameterSpec spec = createCtrIvForAES();
            try {
                final Mac hMac = Mac.getInstance(hashType.getType(), SUN_JCE_PROVIDER_ABBR);
                final Key hMacKey = new SecretKeySpec(aesKey.getEncoded(), hashType.getType());

                cipher.init(Cipher.ENCRYPT_MODE, aesKey, spec);
                byte[] encryptedCipherValue = new byte[cipher.getOutputSize(message.length() + hMac.getMacLength())];
                int encryptedCipherValueLength = cipher.update(message.getBytes(), 0, message.length(), encryptedCipherValue, 0);
                hMac.init(hMacKey);
                hMac.update(message.getBytes());
                int storedBytesInOutput = cipher.doFinal(
                        hMac.doFinal(),
                        0,
                        hMac.getMacLength(),
                        encryptedCipherValue,
                        encryptedCipherValueLength
                );
                if (storedBytesInOutput > 0 && hMac != null) {
                    Map<String, String> converted = new LinkedHashMap<>();
                    converted.put(KEY_SIGNATURE_VALUE, BaseEncoding.base64().encode(hMac.doFinal()));
                    converted.put(KEY_DIGEST_VALUE, BaseEncoding.base64().encode(encryptedCipherValue));
                    converted.put(KEY_ALGORITHM_USED, hashType.getType());
                    return converted;
                }
            } catch (NoSuchAlgorithmException |
                    NoSuchProviderException |
                    InvalidAlgorithmParameterException |
                    InvalidKeyException |
                    ShortBufferException |
                    BadPaddingException |
                    IllegalBlockSizeException e) {
                e.printStackTrace();
            }
        }
        return Collections.emptyMap();
    }

    /**
     * Returns a HMac as a String in base64.
     *
     * @param message value to create verification for
     * @return HMac as base64
     */
    public static Map<String, String> generateIntegrityContainer(final String message) {
        final Key aesKey = getLocalKeyStoreSecretKey();
        return generateIntegrityContainer(aesKey, message);
    }

    /**
     * Use this to verify integrity for a value.
     * This method will generate a new HMac based on an existing Key, from local keyStore, and then
     * create a HMac from this, based on the value. Eventually the provided Key and the existingHMac
     * will be compared and verified.
     *
     * @param aesKey         som secret key
     * @param signatureValue the existing generated Base64-encoded HMac
     * @param digestValue    the generated Base64-encoded Message
     * @param message        actual message. used for integrity-verification
     * @return true|false
     */
    public static boolean verifyIntegrity(
            final Key aesKey,
            final String signatureValue,
            final String digestValue,
            final String message) {
        if (!Strings.isNullOrEmpty(signatureValue) &&
                !Strings.isNullOrEmpty(digestValue) &&
                !Strings.isNullOrEmpty(message) &&
                aesKey != null
                ) {
            configureSecurity();
            final IvParameterSpec spec = createCtrIvForAES();
            try {
                final Mac hMac = Mac.getInstance(hashType.getType(), SUN_JCE_PROVIDER_ABBR);
                final Key hMacKey = new SecretKeySpec(aesKey.getEncoded(), hashType.getType());
                cipher.init(Cipher.DECRYPT_MODE, aesKey, spec);
                final byte[] decodedCipherValue = BaseEncoding.base64().decode(digestValue);
                byte[] plainText = cipher.doFinal(decodedCipherValue, 0, decodedCipherValue.length);
                int messageLength = plainText.length - hMac.getMacLength();
                byte[] messageAsByte = new String(plainText).substring(0, messageLength).getBytes();
                hMac.init(hMacKey);
                hMac.update(message.getBytes());
                byte[] messageHash = new byte[hMac.getMacLength()];
                System.arraycopy(plainText, messageLength, messageHash, 0, messageHash.length);
                if (messageHash != null && messageHash.length > 0) {
                    final byte[] signValue = BaseEncoding.base64().decode(signatureValue);
                    return MessageDigest.isEqual(
                            messageHash, hMac.doFinal()) &&
                            new String(messageAsByte).equals(message) &&
                            MessageDigest.isEqual(signValue, hMac.doFinal());
                }
            } catch (NoSuchAlgorithmException |
                    NoSuchProviderException |
                    InvalidAlgorithmParameterException |
                    InvalidKeyException |
                    BadPaddingException |
                    IllegalBlockSizeException e) {
                e.printStackTrace();
            }
            return false;
        }
        throw new IllegalArgumentException("Unable to verify integrity with the provided values.");
    }

    /**
     * Use this to verify integrity for a value.
     * This method will generate a new HMac based on an existing Key, from local keyStore, and then
     * create a HMac from this, based on the value. Eventually the provided Key and the existingHMac
     * will be compared and verified.
     *
     * @param signatureValue the existing generated Base64-encoded HMac
     * @param digestValue    the generated Base64-encoded Message
     * @param message        actual message. used for integrity-verification
     * @return true|false
     */
    public static boolean verifyIntegrity(
            final String signatureValue,
            final String digestValue,
            final String message) {
        return verifyIntegrity(getLocalKeyStoreSecretKey(), signatureValue, digestValue, message);
    }


    /**
     * Returns a HMac-key based on some existing key (may it be AES, Triple-DES or similar)
     *
     * @param key the key
     * @param hashType HashType
     * @return HMac-Key
     */
    public static Key getHMacKey(final Key key, final HashType hashType) {
        if(key!=null) {
            return getHMacKey(key.getEncoded(), hashType);
        }
        throw new IllegalArgumentException("Argument cannot be null or empty.");
    }

    /**
     * Returns a HMac-key based on some existing keyData (may it be AES, Triple-DES or similar)
     *
     * @param keyData byte stream containing the key
     * @param hashType HashType
     * @return HMac-Key
     */
    public static Key getHMacKey(final byte[] keyData, final HashType hashType) {
        if(keyData!=null && keyData.length>0) {
            return new SecretKeySpec(keyData, hashType.getType());
        }
        throw new IllegalArgumentException("Argument cannot be null or empty.");
    }

    private static Key getLocalKeyStoreSecretKey() {
        KeyStoreUtils.setKeystoreType(
                PropertiesUtils.getInstance().getProperty("keystore.type")
        );
        KeyStore funJceks = KeyStoreUtils.load(
                PropertiesUtils.getInstance().getProperty("keystore.name"),
                PropertiesUtils.getInstance().getProperty("keystore.password"),
                false);
        try {
            return KeyStoreUtils.getKey(
                    funJceks,
                    PropertiesUtils.getInstance().getProperty("keystore.entry.secret.name"),
                    PropertiesUtils.getInstance().getProperty("keystore.entry.secret.password")
            );
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static IvParameterSpec createCtrIvForAES() {
        return new IvParameterSpec(PSEUDO_RANDOM_IVSPEC.getBytes());
    }

    private static void configureSecurity() {
        if(cipher==null) {
            try {
                //AES/CTS/PKCS5Padding?
                cipher = Cipher.getInstance("AES/CTR/NoPadding", SUN_JCE_PROVIDER_ABBR);
            } catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
                e.printStackTrace();
            }
        }
        if (cipher == null) throw new IllegalStateException("Should not happen. Cipher has not been initialised.");
    }

    public static void setHashType(HashType alg) {
        hashType = alg;
    }

    public static HashType getHashType() {
        return hashType;
    }

}
