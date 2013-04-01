package com.vegaasen.playhouse.utils;

import com.google.common.io.BaseEncoding;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class AesUtils {

    public static final int
            AES_KEY_SIZE_128 = 128,
            AES_KEY_SIZE_192 = 192,
            AES_KEY_SIZE_256 = 256;

    private AesUtils() {
    }

    public static SecretKey generateAESKey(final int bitLength)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyGenerator generator = KeyGenerator.getInstance("AES", "SunJCE");
        generator.init(bitLength, new SecureRandom());
        return generator.generateKey();
    }

    /**
     * Converts a Key to base64 / Portable format
     *
     * @param key SecretKey (could be anything, but
     * @return base64-representation of the key
     * @throws Exception
     */
    public static String convertAESKeyToPortableFormat(final Key key) throws Exception {
        if (key != null) {
            final String based = BaseEncoding.base64().encode(key.getEncoded());
            if (based != null && !based.isEmpty()) {
                return based;
            }
            throw new Exception("Unable to convert.");
        }
        throw new IllegalArgumentException("Argument (Key) cannot be null.");
    }

    public static byte[] convertFromPortableFormatToByteArray(final String portableString) throws Exception {
        if (portableString != null && !portableString.isEmpty()) {
            final byte[] converted = BaseEncoding.base64().decode(portableString);
            if (converted != null && converted.length > 0) {
                return converted;
            }
            throw new Exception("Unable to convert back.");
        }
        throw new IllegalArgumentException("Argument (PortableString) cannot be null.");
    }

    public static Key convertFromPortableToAESKey(final String portableString) throws Exception {
        final byte[] converted = convertFromPortableFormatToByteArray(portableString);
        return convertFromByteArrayToAESKey(converted);
    }

    public static Key convertFromByteArrayToAESKey(final byte... converted) throws Exception {
        if (converted != null && converted.length > 0) {
            final Key key = new SecretKeySpec(converted, 0, converted.length, "AES");
            if (key.getEncoded() != null) {
                return key;
            }
            throw new Exception("Unable to convert to AESKey.");
        }
        throw new IllegalArgumentException("Argument (Converted) cannot be null.");
    }

    public static Key convertFromPortableToKey(final String portableString, final String keyType) throws Exception {
        final byte[] converted = convertFromPortableFormatToByteArray(portableString);
        final Key key = new SecretKeySpec(converted, 0, converted.length, keyType);
        if (key.getEncoded() != null) {
            return key;
        }
        throw new Exception("Unable to convert to AESKey.");
    }

}
