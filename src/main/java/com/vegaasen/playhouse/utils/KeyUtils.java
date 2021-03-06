package com.vegaasen.playhouse.utils;

import com.google.common.io.BaseEncoding;
import com.vegaasen.playhouse.types.HashType;

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
public final class KeyUtils {

    public static final int
            AES_KEY_SIZE_128 = 128,
            AES_KEY_SIZE_192 = 192,
            AES_KEY_SIZE_256 = 256;

    private KeyUtils() {
    }

    public static SecretKey generateAESKey(final int bitLength)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        final KeyGenerator generator = KeyGenerator.getInstance(HashType.AES.getType(), "SunJCE");
        generator.init(bitLength, new SecureRandom());
        return generator.generateKey();
    }

    public static byte[] convertFromPortableHexFormatToByteArray(final String portableString) throws Exception {
        if (portableString != null && !portableString.isEmpty()) {
            final byte[] converted = RadixUtils.convertFromHex(portableString);
            if(converted!=null && converted.length>0) {
                return converted;
            }
            throw new Exception("Unable to convert back.");
        }
        throw new IllegalArgumentException("Argument (PortableString) cannot be null.");
    }

    public static SecretKey convertFromPortableHexToSecretKey(final String portableString, final HashType hashType)
            throws Exception{
        final byte[] converted = convertFromPortableHexFormatToByteArray(portableString);
        final SecretKey key = new SecretKeySpec(converted, 0, converted.length, hashType.getType());
        if (key.getEncoded() != null) {
            return key;
        }
        throw new Exception("Unable to convert to Key.");
    }

    /**
     * Converts a Key to base64 / Portable format
     *
     * @param key SecretKey (could be anything, but
     * @return base64-representation of the key
     * @throws Exception
     */
    public static String convertKeyToPortableFormat(final Key key) throws Exception {
        if (key != null) {
            final String based = BaseEncoding.base64().encode(key.getEncoded());
            if (based != null && !based.isEmpty()) {
                return based;
            }
            throw new Exception("Unable to convert.");
        }
        throw new IllegalArgumentException("Argument (Key) cannot be null.");
    }

    public static String convertKeyToPortableFormatHex(final Key key) throws Exception {
        if (key != null) {
            final String hexed = RadixUtils.convertToHex(key.getEncoded());
            if (hexed != null && !hexed.isEmpty()) {
                return hexed;
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

    public static Key convertFromPortableToKey(final String portableString, final HashType hashType) throws Exception {
        final byte[] converted = convertFromPortableFormatToByteArray(portableString);
        return convertFromByteArrayToKey(hashType, converted);
    }

    public static Key convertFromPortableToKey(final String portableString, final String keyType) throws Exception {
        final byte[] converted = convertFromPortableFormatToByteArray(portableString);
        final Key key = new SecretKeySpec(converted, 0, converted.length, keyType);
        if (key.getEncoded() != null) {
            return key;
        }
        throw new Exception("Unable to convert to Key.");
    }

    public static SecretKey convertFromPortableToSecretKey(final String portableString, final HashType hashType) throws Exception{
        final byte[] converted = convertFromPortableFormatToByteArray(portableString);
        final SecretKey key = new SecretKeySpec(converted, 0, converted.length, hashType.getType());
        if (key.getEncoded() != null) {
            return key;
        }
        throw new Exception("Unable to convert to Key.");
    }

    public static Key convertFromByteArrayToKey( final HashType hashType, final byte... converted) throws Exception {
        if (converted != null && converted.length > 0) {
            final Key key = new SecretKeySpec(converted, 0, converted.length, hashType.getType());
            if (key.getEncoded() != null) {
                return key;
            }
            throw new Exception("Unable to convert to Key.");
        }
        throw new IllegalArgumentException("Argument (Converted) cannot be null.");
    }

    public static SecretKey convertFromByteArrayToSecretKey(final HashType hashType, final byte... converted) throws Exception{
        if(converted!=null && converted.length>0) {
            return new SecretKeySpec(converted, hashType.getType());
        }
        throw new Exception("Unable to convert to Key.");
    }

}
