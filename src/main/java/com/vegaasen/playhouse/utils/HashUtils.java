package com.vegaasen.playhouse.utils;

import com.vegaasen.playhouse.types.HashType;

import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.logging.Logger;

/**
 * @author <a href="vegard.aasen@telenor.com">t769765</a>
 */
public final class HashUtils {

    private static final Logger LOG = Logger.getLogger(HashUtils.class.getName());

    private static final String UTF_8 = "UTF-8";
    private static final String EMPTY = "";

    private HashUtils() {
    }

    public static final class Sha512 {

        private static final HashType ALGORITHM = HashType.SHA_512;

        public static String getHashAsHex(final String password, final byte[] salt) {
            return RadixUtils.convertToHex(getHash(password, salt));
        }

        public static byte[] getHash(final String password, final byte[] salt) {
            return HashUtils.getHash(password, salt, ALGORITHM);
        }

    }

    public static final class Sha384 {

        private static final HashType ALGORITHM = HashType.SHA_384;

        public static String getHashAsHex(final String password, final byte[] salt) {
            return RadixUtils.convertToHex(getHash(password, salt));
        }

        public static byte[] getHash(final String password, final byte[] salt) {
            return HashUtils.getHash(password, salt, ALGORITHM);
        }

    }

    public static final class Sha256 {

        private static final HashType ALGORITHM = HashType.SHA_256;

        public static String getHashAsHex(final String password, final byte[] salt) {
            return RadixUtils.convertToHex(getHash(password, salt));
        }

        public static byte[] getHash(final String password, final byte[] salt) {
            return HashUtils.getHash(password, salt, ALGORITHM);
        }

    }

    private static byte[] getHash(final String password, final byte[] salt, final HashType algorithm) {
        try {
            final MessageDigest digest = MessageDigest.getInstance(algorithm.getType());
            digest.reset();
            digest.update(salt);
            return digest.digest(password.getBytes(UTF_8));
        } catch (final NoSuchAlgorithmException | UnsupportedEncodingException e) {
            LOG.info("Unable to translate message." + e.getMessage());
        }
        return EMPTY.getBytes();
    }

}
