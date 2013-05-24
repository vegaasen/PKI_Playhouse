package com.vegaasen.playhouse.utils;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class RadixUtils {

    public static final String DEFAULT_ENCODING = "UTF-8";

    private static final String EMPTY = "";

    private static String encoding;

    static {
        encoding = DEFAULT_ENCODING;
    }

    private RadixUtils() {
    }

    public static String convertToHex(final String message) {
        try {
            return convertToHex(message.getBytes(encoding));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return EMPTY;
    }

    public static String convertToHex(final byte[] message) {
        return String.format("%040x", new BigInteger(message));
    }

    public static byte[] convertFromHex(final String hexMessage) {
        return stringToBytes(hexMessage);
    }

    public static void setEncoding(String enc) {
        encoding = enc;
    }

    private static int parseHexDigit(final char c) {
        if (c >= '0' && c <= '9') {
            return c - '0';
        }
        if (c >= 'a' && c <= 'f') {
            return 10 + c - 'a';
        }
        if (c >= 'A' && c <= 'F') {
            return 10 + c - 'A';
        }
        throw new RuntimeException("Unparsable hex digit `" + c + "'");
    }

    private static byte[] stringToBytes(final String s) {
        final char[] c = s.toCharArray();
        final byte[] b = new byte[c.length / 2];
        int w = 0;
        for (int q = 0; q < b.length; q++) {
            final int b1 = parseHexDigit(c[w++]);
            final int b2 = parseHexDigit(c[w++]);
            b[q] = (byte) (b1 << 4 | b2);
        }
        return b;
    }
}
