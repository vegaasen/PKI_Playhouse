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
            return String.format("%040x", new BigInteger(message.getBytes(encoding)));
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
        return EMPTY;
    }

    public static String convertFromHex(final String hexMessage) {
        final StringBuilder str = new StringBuilder();
        for (int i = 0; i < hexMessage.length(); i += 2) {
            str.append((char) Integer.parseInt(hexMessage.substring(i, i + 2), 16));
        }
        return str.toString();
    }

    public static void setEncoding(String enc) {
        encoding = enc;
    }
}
