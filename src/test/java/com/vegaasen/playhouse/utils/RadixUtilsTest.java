package com.vegaasen.playhouse.utils;

import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public class RadixUtilsTest {

    public static final String MESSAGE = "Vegard is oh so cool";
    public static final String MESSAGE_HEX = "566567617264206973206f6820736f20636f6f6c";

    @Test
    public void shouldGenerateStringToHex() {
        final String expectedHexMessage = MESSAGE_HEX;
        final String result = RadixUtils.convertToHex(MESSAGE);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(expectedHexMessage, result);
    }

    @Test
    public void shouldGenerateStringToHex_ISO_8859_1() {
        final String expectedHexMessage = "566567617264206973206f6820736f20636f6f6ce6f8e5";
        RadixUtils.setEncoding("ISO-8859-1");
        final String result = RadixUtils.convertToHex(MESSAGE + "æøå");
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(expectedHexMessage, result);
    }

    @Test
    public void shouldReturnEmptyString_wrong_encoding() {
        RadixUtils.setEncoding("NO-SUCH-ENCODING-TYPE");
        final String result = RadixUtils.convertToHex(MESSAGE);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    public void shouldConvertBackFromHexString() {
        final String expectedHexMessage = MESSAGE;
        final String result = RadixUtils.convertFromHex(MESSAGE_HEX);
        assertNotNull(result);
        assertTrue(!result.isEmpty());
        assertEquals(result, expectedHexMessage);
    }

    @After
    public void tearDown() {
        RadixUtils.setEncoding(RadixUtils.DEFAULT_ENCODING);
    }

}
