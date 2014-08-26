package com.vegaasen.playhouse.utils;

import org.junit.Test;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class HashUtilsTest {

    private static final String PASSWORD = "myPassword";
    private static final byte[] SALT = Long.toString(System.currentTimeMillis()).getBytes();

    @Test
    public void hash_sha512_password_String() {
        final String result = HashUtils.Sha512.getHashAsHex(PASSWORD, SALT);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void hash_sha512_password() {
        final byte[] result = HashUtils.Sha512.getHash(PASSWORD, SALT);
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void hash_sha256_password_String() {
        final String result = HashUtils.Sha256.getHashAsHex(PASSWORD, SALT);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void hash_sha256_password() {
        final byte[] result = HashUtils.Sha256.getHash(PASSWORD, SALT);
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

    @Test
    public void hash_sha384_password_String() {
        final String result = HashUtils.Sha384.getHashAsHex(PASSWORD, SALT);
        assertNotNull(result);
        assertFalse(result.isEmpty());
    }

    @Test
    public void hash_sha384_password() {
        final byte[] result = HashUtils.Sha384.getHash(PASSWORD, SALT);
        assertNotNull(result);
        assertTrue(result.length > 0);
    }

}