package com.vegaasen.playhouse.utils;

import com.carrotsearch.junitbenchmarks.BenchmarkRule;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TestRule;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="vegard.aasen@telenor.com">t769765</a>
 */
public class HashUtilsPerformanceTest {

    private static final int MAX_ROUNDS = 100000, MAX_THREADS = 70;
    private static final String PASSWORD = "myPassword";
    private static final byte[] SALT = Long.toString(System.currentTimeMillis()).getBytes();

    @Rule
    public TestRule benchmarkRun = new BenchmarkRule();

    @Test
    public void hash_sha512_password_loadsOfRounds() {
        final Runnable runnable1 = new Runnable() {
            @Override
            public void run() {
                int i = 0;
                do {
                    final byte[] result = HashUtils.Sha512.getHash(PASSWORD, SALT);
                    assertNotNull(result);
                    assertTrue(result.length > 0);
                    i++;
                } while (i < MAX_ROUNDS);
            }
        };
        final int maxThreads = MAX_THREADS;
        for (int i = 0; i < maxThreads; i++) {
            Thread thread = new Thread(runnable1);
            thread.start();
        }
    }

    @Test
    public void hash_sha256_password_loadsOfRounds() {
        final Runnable runnable1 = new Runnable() {
            @Override
            public void run() {
                int i = 0;
                do {
                    final byte[] result = HashUtils.Sha256.getHash(PASSWORD, SALT);
                    assertNotNull(result);
                    assertTrue(result.length > 0);
                    i++;
                } while (i < MAX_ROUNDS);
            }
        };
        final int maxThreads = MAX_THREADS;
        for (int i = 0; i < maxThreads; i++) {
            Thread thread = new Thread(runnable1);
            thread.start();
        }
    }

    @Test
    public void hash_sha384_password_loadsOfRounds() {
        final Runnable runnable1 = new Runnable() {
            @Override
            public void run() {
                int i = 0;
                do {
                    final byte[] result = HashUtils.Sha384.getHash(PASSWORD, SALT);
                    assertNotNull(result);
                    assertTrue(result.length > 0);
                    i++;
                } while (i < MAX_ROUNDS);
            }
        };
        final int maxThreads = MAX_THREADS;
        for (int i = 0; i < maxThreads; i++) {
            Thread thread = new Thread(runnable1);
            thread.start();
        }
    }

}
