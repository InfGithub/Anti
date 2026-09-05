package com.inf.anti;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Random;

import org.junit.jupiter.api.Test;

import com.inf.anti.crypt.Crypter;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CrypterTest {

    private static final byte[] PASSWORD = "correct horse battery staple".getBytes(StandardCharsets.UTF_8);

    private static Crypter crypter() {
        return new Crypter(1 << 20);
    }

    private static byte[] bytes(int length) {
        return new byte[length];
    }

    private static byte[] copy(byte[] src) {
        byte[] dst = new byte[src.length];
        System.arraycopy(src, 0, dst, 0, src.length);
        return dst;
    }

    @Test
    void roundTripRestoresPlaintext() {
        byte[] plain = "attack at dawn".getBytes(StandardCharsets.UTF_8);
        byte[] salt = bytes(32);
        byte[] mac = bytes(32);

        crypter().encryption(PASSWORD, plain, salt, mac);
        crypter().decryption(PASSWORD, plain, salt, mac);

        assertArrayEquals("attack at dawn".getBytes(StandardCharsets.UTF_8), plain);
    }

    @Test
    void wrongPasswordFails() {
        byte[] plain = "secret message".getBytes(StandardCharsets.UTF_8);
        byte[] salt = bytes(32);
        byte[] mac = bytes(32);

        crypter().encryption(PASSWORD, plain, salt, mac);

        byte[] wrong = "a different key".getBytes(StandardCharsets.UTF_8);
        assertThrows(Error.class, () -> crypter().decryption(wrong, plain, salt, mac));
    }

    @Test
    void tamperedCipherFails() {
        byte[] plain = "integrity matters".getBytes(StandardCharsets.UTF_8);
        byte[] salt = bytes(32);
        byte[] mac = bytes(32);

        crypter().encryption(PASSWORD, plain, salt, mac);
        plain[5] ^= 0x01;

        assertThrows(Error.class, () -> crypter().decryption(PASSWORD, plain, salt, mac));
    }

    @Test
    void tamperedMacFails() {
        byte[] plain = "tamper the tag".getBytes(StandardCharsets.UTF_8);
        byte[] salt = bytes(32);
        byte[] mac = bytes(32);

        crypter().encryption(PASSWORD, plain, salt, mac);
        mac[0] ^= 0x01;

        assertThrows(Error.class, () -> crypter().decryption(PASSWORD, plain, salt, mac));
    }

    @Test
    void largeDataRoundTrip() {
        byte[] plain = new byte[2 * 1024 * 1024 + 123];
        new Random(42).nextBytes(plain);
        byte[] original = copy(plain);

        byte[] salt = bytes(32);
        byte[] mac = bytes(32);
        Crypter crypter = crypter();

        crypter.encryption(PASSWORD, plain, salt, mac);
        assertTrue(!Arrays.equals(original, plain));

        crypter.decryption(PASSWORD, plain, salt, mac);
        assertArrayEquals(original, plain);
    }

    @Test
    void emptyDataRoundTrip() {
        byte[] plain = bytes(0);
        byte[] salt = bytes(32);
        byte[] mac = bytes(32);

        crypter().encryption(PASSWORD, plain, salt, mac);
        crypter().decryption(PASSWORD, plain, salt, mac);

        assertArrayEquals(bytes(0), plain);
    }

    @Test
    void randomSaltEachCall() {
        byte[] plain = "same plaintext".getBytes(StandardCharsets.UTF_8);
        byte[] mac = bytes(32);

        byte[] salt1 = bytes(32);
        byte[] salt2 = bytes(32);
        byte[] cipher1 = copy(plain);
        byte[] cipher2 = copy(plain);

        Crypter c1 = crypter();
        Crypter c2 = crypter();
        c1.encryption(PASSWORD, cipher1, salt1, mac);
        c2.encryption(PASSWORD, cipher2, salt2, mac);

        assertTrue(!Arrays.equals(salt1, salt2));
        assertTrue(!Arrays.equals(cipher1, cipher2));
    }

    @Test
    void shortSaltRoundTripWorks() {
        byte[] plain = "short salt ok".getBytes(StandardCharsets.UTF_8);
        byte[] salt = bytes(8);
        byte[] mac = bytes(32);

        Crypter crypter = crypter();
        crypter.encryption(PASSWORD, plain, salt, mac);
        crypter.decryption(PASSWORD, plain, salt, mac);

        assertArrayEquals("short salt ok".getBytes(StandardCharsets.UTF_8), plain);
    }

    @Test
    void invalidChunkSizeRejected() {
        assertThrows(IllegalArgumentException.class, () -> new Crypter(0));
        assertThrows(IllegalArgumentException.class, () -> new Crypter(-1));
    }

    @Test
    void mismatchedChunkSizeFails() {
        byte[] plain = "chunk size binding".getBytes(StandardCharsets.UTF_8);
        byte[] salt = bytes(32);
        byte[] mac = bytes(32);

        Crypter enc = new Crypter(1 << 20);
        enc.encryption(PASSWORD, plain, salt, mac);

        Crypter dec = new Crypter(1 << 18);
        assertThrows(Error.class, () -> dec.decryption(PASSWORD, plain, salt, mac));
    }
}