package com.inf.anti;

import java.nio.charset.StandardCharsets;

import org.junit.jupiter.api.Test;

import com.inf.anti.util.Shake256;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Shake256Test {

    private static final String PATTERN = "Keccak test data.";

    private static byte[] patternInput(int length) {
        byte[] pattern = PATTERN.getBytes(StandardCharsets.US_ASCII);
        byte[] input = new byte[length];
        for (int i = 0; i < length; i++) {
            input[i] = pattern[i % pattern.length];
        }
        return input;
    }

    private static String reference(int length) {
        return switch (length) {
            case 0 -> "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f"
                    + "d75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be";
            case 135 -> "05ae1619ffc1db823bbdbb2f440b74c5a2fa6bda6c3d1455ba923a36ba688849"
                    + "40c27e67bf7e2e1d71b7d2cd6d6a18b922fc165d94fe24a0faf4a649d190fed9";
            case 136 -> "9122e51fe4a674528b76bc3893b21616e0ee154b1e2ecb12261dea833a9c47e3"
                    + "2b1da10896b3ca0d9a50c9210cddbf857db71d630b3de8c67e51e3d37499d1bb";
            case 137 -> "10131d013f3fb37bc1a46534cecea8e98d86f4e5c131ade4a4a465d1721628ca"
                    + "298927ff61af4f55ca1e06db5f3b1dda46e71ff64d5438bf3fa83735520c0ad5";
            default -> throw new IllegalArgumentException("unexpected length: " + length);
        };
    }

    @Test
    void emptyInputMatchesPython() {
        assertArrayEquals(hex(reference(0)), oneShot(0));
    }

    @Test
    void emptyUpdateIsNoOp() {
        Shake256 shake = new Shake256();
        shake.update(new byte[0]);
        assertArrayEquals(hex(reference(0)), shake.getFinal(64));
    }

    @Test
    void boundary135MatchesPython() {
        assertArrayEquals(hex(reference(135)), oneShot(135));
    }

    @Test
    void boundary136MatchesPython() {
        assertArrayEquals(hex(reference(136)), oneShot(136));
    }

    @Test
    void boundary137MatchesPython() {
        assertArrayEquals(hex(reference(137)), oneShot(137));
    }

    @Test
    void incrementalAbsorbEqualsOneShot() {
        for (int n : new int[] { 135, 136, 137, 300, 1000 }) {
            byte[] input = patternInput(n);

            byte[] whole = oneShot(n);

            Shake256 shake = new Shake256();
            for (int i = 0; i < input.length; i++) {
                shake.update(new byte[] { input[i] });
            }
            assertArrayEquals(whole, shake.getFinal(64), "incremental mismatch at n=" + n);
        }
    }

    @Test
    void copyIsIndependent() {
        Shake256 shake = new Shake256();
        shake.update(patternInput(10));

        Shake256 a = shake.copy();
        Shake256 b = shake.copy();

        a.update(patternInput(50));
        b.update(patternInput(200));

        byte[] outA = a.getFinal(64);
        byte[] outB = b.getFinal(64);

        Shake256 wholeA = new Shake256();
        wholeA.update(patternInput(10));
        wholeA.update(patternInput(50));
        Shake256 wholeB = new Shake256();
        wholeB.update(patternInput(10));
        wholeB.update(patternInput(200));

        assertArrayEquals(wholeA.getFinal(64), outA);
        assertArrayEquals(wholeB.getFinal(64), outB);
    }

    @Test
    void getFinalIsStreaming() {
        Shake256 shake = new Shake256();
        shake.update(patternInput(100));

        byte[] first = shake.getFinal(20);
        byte[] second = shake.getFinal(44);

        Shake256 whole = new Shake256();
        whole.update(patternInput(100));
        byte[] combined = new byte[64];
        System.arraycopy(first, 0, combined, 0, 20);
        System.arraycopy(second, 0, combined, 20, 44);

        assertArrayEquals(whole.getFinal(64), combined);
    }

    @Test
    void zeroLengthOutputIsEmpty() {
        assertArrayEquals(new byte[0], new Shake256().getFinal(0));
    }

    @Test
    void negativeLengthRejected() {
        assertThrows(IllegalArgumentException.class, () -> new Shake256().getFinal(-1));
    }

    @Test
    void updateAfterGetFinalRejected() {
        Shake256 shake = new Shake256();
        shake.update(patternInput(10));
        shake.getFinal(32);
        assertThrows(IllegalStateException.class, () -> shake.update(patternInput(10)));
    }

    @Test
    void nullUpdateRejected() {
        assertThrows(NullPointerException.class, () -> new Shake256().update(null));
    }

    private static byte[] hex(String hex) {
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("odd hex length");
        }
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < out.length; i++) {
            out[i] = (byte) Integer.parseInt(hex.substring(2 * i, 2 * i + 2), 16);
        }
        return out;
    }

    private static byte[] oneShot(int length) {
        Shake256 shake = new Shake256();
        shake.update(patternInput(length));
        return shake.getFinal(64);
    }
}