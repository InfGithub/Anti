package com.inf.anti.util;

import java.security.SecureRandom;

public final class RandomSource {
    private static final SecureRandom random = new SecureRandom();

    private RandomSource() {

    }

    public static byte[] withBytes(int length) {
        byte[] bytes = new byte[length];
        random.nextBytes(bytes);
        return bytes;
    }
}
