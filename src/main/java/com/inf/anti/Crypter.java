package com.inf.anti;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.util.Arrays;

public final class Crypter {

    private final int chunkSize;

    public Crypter(int chunkSize) {
        if (chunkSize <= 0) {
            throw new IllegalArgumentException("chunkSize must be positive");
        }
        this.chunkSize = chunkSize;
    }

    private void cryption(
            byte[] pswdBuffer,
            byte[] dataBuffer,
            byte[] saltBuffer) {
        Shake256 base = new Shake256();
        base.update(pswdBuffer);
        base.update(saltBuffer);

        for (int index = 0; index < dataBuffer.length; index += chunkSize) {
            int end = Math.min(index, dataBuffer.length - chunkSize) + chunkSize;
            Shake256 chunk = base.copy();
            byte[] indexData = ByteBuffer
                    .allocate(4).putInt(index).array();
            chunk.update(indexData);
            byte[] value = chunk.getFinal(end - index);
            for (int i = index; i < end; i++) {
                dataBuffer[i] ^= value[i - index];
            }
        }
    }

    public void encryption(
            byte[] pswdBuffer,
            byte[] dataBuffer,
            byte[] saltBuffer,
            byte[] macBuffer) {
        byte[] salt = RandomSource.withBytes(saltBuffer.length);
        System.arraycopy(
                salt, 0,
                saltBuffer, 0,
                salt.length);

        cryption(pswdBuffer, dataBuffer, saltBuffer);

        Shake256 mac = new Shake256();
        mac.update(pswdBuffer);
        mac.update(dataBuffer);
        mac.update(saltBuffer);
        System.arraycopy(
                mac.getFinal(macBuffer.length), 0, macBuffer, 0, macBuffer.length);
    }

    public void decryption(
            byte[] pswdBuffer,
            byte[] dataBuffer,
            byte[] saltBuffer,
            byte[] macBuffer) {
        Shake256 mac = new Shake256();
        mac.update(pswdBuffer);
        mac.update(dataBuffer);
        mac.update(saltBuffer);
        byte[] macValue = mac.getFinal(macBuffer.length);

        if (!MessageDigest.isEqual(macValue, macBuffer)) {
            Arrays.fill(pswdBuffer, (byte) 0);
            Arrays.fill(saltBuffer, (byte) 0);
            Arrays.fill(macBuffer, (byte) 0);
            throw new CatastrophicError("Data has been tampered with");
        }
        cryption(pswdBuffer, dataBuffer, saltBuffer);
    }

    private static final class CatastrophicError extends Error {

        public CatastrophicError(String message) {
            super(message);
        }
    }
}
