package com.inf.anti.util;

import java.util.Objects;

/**
 * 增量式 SHAKE256（FIPS 202 XOF）纯 Java 实现。
 *
 * <p>
 * 与 Keccak CompactFIPS202 参考实现字节兼容：增量吸收等价于一次性吸收，
 * getFinal 采用流式语义，多次调用返回输出流中的后续字节。
 * </p>
 *
 * <p>
 * 优化要点：完整块按 64 位 lane 批量吸收/挤压，Keccak-f[1600] 置换零堆分配，
 * 旋转常量预计算查表。输出与朴素版本逐字节一致。
 * </p>
 */
public final class Shake256 {

    private static final int RATE_BYTES = 136;
    private static final int RATE_LANES = 17;
    private static final int LANE_COUNT = 25;
    private static final int ROUNDS = 24;
    private static final int[] ROTATIONS = {
            1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
            27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    };

    private final long[] state = new long[LANE_COUNT];
    private int bytesInBlock = 0;
    private boolean squeezing = false;
    private int squeezePos = 0;

    /** 构造一个空的 SHAKE256 实例。 */
    public Shake256() {
    }

    /**
     * 吸收一段输入数据。
     *
     * @param data 输入字节数组
     * @throws NullPointerException  data 为 null 时
     * @throws IllegalStateException 已调用过 getFinal 后再次吸收时
     */
    public void update(byte[] data) {
        Objects.requireNonNull(data, "data must not be null");
        if (squeezing) {
            throw new IllegalStateException("Cannot absorb after getFinal");
        }

        int pos = 0;
        int len = data.length;

        if (bytesInBlock != 0) {
            while (pos < len && bytesInBlock < RATE_BYTES) {
                state[bytesInBlock >> 3] ^= (long) (data[pos] & 0xFF) << ((bytesInBlock & 7) << 3);
                pos++;
                bytesInBlock++;
            }
            if (bytesInBlock == RATE_BYTES) {
                permute();
                bytesInBlock = 0;
            }
            if (pos == len) {
                return;
            }
        }

        while (len - pos >= RATE_BYTES) {
            absorbBlock(data, pos);
            pos += RATE_BYTES;
            permute();
        }

        while (pos < len) {
            state[bytesInBlock >> 3] ^= (long) (data[pos] & 0xFF) << ((bytesInBlock & 7) << 3);
            pos++;
            bytesInBlock++;
        }
    }

    /**
     * 返回当前状态的一个独立深拷贝。
     *
     * @return 状态副本
     */
    public Shake256 copy() {
        Shake256 clone = new Shake256();
        System.arraycopy(this.state, 0, clone.state, 0, LANE_COUNT);
        clone.bytesInBlock = this.bytesInBlock;
        clone.squeezing = this.squeezing;
        clone.squeezePos = this.squeezePos;
        return clone;
    }

    /**
     * 完成填充并输出指定长度的 SHAKE256 输出（流式，可多次调用）。
     *
     * @param length 期望输出字节数
     * @return 长度恰为 length 的输出
     * @throws IllegalArgumentException length 为负时
     */
    public byte[] getFinal(int length) {
        if (length < 0) {
            throw new IllegalArgumentException("length must be non-negative");
        }

        if (!squeezing) {
            xorByteAt(bytesInBlock, 0x1F);
            xorByteAt(RATE_BYTES - 1, 0x80);
            permute();
            squeezing = true;
            squeezePos = 0;
        }

        byte[] out = new byte[length];
        int outPos = 0;
        while (outPos < length) {
            if (squeezePos == RATE_BYTES) {
                permute();
                squeezePos = 0;
            }
            int count = Math.min(RATE_BYTES - squeezePos, length - outPos);
            squeezeInto(out, outPos, count);
            outPos += count;
            squeezePos += count;
        }
        return out;
    }

    /** 把 data[off..off+135] 的 17 个 lane 小端异或进速率区。 */
    private void absorbBlock(byte[] data, int off) {
        for (int lane = 0; lane < RATE_LANES; lane++) {
            int i = off + (lane << 3);
            long v = (long) (data[i] & 0xFF)
                    | ((long) (data[i + 1] & 0xFF) << 8)
                    | ((long) (data[i + 2] & 0xFF) << 16)
                    | ((long) (data[i + 3] & 0xFF) << 24)
                    | ((long) (data[i + 4] & 0xFF) << 32)
                    | ((long) (data[i + 5] & 0xFF) << 40)
                    | ((long) (data[i + 6] & 0xFF) << 48)
                    | ((long) (data[i + 7] & 0xFF) << 56);
            state[lane] ^= v;
        }
    }

    /** 把当前块从 squeezePos 起的 count 个字节写入 out[outPos..]。 */
    private void squeezeInto(byte[] out, int outPos, int count) {
        int blockPos = squeezePos;
        while (count >= 8 && (blockPos & 7) == 0) {
            long v = state[blockPos >>> 3];
            int o = outPos;
            out[o] = (byte) v;
            out[o + 1] = (byte) (v >>> 8);
            out[o + 2] = (byte) (v >>> 16);
            out[o + 3] = (byte) (v >>> 24);
            out[o + 4] = (byte) (v >>> 32);
            out[o + 5] = (byte) (v >>> 40);
            out[o + 6] = (byte) (v >>> 48);
            out[o + 7] = (byte) (v >>> 56);
            count -= 8;
            blockPos += 8;
            outPos += 8;
        }
        while (count > 0) {
            out[outPos++] = (byte) ((state[blockPos >>> 3] >>> ((blockPos & 7) << 3)) & 0xFF);
            blockPos++;
            count--;
        }
    }

    /** 把字节 b 异或进状态中固定字节位置 p（小端语义，不改变 bytesInBlock）。 */
    private void xorByteAt(int p, int b) {
        state[p >>> 3] ^= (long) (b & 0xFF) << ((p & 7) << 3);
    }

    /** 一次 Keccak-f[1600] 置换（24 轮，零堆分配）。 */
    private void permute() {
        long[] a = state;
        int lfsr = 0x01;

        for (int round = 0; round < ROUNDS; round++) {
            /* θ */
            long c0 = a[0] ^ a[5] ^ a[10] ^ a[15] ^ a[20];
            long c1 = a[1] ^ a[6] ^ a[11] ^ a[16] ^ a[21];
            long c2 = a[2] ^ a[7] ^ a[12] ^ a[17] ^ a[22];
            long c3 = a[3] ^ a[8] ^ a[13] ^ a[18] ^ a[23];
            long c4 = a[4] ^ a[9] ^ a[14] ^ a[19] ^ a[24];
            long d0 = c4 ^ Long.rotateLeft(c1, 1);
            long d1 = c0 ^ Long.rotateLeft(c2, 1);
            long d2 = c1 ^ Long.rotateLeft(c3, 1);
            long d3 = c2 ^ Long.rotateLeft(c4, 1);
            long d4 = c3 ^ Long.rotateLeft(c0, 1);
            for (int y = 0; y < 5; y++) {
                int i = y * 5;
                a[i] ^= d0;
                a[i + 1] ^= d1;
                a[i + 2] ^= d2;
                a[i + 3] ^= d3;
                a[i + 4] ^= d4;
            }

            /* ρ + π */
            int x = 1;
            int y = 0;
            long current = a[1];
            for (int t = 0; t < 24; t++) {
                int Y = (2 * x + 3 * y) % 5;
                x = y;
                y = Y;
                long temp = a[x + 5 * y];
                a[x + 5 * y] = Long.rotateLeft(current, ROTATIONS[t]);
                current = temp;
            }

            /* χ */
            for (int yy = 0; yy < 5; yy++) {
                int i = yy * 5;
                long t0 = a[i];
                long t1 = a[i + 1];
                long t2 = a[i + 2];
                long t3 = a[i + 3];
                long t4 = a[i + 4];
                a[i] = t0 ^ ((~t1) & t2);
                a[i + 1] = t1 ^ ((~t2) & t3);
                a[i + 2] = t2 ^ ((~t3) & t4);
                a[i + 3] = t3 ^ ((~t4) & t0);
                a[i + 4] = t4 ^ ((~t0) & t1);
            }

            /* ι */
            for (int j = 0; j < 7; j++) {
                int bitPosition = (1 << j) - 1;
                if ((lfsr & 0x01) != 0) {
                    a[0] ^= 1L << bitPosition;
                }
                if ((lfsr & 0x80) != 0) {
                    lfsr = ((lfsr << 1) ^ 0x71) & 0xFF;
                } else {
                    lfsr = (lfsr << 1) & 0xFF;
                }
            }
        }
    }
}