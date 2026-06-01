package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.misc.XACryptoException;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.TWOFISH_Q0;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.TWOFISH_Q1;

public class Twofish {
    private final int[] K = new int[40];
    private final int[] S;
    private final int kW;

    public Twofish(byte[] key) throws XACryptoException {
        if (key.length != 16 && key.length != 24 && key.length != 32)
            throw new XACryptoException("16,24,32 bit key is required :-(");

        kW = key.length / 8;
        S = new int[kW];

        int[] M = new int[2 * kW];
        for (int i = 0; i < 2 * kW; i++) M[i] = read32LE(key, i * 4);

        int[] Me = new int[kW];
        int[] Mo = new int[kW];
        for (int i = 0; i < kW; i++) {
            Me[i] = M[2 * i];
            Mo[i] = M[2 * i + 1];

            byte[] m = new byte[8];
            for (int j = 0; j < 8; j++) m[j] = key[8 * i + j];
            int s0 = gfMultRS(0x01, m[0] & 0xFF) ^ gfMultRS(0xA4, m[1] & 0xFF) ^ gfMultRS(0x55, m[2] & 0xFF) ^ gfMultRS(0x87, m[3] & 0xFF) ^
                    gfMultRS(0x5A, m[4] & 0xFF) ^ gfMultRS(0x58, m[5] & 0xFF) ^ gfMultRS(0xDB, m[6] & 0xFF) ^ gfMultRS(0x9E, m[7] & 0xFF);
            int s1 = gfMultRS(0xA4, m[0] & 0xFF) ^ gfMultRS(0x56, m[1] & 0xFF) ^ gfMultRS(0x82, m[2] & 0xFF) ^ gfMultRS(0xF3, m[3] & 0xFF) ^
                    gfMultRS(0x1E, m[4] & 0xFF) ^ gfMultRS(0xC6, m[5] & 0xFF) ^ gfMultRS(0x68, m[6] & 0xFF) ^ gfMultRS(0xE5, m[7] & 0xFF);
            int s2 = gfMultRS(0x02, m[0] & 0xFF) ^ gfMultRS(0xA1, m[1] & 0xFF) ^ gfMultRS(0xFC, m[2] & 0xFF) ^ gfMultRS(0xC1, m[3] & 0xFF) ^
                    gfMultRS(0x47, m[4] & 0xFF) ^ gfMultRS(0xAE, m[5] & 0xFF) ^ gfMultRS(0x3D, m[6] & 0xFF) ^ gfMultRS(0x19, m[7] & 0xFF);
            int s3 = gfMultRS(0xA4, m[0] & 0xFF) ^ gfMultRS(0x55, m[1] & 0xFF) ^ gfMultRS(0x87, m[2] & 0xFF) ^ gfMultRS(0x5A, m[3] & 0xFF) ^
                    gfMultRS(0x58, m[4] & 0xFF) ^ gfMultRS(0xDB, m[5] & 0xFF) ^ gfMultRS(0x9E, m[6] & 0xFF) ^ gfMultRS(0x03, m[7] & 0xFF);
            S[i] = (s0 & 0xFF) | ((s1 & 0xFF) << 8) | ((s2 & 0xFF) << 16) | ((s3 & 0xFF) << 24);
        }
        for (int i = 0; i < 20; i++) {
            int A = h(2 * i * 0x01010101, Me, kW);
            int B = Integer.rotateLeft(h((2 * i + 1) * 0x01010101, Mo, kW), 8);
            K[2 * i] = A * B;
            K[2 * i + 1] = Integer.rotateLeft(A + 2 * B, 9);
        }
    }
    private int h(int x, int[] L, int k) { return -1; }
    public byte[] encryptBlock(byte[] in) throws XACryptoException { return new byte[1]; }
    private static int read32LE(byte[] b, int off) { return -1; }
    private static void write32LE(int v, byte[] b, int off) {};
    private static int gfMultMDS(int a, int b) { return -1; }
    private static int gfMultRS(int a, int b) { return -1; }
}
