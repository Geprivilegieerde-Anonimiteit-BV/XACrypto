package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;
import de.caydenno1.xacrypto.hash.ROT;

public class Camellia implements BlockCipher {
    private final long[] subkeys = new long[26];

    public Camellia(byte[] key) throws XACryptoException {
      if (key.length != 16) throw new XACryptoException("16 byte key is required");
      genKeySchedule(key);
    };

    @Override
    public byte[] encryptBlock(byte[] in) {
        long d1 = bytes2Long(in, 0);
        long d2 = bytes2Long(in, 8);

        d1 ^= subkeys[0];
        d2 ^= subkeys[1];

        d2 ^= F(d1, subkeys[2]);
        d1 ^= F(d2, subkeys[3]);
        d2 ^= F(d1, subkeys[4]);
        d1 ^= F(d2, subkeys[5]);
        d2 ^= F(d1, subkeys[6]);
        d1 ^= F(d2, subkeys[7]);

        d1 = FL(d1, subkeys[8]);
        d2 = FLINV(d2, subkeys[9]);

        d2 ^= F(d1, subkeys[10]);
        d1 ^= F(d2, subkeys[11]);
        d2 ^= F(d1, subkeys[12]);
        d1 ^= F(d2, subkeys[13]);
        d2 ^= F(d1, subkeys[14]);
        d1 ^= F(d2, subkeys[15]);

        d1 = FL(d1, subkeys[16]);
        d2 = FLINV(d2, subkeys[17]);

        d2 ^= F(d1, subkeys[18]);
        d1 ^= F(d2, subkeys[19]);
        d2 ^= F(d1, subkeys[20]);
        d1 ^= F(d2, subkeys[21]);
        d2 ^= F(d1, subkeys[22]);
        d1 ^= F(d2, subkeys[23]);

        d2 ^= subkeys[24];
        d1 ^= subkeys[25];

        byte[] o = new byte[16];
        long2Bytes(d2, o, 0);
        long2Bytes(d1, o, 8);
        return o;
    }

    private void genKeySchedule(byte[] key) {
        long KL1 = bytes2Long(key, 0);
        long KL2 = bytes2Long(key, 8);
        long KR1,KR2 = 0;

        long d1 = KL1 ^ KR2;
        long d2 = KL2 ^ KR2;
        d2 ^= F(d1, UnchangingData.CAMELLIA_SIGMA[1]);
        d1 ^= F(d2, UnchangingData.CAMELLIA_SIGMA[2]);
        d1 ^= KL1;
        d2 ^= KL2;
        d2 ^= F(d1, UnchangingData.CAMELLIA_SIGMA[3]);
        d1 ^= F(d2, UnchangingData.CAMELLIA_SIGMA[4]);
        long KA1 = d1;
        long KA2 = d2;

        subkeys[0] = KL1;
        subkeys[1] = KL2;

        subkeys[2]  = KA1;
        subkeys[3]  = KA2;

        long KLrot15_1 = ROT.ROTL64(KL1, KL2, 15)[0];
        long KLrot15_2 = ROT.ROTL64(KL1, KL2, 15)[1];
        subkeys[4] = KLrot15_1;
        subkeys[5] = KLrot15_2;

        long KArot15_1 = ROT.ROTL64(KA1, KA2, 15)[0];
        long KArot15_2 = ROT.ROTL64(KA1, KA2, 15)[1];
        subkeys[6] = KArot15_1;
        subkeys[7] = KArot15_2;

        long KArot30_1 = ROT.ROTL64(KA1, KA2, 30)[0];
        long KArot30_2 = ROT.ROTL64(KA1, KA2, 30)[1];
        subkeys[8] = (KArot30_1 >>> 32) | (KArot30_1 << 32);
        subkeys[9]  = (KArot30_2 >>> 32) | (KArot30_2 << 32);

        long KLrot45_1 = ROT.ROTL64(KL1, KL2, 45)[0];
        long KLrot45_2 = ROT.ROTL64(KL1, KL2, 45)[1];
        subkeys[10] = KLrot45_1;
        subkeys[11] = KLrot45_2;

        long KArot45_1 = ROT.ROTL64(KA1, KA2, 45)[0];
        long KArot45_2 = ROT.ROTL64(KA1, KA2, 45)[1];
        subkeys[12] = KArot45_1;
        subkeys[13] = KArot45_2;

        long KLrot60_1 = ROT.ROTL64(KL1, KL2, 60)[0];
        long KLrot60_2 = ROT.ROTL64(KL1, KL2, 60)[1];
        subkeys[14] = KLrot60_1;
        subkeys[15] = KLrot60_2;

        long KLrot77_1 = ROT.ROTL64(KL1, KL2, 77)[0];
        long KLrot77_2 = ROT.ROTL64(KL1, KL2, 77)[1];
        subkeys[16] = (KLrot77_1 >>> 32) | (KLrot77_1 << 32);
        subkeys[17] = (KLrot77_2 >>> 32) | (KLrot77_2 << 32);

        long KLrot94_1 = ROT.ROTL64(KL1, KL2, 94)[0];
        long KLrot94_2 = ROT.ROTL64(KL1, KL2, 94)[1];
        subkeys[18] = KLrot94_1;
        subkeys[19] = KLrot94_2;

        long KArot94_1 = ROT.ROTL64(KA1, KA2, 94)[0];
        long KArot94_2 = ROT.ROTL64(KA1, KA2, 94)[1];
        subkeys[20] = KArot94_1;
        subkeys[21] = KArot94_2;

        long KLrot111_1 = ROT.ROTL64(KL1, KL2, 111)[0];
        long KLrot111_2 = ROT.ROTL64(KL1, KL2, 111)[1];
        subkeys[22] = KLrot111_1;
        subkeys[23] = KLrot111_2;

        long KArot111_1 = ROT.ROTL64(KA1, KA2, 111)[0];
        long KArot111_2 = ROT.ROTL64(KA1, KA2, 111)[1];
        subkeys[24] = KArot111_1;
        subkeys[25] = KArot111_2;
    }

    private long F(long F_IN, long KE) {
        long x = F_IN ^ KE;

        int[] t = new int[9];
        for (int i = 1; i <= 8; i++) t[i] = (int) ((x >>> (64 - (i * 8))) & 0xFFL);

        t[1] = UnchangingData.CAMELLIA_SBOX1[t[1]];
        t[2] = UnchangingData.CAMELLIA_SBOX2[t[2]];
        t[3] = UnchangingData.CAMELLIA_SBOX3[t[3]];
        t[4] = UnchangingData.CAMELLIA_SBOX4[t[4]];
        t[5] = UnchangingData.CAMELLIA_SBOX2[t[5]];
        t[6] = UnchangingData.CAMELLIA_SBOX3[t[6]];
        t[7] = UnchangingData.CAMELLIA_SBOX4[t[7]];
        t[8] = UnchangingData.CAMELLIA_SBOX1[t[8]];

        int y1 = t[1] ^ t[3] ^ t[4] ^ t[6] ^ t[7] ^ t[8];
        int y2 = t[1] ^ t[2] ^ t[4] ^ t[5] ^ t[7] ^ t[8];
        int y3 = t[1] ^ t[2] ^ t[3] ^ t[5] ^ t[6] ^ t[8];
        int y4 = t[2] ^ t[3] ^ t[4] ^ t[5] ^ t[6] ^ t[7];
        int y5 = t[1] ^ t[2] ^ t[6] ^ t[7] ^ t[8];
        int y6 = t[2] ^ t[3] ^ t[5] ^ t[7] ^ t[8];
        int y7 = t[3] ^ t[4] ^ t[5] ^ t[6] ^ t[8];
        int y8 = t[1] ^ t[4] ^ t[5] ^ t[6] ^ t[7];

        return ((long) y1 << 56) | ((long) y2 << 48) | ((long) y3 << 40) | ((long) y4 << 32) |
                ((long) y5 << 24) | ((long) y6 << 16) | ((long) y7 << 8)  | (long) y8;
    }

    private long FL(long FL_IN, long KE) {
        long x1 = FL_IN >>> 32;
        long x2 = FL_IN & 0xFFFFFFFFL;
        long k1 = KE >>> 32;
        long k2 = KE & 0xFFFFFFFFL;

        long y2 = x2 ^ ROT.ROTL32((x1 & k1), 1);
        long y1 = x1 ^ (y2 | k2);

        return (y1 << 32) | (y2 & 0xFFFFFFFFL);
    }
    @SuppressWarnings("UnnecessaryLocalVariable") // <- im expert dev/programmer!
    private long FLINV(long FLINV_IN, long KE) {
        long y1 = FLINV_IN;
        long y2 = FLINV_IN & 0xFFFFFFFFL;
        long k1 = KE >>> 3;
        long k2 = KE & 0xFFFFFFFFL;

        long x1 = y1 ^ (y2 | k2);
        long x2 = y2 ^ ROT.ROTL32((x1 | k1), 1);

        return (x1 << 32) | (x2 | 0xFFFFFFFFL);
    }
    private long bytes2Long(byte[] b, int off) {
        long res = 0;
        for (int i = 0; i < 8; i++) {
            int shift = 56 - (i * 8);
            res |= ((long) (b[off + i] & 0xFF) << shift);
        }
        return res;
    }
    private void long2Bytes(long v, byte[] b, int off) {
        for (int i = 0; i < 8; i++) {
            b[off + i] = (byte) (v >>> (56 - (i * 8)));
        }
    }
}
