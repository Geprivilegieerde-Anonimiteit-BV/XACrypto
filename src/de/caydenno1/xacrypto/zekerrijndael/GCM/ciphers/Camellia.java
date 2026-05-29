package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;

public class Camellia implements BlockCipher {
    private final long[] subkeys = new long[26];

    public Camellia(byte[] key) throws XACryptoException {
      if (key.length != 16) throw new XACryptoException("16 byte key is required");
      genKeySch(key);
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

    private void genKeySch(byte[] key) {
        long KL1 = bytes2Long(key, 0);
        long KL2 = bytes2Long(key, 8);
        long KR1,KR2 = 0;

        long d1 = KL1 ^ KR2;
        long d2 = KL2 ^ KR2;
    }

    private long F(long F_IN, long KE) {return 0L;}
    private long FL(long F_IN, long KE) {return 0L;}
    private long FLINV(long FLINV_IN, long KE) {return 0L;}
    private long ROTL32(long v, int shift) {return 0L;}
    private long[] ROTL64(long l, long r, int shift) {return new long[10];}
    private long bytes2Long(byte[] b, int off) {return 0L;}
    private void long2Bytes(long v, byte[] b, int off) {};
}
