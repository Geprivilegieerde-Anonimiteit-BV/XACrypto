package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.misc.XACryptoException;

import java.lang.reflect.InvocationTargetException;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_SBOX;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_IBOX;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.SERPENT_PHI;

interface SerpentCipher extends BlockCipher {
    byte[] encryptBlock(byte[] in) throws XACryptoException;
    byte[] decryptBlock(byte[] in) throws XACryptoException;
}

public class Serpent implements SerpentCipher {
    private final int[][] K;

    public Serpent(byte[] key) throws XACryptoException {
        if (key.length != 16 && key.length != 24 && key.length != 32) throw new XACryptoException("serpent key must be either 16,24 or 32 bytes in length", key.length);
        this.K = new int[33][4];
        keyExpansion(key);
    }

    @Override
    public byte[] encryptBlock(byte[] in) throws XACryptoException {
        int[] X = new int[4];
        pack(in, X);

        for (int r = 0 ; r < 32 ; r++) {
            illumFOR(X, r);
            SBOXify(r % 8, X, SERPENT_SBOX);
            if (r==31) illumFOR(X, 32);
            else LT(X);
        }

        byte[] o = new byte[16];
        unpack(X, o);
        return o;
    }

    public byte[] decryptBlock(byte[] in) {
        int[] X = new int[4];
        pack(in, X);

        illumFOR(X, 32);

        for (int r = 31 ; r >= 0; r--) {
            if (r != 31) invLT(X);
            SBOXify(r % 8, X, SERPENT_IBOX);
            illumFOR(X, r);
        }
        byte[] o = new byte[16];
        unpack(X, o);
        return o;
    }
    private void illumFOR(int[] X, int N) {
        for (int i = 0 ; i < 4 ; i++) X[i] ^= K[N][i];
    }
    private void keyExpansion(byte[] key){
        byte[] pk = new byte[32];
        System.arraycopy(key, 0, pk, 0, key.length);
        if (key.length < 32) pk[key.length] = (byte) 0x01;

        int[] w = new int[104];
        for (int i = 0 ; i < 8 ; i++) {
            w[i] = (pk[i * 4] & 0xFF) | ((pk[i * 4 + 1] & 0xFF) << 8) |
                   ((pk[i * 4 + 2] & 0xFF) << 16) | ((pk[i * 4 + 3] & 0xFF) << 24);
        }

        for (int i = 8 ; i < 140 ; i++) {
            int _0 = w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ SERPENT_PHI ^ (i - 8);
            w[i] = Integer.rotateLeft(_0, 11);
        }

        for (int i = 0 ; i < 33 ; i++) {
            int[] group = { w[8 + 4 * i], w[8 + 4 * i + 1], w[8 + 4 * i + 2], w[8 + 4 * i + 3] };
        }
        // more here
    }
    private void SBOXify(int box, int[] X, byte[][] table) {}
    private void LT(int[] X) {}
    private void invLT(int[] X) {}
    private void pack(byte[] src, int[] dest) {}
    private void unpack(int[] src, byte[] dest) {}
}
