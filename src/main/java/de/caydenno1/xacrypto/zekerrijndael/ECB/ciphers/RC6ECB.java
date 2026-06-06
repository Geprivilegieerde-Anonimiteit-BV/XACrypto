package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.*;
import static de.caydenno1.xacrypto.zekerrijndael.Global.LE32.*;

public class RC6ECB implements ECB {
    private final int[] S;
    // 20 rounds

    public RC6ECB(byte[] key) throws XACryptoException {
        if (key.length <= 0 || key.length > 255) throw new XACryptoException("keys must be 1-255 bytes inclusive :\\");

        int c = Math.max(1, (key.length + 3) / 4);
        int[] L = new int[c];
        for (int i = 0 ; i < key.length ; i++) L[i / 4] |= (key[i] & 0xFF) << (8 * (i % 4));

        S = new int[44 /* 2x 20 rounds = 40 rounds + 4 = 44. */];
        S[0] = RC6_P;
        for (int i = 1 ; i < S.length ; i++) S[i] = S[i - 1] + RC6_Q;

        int A = 0, B = 0, i = 0, j = 0;
        int v = 3 * Math.max(c, S.length);
        for (int s = 0 ; s < v ; s++) {
            A = S[i] = Integer.rotateLeft(S[i] + A + B, 3);
            B = L[j] = Integer.rotateLeft(L[j] + A + B, A + B);
            i = (i + 1)%S.length;
            j = (j + 1)%c;
        }
    }

    private void encryptBlock(byte[] in, int inOff, byte[] out, int outOff) {};

    private void decryptBlock(byte[] in, int inOff, byte[] out, int outOff) {};

    public byte[] encrypt(byte[] pln) throws XACryptoException { return new byte[16]; }

    public byte[] decrypt(byte[] cip) throws XACryptoException { return new byte[16]; }


}
