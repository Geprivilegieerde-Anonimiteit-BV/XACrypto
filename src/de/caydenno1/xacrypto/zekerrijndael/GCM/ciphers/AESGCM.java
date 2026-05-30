package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;
import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GHASH;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

import java.util.Arrays;

interface AESCipher {
    Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException;
}

public class AESGCM implements AESCipher {
    public Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException {
        byte[] zbyte = new byte[16];
        byte[] H = new AES(key, 128).encryptBlock(zbyte);

        AES aes = new AES(key, 128);
        byte[] cip = aes.encryptCTR(pln, nonce);

        GHASH gh = new GHASH(H);
        byte[] S = gh.compute(aad, cip);

        byte[] J0 = Arrays.copyOf(nonce, 16);
        byte[] TB = new AES(key, 128).encryptBlock(J0);

        byte[] Tag = xor(TB, S);

        return new Result(cip, Tag);
    }

    private byte[] xor(byte[] a, byte[] b) {
        byte[] r = new byte[16];
        for (int i = 0; i < 16; i++) r[i] = (byte)(a[i] ^ b[i]);
        return r;
    } // wanted to use GHASH's xor but it wont work for some reason. i might fix it eventually, who knows.
}
