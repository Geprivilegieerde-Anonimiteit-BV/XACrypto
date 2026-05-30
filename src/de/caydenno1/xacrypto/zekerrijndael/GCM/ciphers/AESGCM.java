package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GHASH;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

import java.util.Arrays;

interface AESCipher {
    Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException;
}

public class AESGCM implements AESCipher {
    public Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException {
        System.out.println("WARNING! AESGCM may not be fully functional and partially broken. I am unsure if it fully works or not.");
        byte[] zbyte = new byte[16];
        byte[] J0 = new byte[16];

        AES aes = new AES(key, 128);
        byte[] H = aes.encryptBlock(zbyte);
        GHASH gh = new GHASH(H);

        if (nonce.length == 12) {
            System.arraycopy(nonce, 0, J0, 0, 12);
            J0[15] = 1;
        } else {
           J0 = gh.compNonce(H, nonce);
        }

        byte[] cip = aes.encryptCTR(pln, J0);

        byte[] S = gh.compute(aad, cip);

        byte[] TB = aes.encryptBlock(J0);

        byte[] Tag = gh.xor(TB, S);

        return new Result(cip, Tag);
    }
}