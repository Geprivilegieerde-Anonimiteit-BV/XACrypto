package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;

public class SerpentGCM implements BlockCipher {
    private int[] subkeys;

    public SerpentGCM(byte[] key) {}

    @Override
    public byte[] encryptBlock(byte[] pln) throws XACryptoException {
        return new byte[0];//placeholder :)
    }
}
