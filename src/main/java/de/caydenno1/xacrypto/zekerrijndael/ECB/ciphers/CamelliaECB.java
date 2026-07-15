package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.Global.Camellia;

public class CamelliaECB implements ECBExceptionless {
    private final Camellia engine;

    public CamelliaECB(byte[] key) throws XACryptoException {
        this.engine = new Camellia(key);
    }

    public byte[] encrypt(byte[] pln) {
        int pLen = 16 - (pln.length % 16);
        byte[] pData = new byte[pln.length + pLen];

        System.arraycopy(pln, 0, pData, 0, pln.length);
        for (int i = pln.length; i < pData.length; i++) {
            pData[i] = (byte) pLen;
        }

        byte[] cip = new byte[pData.length];

        for (int i = 0 ; i < pData.length ; i += 16) {
            engine.encryptBlock(pData, i, cip, i);
        }

        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length % 16 != 0) throw new XACryptoException("ciphertext length is not a multiple of 16",(int)cip.length);

        byte[] decomp = new byte[cip.length];

        for (int i = 0 ; i < cip.length ; i += 16) {
            engine.decryptBlock(cip, i, decomp, i);
        }

        int pLen = decomp[decomp.length - 1] & 0xFF;

        if (pLen < 1 || pLen > 16) throw new XACryptoException("padding must be 1-16 exclusive in length", (int)pLen);

        for (int i = decomp.length - pLen; i < decomp.length; i++) {
            if ((decomp[i] & 0xFF) != pLen) throw new XACryptoException("something up with yo padding.. :(");
        }

        byte[] pln = new byte[decomp.length - pLen];
        System.arraycopy(decomp, 0, pln, 0, pln.length);

        return pln;
    }
}
