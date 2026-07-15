package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;

public class AriaECB implements ECB {
    private final Aria engine;

    public AriaECB(byte[] key) throws XACryptoException {
        this.engine = new Aria(true,key);
    }

    public byte[] encrypt(byte[] pln) throws XACryptoException {
        int pLen = 16 - (pln.length % 16);
        byte[] pData = new byte[pln.length + pLen];

        System.arraycopy(pln, 0, pData,0, pln.length);
        for (int i = pln.length ; i < pData.length ; i++) pData[i] = (byte) pLen;

        byte[] cip = new byte[pData.length];
        byte[] in = new byte[16];

        for (int i = 0 ; i < pData.length ; i += 16) {
            System.arraycopy(pData, i, in, 0, 16);
            byte[] out = engine.encryptBlock(in);
            System.arraycopy(out, 0, cip, i, 16);
        }

        return cip;
    }

    public byte[] decrypt(byte[] cip) throws XACryptoException {
        if (cip.length % 16 != 0) throw new XACryptoException("length of ciphertext must be a multiple of 16 (16-byte size) :-{");

        byte[] decomp = new byte[cip.length];
        byte[] in = new byte[16];

        for (int i = 0 ; i < cip.length ; i += 16) {
            System.arraycopy(cip, i, in, 0, 16);
            byte[] out = engine.decryptBlock(in);
            System.arraycopy(out, 0, decomp, i, 16);
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
