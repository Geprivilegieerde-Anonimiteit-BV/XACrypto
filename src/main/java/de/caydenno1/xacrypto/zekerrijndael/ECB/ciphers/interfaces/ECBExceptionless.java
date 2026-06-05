package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces;

import de.caydenno1.xacrypto.misc.XACryptoException;

public interface ECBExceptionless {
    public byte[] encrypt(byte[] pln);
    public byte[] decrypt(byte[] cip) throws XACryptoException;
}
