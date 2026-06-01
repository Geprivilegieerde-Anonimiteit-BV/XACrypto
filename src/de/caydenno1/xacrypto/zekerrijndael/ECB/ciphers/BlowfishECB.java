package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.Blowfish;

interface BlowfishCipher {
    public byte[] encrypt(byte[] plaintext);
    public byte[] decrypt(byte[] ciphertext);
}

public class BlowfishECB implements BlowfishCipher {
    private final Blowfish engine;

    public BlowfishECB(byte[] key) throws XACryptoException {
        this.engine = new Blowfish(key);
    }

    public byte[] encrypt(byte[] plaintext) { return new byte[1]; }

    public byte[] decrypt(byte[] ciphertext) { return new byte[1]; }
}
