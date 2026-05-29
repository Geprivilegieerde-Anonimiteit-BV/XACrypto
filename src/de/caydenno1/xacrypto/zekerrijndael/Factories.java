package de.caydenno1.xacrypto.zekerrijndael;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES128;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.SM4GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.Camellia;
public class Factories {
    public static GCM AES128(byte[] key) {
        return new GCM(new AES128(key));
    }
    public static GCM SM4GCM(byte[] key) throws XACryptoException { return new GCM(new SM4GCM(key));}
    public static GCM Camellia(byte[] key) throws XACryptoException { return new GCM(new Camellia(key));}
}
