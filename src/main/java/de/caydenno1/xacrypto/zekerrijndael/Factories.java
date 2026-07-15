package de.caydenno1.xacrypto.zekerrijndael;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.SM4GCM;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;
import de.caydenno1.xacrypto.zekerrijndael.Global.Camellia;
import de.caydenno1.xacrypto.zekerrijndael.Global.Twofish;

public class Factories {

    public static class GCMFactory {

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM AES128(byte[] key) throws XACryptoException, NoSuchMethodException {
            return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new AES(key, 128));
        }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM SM4GCM(byte[] key) throws XACryptoException, NoSuchMethodException {
            return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new SM4GCM(key));
        }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM Camellia(byte[] key) throws XACryptoException, NoSuchMethodException {
            return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new Camellia(key));
        }

        public static de.caydenno1.xacrypto.zekerrijndael.GCM.GCM Aria(byte[] key) throws XACryptoException, NoSuchMethodException {
            return new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(new Aria(true, key));
        }
    }

    public static class ECBFactory {

        public static ECBExceptionless Blowfish(byte[] key) throws XACryptoException {
            return new BlowfishECB(key);
        }

        public static AriaECB Aria(byte[] key) throws XACryptoException {
            return new AriaECB(key);
        }

        public static ECBExceptionless SM4(byte[] key) throws XACryptoException {
            return new SM4ECB(key);
        }

        public static AESECB AES(byte[] key) throws XACryptoException {
            return new AESECB(key);
        }

        public static TwofishECB Twofish(byte[] key) throws XACryptoException {
            return new TwofishECB(key);
        }

        public static RC6ECB RC6(byte[] key) throws XACryptoException {
            return new RC6ECB(key);
        }
    }
}
