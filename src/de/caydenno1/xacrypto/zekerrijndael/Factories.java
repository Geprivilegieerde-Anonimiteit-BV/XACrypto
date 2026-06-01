package de.caydenno1.xacrypto.zekerrijndael;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.*;
import java.lang.reflect.InvocationTargetException;

public class Factories {
    public static GCM AES128(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new GCM(new AES(key, 128)); }
    public static GCM SM4GCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new GCM(new SM4GCM(key));}
    public static GCM Camellia(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new GCM(new Camellia(key));}
    public static GCM AESGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new GCM(new AESGCM());}
    public static ARIAGCM ARIAGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new ARIAGCM(key); }
    public static GCM SerpentGCM(byte[] key) throws XACryptoException, InvocationTargetException, NoSuchMethodException, IllegalAccessException { return new SerpentGCM(key); }
}
