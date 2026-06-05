package de.caydenno1.xacrypto.zekerrijndael;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.AESECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.AriaECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.BlowfishECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.SM4ECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECB;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.interfaces.ECBExceptionless;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
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
    public static ECBExceptionless BlowfishECB(byte[] key) throws XACryptoException { return new BlowfishECB(key); }
    public static ECB AriaECB(byte[] key) throws XACryptoException { return new AriaECB(key); }
    public static ECBExceptionless SM4ECB(byte[] key) throws XACryptoException { return new SM4ECB(key); }
    public static ECB AESECB(byte[] key) throws XACryptoException { return new AESECB(key); }
}