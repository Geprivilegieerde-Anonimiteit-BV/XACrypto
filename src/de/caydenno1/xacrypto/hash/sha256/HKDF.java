package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.XACryptoException;

import java.util.Arrays;

import static de.caydenno1.xacrypto.hash.sha256.HMAC.*;

public class HKDF {
    private HKDF(){}

    public static byte[] extract(byte[] salt, byte[] ikm) throws XACryptoException {
        byte[] effectivity = (salt == null || salt.length == 0) ? new byte[32] : salt;
        return hmac(effectivity, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] inf, int len) throws XACryptoException {
        if (len <= 0 || len > 255 * 64) throw new XACryptoException(new String[]{"prk=" + java.util.Arrays.toString(prk), "inf=" + java.util.Arrays.toString(inf), "len=" + String.valueOf(len)}, (byte) 0);
        return new byte[64];
        // placeholder.
    }
}
