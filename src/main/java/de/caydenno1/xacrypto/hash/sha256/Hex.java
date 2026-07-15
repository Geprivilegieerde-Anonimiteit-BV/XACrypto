package de.caydenno1.xacrypto.hash.sha256;

import de.caydenno1.xacrypto.misc.XACryptoException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

public class Hex {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public static byte[] hash(byte[] data) throws XACryptoException {
        return new Digest().upd(data).digest();
    }

    public static byte[] hash(String text) throws XACryptoException {
        return hash(text.getBytes(StandardCharsets.UTF_8));
    }

    public static String hashPlain(String text) throws XACryptoException {
        byte[] res = new Digest().upd(text).digest();
        char[] out = new char[res.length * 2];
        for (int i = 0; i < res.length; i++) {
            out[i * 2]     = HEX[(res[i] >>> 4) & 0xF];
            out[i * 2 + 1] = HEX[res[i] & 0xF];
        }
        return new String(out);
    }

    public static String hashHex(String text) throws XACryptoException {
        return Byte2Hex(hash(text));
    }

    public static String hashHex(byte[] data) throws XACryptoException {
        return Byte2Hex(hash(data));
    }

    public static ByteBuffer Hash2Buffer(byte[] data) throws XACryptoException {
        return ByteBuffer.wrap(hash(data)).asReadOnlyBuffer();
    }

    public static byte[] doubleHash(byte[] data) throws XACryptoException {
        return hash(hash(data));
    }

    public static String Byte2Hex(byte[] b) {
        char[] o = new char[b.length * 2];
        for (int i = 0; i < b.length; i++) {
            o[i * 2]     = HEX[(b[i] >>> 4) & 0xF];
            o[i * 2 + 1] = HEX[b[i] & 0xF];
        }
        return new String(o);
    }
}
