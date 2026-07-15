package de.caydenno1.xacrypto.hash.sha224;

import java.nio.charset.StandardCharsets;

import static de.caydenno1.xacrypto.hash.sha224.SHA224.digest;

public class Digest {
    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public static String digestHex(String text) {
        byte[] hash = digest(text.getBytes(StandardCharsets.UTF_8));
        char[] out = new char[hash.length * 2];
        for (int i = 0; i < hash.length; i++) {
            out[i * 2]     = HEX[(hash[i] >>> 4) & 0xF];
            out[i * 2 + 1] = HEX[hash[i] & 0xF];
        }
        return new String(out);
    }
}
