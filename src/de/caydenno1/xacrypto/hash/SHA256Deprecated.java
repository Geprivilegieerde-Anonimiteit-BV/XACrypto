package de.caydenno1.xacrypto.hash;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class SHA256Deprecated {
    // THIS IS A TEMPORARY FILE AND EXTREMELY VOLATILE!! it will be removed when i create a more advanced sha256 (i just dont have the time rn so this will be here for now)
    // this just uses MessageDigest and is extremely BAD! do not use this, do not use it, dont use itttt! lol //
    // you have been warned. //

    private SHA256Deprecated(){};

    public static String hash(String raw) throws NoSuchAlgorithmException {
        MessageDigest dig = MessageDigest.getInstance("SHA-256");

        byte[] res = dig.digest(raw.getBytes(StandardCharsets.UTF_8));
        StringBuilder hex = new StringBuilder();
        for (byte b :res) {
            hex.append(String.format("%02x", b));
        }

        return hex.toString();
    };
}
