package de.caydenno1.xacrypto.misc;

public class isNull {
    public static boolean isNull(Object v) {
        return v == null;
    }
    public boolean isNull(Object v, Object alt) {
        return v == null || v == alt;
    }
    public static boolean isValidText(String s) {
        if (s == null || s.isBlank()) return false;
        return !s.trim().isEmpty();
    }
}
