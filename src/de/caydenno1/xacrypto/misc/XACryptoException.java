package de.caydenno1.xacrypto.misc;

public class XACryptoException extends Exception {
    public XACryptoException(String res) {
        super(res);
    }
    public XACryptoException(byte id){
        super(String.format("0x%02X", id & 0xFF));
    }
}
