package de.caydenno1.xacrypto.misc;

public class XACryptoException extends Exception {
    private int id;

    public XACryptoException(String res) {
        super(res);
    }
    public XACryptoException(byte id){
        super(String.format("0x%02X", id & 0xFF));
    }
    public XACryptoException(String[] pnts, byte id){
        super(String.join("|", pnts));
        this.id = id & 0xFF;
    }
}
