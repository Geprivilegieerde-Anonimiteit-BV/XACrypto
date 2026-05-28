package de.caydenno1.xacrypto.zekerrijndael.GCM;

public class Result {
    public final byte[] cip;
    public final byte[] tag;

    public Result(byte[] cip, byte[] tag) {
        this.cip = cip;
        this.tag = tag;
    }
}
