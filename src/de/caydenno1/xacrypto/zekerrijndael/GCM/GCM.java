package de.caydenno1.xacrypto.zekerrijndael.GCM;

public class GCM {
    private final BlockCipher cip;
    private final GHASH gh;

    private GCM(BlockCipher cip){
        this.cip = cip;
        byte[] H = cip.encryptBlock(new byte[16]);
        this.gh = new GHASH(H);
    }
}
