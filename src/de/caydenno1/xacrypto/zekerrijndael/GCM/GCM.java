package de.caydenno1.xacrypto.zekerrijndael.GCM;

public class GCM {
    private final BlockCipher cip;
    private final GHASH gh;

    private GCM(BlockCipher cip){
        this.cip = cip;
        byte[] H = cip.encryptBlock(new byte[16]);
        this.gh = new GHASH(H);
    }
    private static byte[] j0(byte[] iv) {
        byte[] J0 = new byte[16];
        System.arraycopy(iv, 0, J0, 0, 12);
        J0[15] = 0x01;
        return J0;
    }
}
