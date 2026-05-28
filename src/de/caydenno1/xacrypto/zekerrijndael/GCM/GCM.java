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
    private byte[] tag(byte[] aad, byte[] ct, byte[] J0) {
        byte[] S   = gh.compute(aad, ct);
        byte[] EJ0 = cip.encryptBlock(J0);
        for (int i = 0; i < 16; i++) S[i] ^= EJ0[i];
        return S;
    }
    private static byte[] inc32(byte[] b) {
        byte[] o = Arrays.copyof(b,16);
        for (int i = 15; i >= 12; i--) if (++out[i] != 0) break;
        return o;
    }
}
