package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

import java.nio.ByteBuffer;
import java.util.Arrays;

public class GHASH {
    private final byte[] H;

    public GHASH(byte[] H) {
        this.H = Arrays.copyOf(H, 16);
    }

    public byte[] compute(byte[] aad, byte[] cip){
        byte[] Y = new byte[16];
        Y = processBlocks(Y, aad);
        Y = processBlocks(Y, cip);
        byte[] lenBlock = buildLenBlock(
                aad.length * 8L,
                cip.length * 8L
        );
        Y = xor(Y, lenBlock);
        Y = multi(Y,H);
        return Y;
    }
    private byte[] processBlocks(byte[]Y, byte[] in) {
        for (int off = 0; off < in.length; off+=16){
            byte[] bloc = new byte[16];
            int len = Math.min(16, in.length - off);
            System.arraycopy(in, off, bloc, 0, len);
            Y = xor(Y, bloc);
            Y = multi(Y, H);
        }
        return Y;
    }
    private byte[] multi(byte[] X, byte[] Y) {
        byte[] Z = new byte[16];
        byte[] V = Arrays.copyOf(Y, 16);
        for (int bit = 0 ; bit < 128 ; bit++) {
            int byindex = bit / 8;
            int biindex = 7 - (bit%8);

            if (((X[byindex] >> biindex) & 1) == 1) Z = xor(Z,V);
            RShift(V);
            if ((V[15] & 1) != 0) V = xor(V,UnchangingData.R);
        }
        return Z;
    }
    private void RShift(byte[] bloc) {
        int c = 0 ;
        for (int i = 0 ; i < 16 ; i++){
            int val = bloc[i] & 0xFF;
            int next = val & 1;
            bloc[i] = (byte) ((val >>> 1) | (c << 7));

            c = next;
        }
    }
    private byte[] buildLenBlock(long aad, long cipb) {
        ByteBuffer buf = ByteBuffer.allocate(16);

        buf.putLong(aad);
        buf.putLong(cipb);

        return buf.array();
    }
    private byte[] xor(byte[] a, byte[] b){
        byte[] res = new byte[16];
        for (int i = 0 ; i < 16 ; i++){
            res[i] = (byte) (a[i] ^ b[i]);
        }

        return res;
    }
}
