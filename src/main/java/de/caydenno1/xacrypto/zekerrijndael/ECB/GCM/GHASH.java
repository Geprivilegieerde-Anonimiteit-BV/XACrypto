package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

import java.util.Arrays;


public class GHASH {
    private final byte[] H;

    private final byte[] _Z = new byte[16];
    private final byte[] _V = new byte[16];
    private final byte[] _bloc = new byte[16];
    private final byte[] _lenBlock = new byte[16];
    private final byte[] _Y = new byte[16];
    private final byte[] _blk = new byte[16];

    public GHASH(byte[] H) {
        this.H = Arrays.copyOf(H, 16);
    }

    public byte[] H() {
        return H;
    }

    public byte[] compute(byte[] aad, byte[] cip){
        Arrays.fill(_Y, (byte) 0);
        proc(_Y, aad);
        proc(_Y, cip);
        buildLenBlock(aad.length * 8L, cip.length * 8L);
        xor(_Y, _lenBlock);
        multi(_Y, H, _Y);
        return Arrays.copyOf(_Y, 16);
    }

    private void proc(byte[] Y, byte[] in) {
        for (int off = 0; off < in.length; off += 16) {
            Arrays.fill(_bloc, (byte) 0);
            int len = Math.min(16, in.length - off);
            System.arraycopy(in, off, _bloc, 0, len);
            xor(Y, _bloc);
            multi(Y, H, Y);
        }
    }

    void multi(byte[] X, byte[] Y, byte[] out) {
        Arrays.fill(_Z, (byte) 0);
        System.arraycopy(Y, 0, _V, 0, 16);
        for (int bit = 0; bit < 128; bit++) {
            if (((X[bit >>> 3] >> (7 - (bit & 7))) & 1) == 1) {
                for (int i = 0; i < 16; i++) _Z[i] ^= _V[i];
            }
            boolean isLSB1 = (_V[15] & 1) != 0;
            RS(_V);
            if (isLSB1) {
                for (int i = 0; i < 16; i++) _V[i] ^= UnchangingData.R[i];
            }
        }
        System.arraycopy(_Z, 0, out, 0, 16);
    }

    private void RS(byte[] bloc) {
        int c = 0;
        for (int i = 0; i < 16; i++) {
            int val = bloc[i] & 0xFF;
            int next = val & 1;
            bloc[i] = (byte) ((val >>> 1) | (c << 7));
            c = next;
        }
    }

    public byte[] compNonce(byte[] H, byte[] nonce) {
        Arrays.fill(_Y, (byte) 0);

        int len = nonce.length;
        int off = 0;

        while (len > 0) {
            Arrays.fill(_blk, (byte) 0);
            int cl = Math.min(16, len);
            System.arraycopy(nonce, off, _blk, 0, cl);
            xor(_Y, _blk);
            multi(_Y, H, _Y);
            off += cl;
            len -= cl;
        }

        Arrays.fill(_blk, (byte) 0);
        long bL = (long) nonce.length * 8;
        for (int i = 8; i < 16; i++) {
            _blk[i] = (byte) ((bL >>> (8 * (15 - i))) & 0xFF);
        }

        xor(_Y, _blk);
        multi(_Y, H, _Y);
        return Arrays.copyOf(_Y, 16);
    }

    private void buildLenBlock(long aad, long cipb) {
        _lenBlock[0]  = (byte)(aad >>> 56);
        _lenBlock[1]  = (byte)(aad >>> 48);
        _lenBlock[2]  = (byte)(aad >>> 40);
        _lenBlock[3]  = (byte)(aad >>> 32);
        _lenBlock[4]  = (byte)(aad >>> 24);
        _lenBlock[5]  = (byte)(aad >>> 16);
        _lenBlock[6]  = (byte)(aad >>> 8);
        _lenBlock[7]  = (byte)(aad);
        _lenBlock[8]  = (byte)(cipb >>> 56);
        _lenBlock[9]  = (byte)(cipb >>> 48);
        _lenBlock[10] = (byte)(cipb >>> 40);
        _lenBlock[11] = (byte)(cipb >>> 32);
        _lenBlock[12] = (byte)(cipb >>> 24);
        _lenBlock[13] = (byte)(cipb >>> 16);
        _lenBlock[14] = (byte)(cipb >>> 8);
        _lenBlock[15] = (byte)(cipb);
    }

    public byte[] xor(byte[] a, byte[] b) {
        for (int i = 0; i < 16; i++) a[i] ^= b[i];
        return a;
    }
}
