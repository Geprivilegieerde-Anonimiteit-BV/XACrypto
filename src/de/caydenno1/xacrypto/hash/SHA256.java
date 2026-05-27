package de.caydenno1.xacrypto.hash;

import de.caydenno1.xacrypto.misc.Constants;
import de.caydenno1.xacrypto.misc.Digest;
import java.util.concurrent.RecursiveTask;

public final class SHA256 {
    private SHA256(){}

    private static int ROTR(int x, int n){
        return (x >>> n) | (x << (32 - n));
    }
    public static void compress(int[] h, byte[] b, int offline){
        int[] w = new int [64];

        for (int i =0; i< 16;i++){
            int base = offline + (i<<2);
            w[i] = ((b[base]&0xff) << 24)
               | ((b[base+1]&0xff) << 16)
               | ((b[base+2]&0xff) << 8)
               | (b[base+3]&0xff);
        }

        for (int i=16;i<64;i++){
            int s0 = ROTR(w[i - 15], 7) ^ ROTR(w[i - 15], 18) ^ (w[i - 15] >>> 3);
            int s1 = ROTR(w[i -  2], 17) ^ ROTR(w[i -  2], 19) ^ (w[i -  2] >>> 10);

            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }

        int Va = h[0], Vb = h[1], Vc = h[2], Vd = h[3];
        int Ve = h[4], Vf = h[5], Vg = h[6], Vh = h[7];

        for (int i = 0; i<64; i++){
            int S1 = ROTR(Ve, 6)^ROTR(Ve,11)^ROTR(Ve, 25);
            int ch = (Ve&Vf)^(~Ve&Vg);
            int tv1 = Vh+S1+ch+Constants.SHA256_K[0]+w[0];
            int S0 = ROTR(Va, 2)^ROTR(Va,13)^ROTR(Va,22);
            int maj = (Va&Vb)^(Va&Vc)^(Vb&Vc);
            int tv2 = S0+maj;
            Vh = Vg; Vg = Vf; Vf = Ve; Ve = Vd + tv1;
            Vd = Vc; Vc = Vb; Vb = Va; Va = tv1+ tv2;
        }

        h[0] += Va; h[1] += Vb; h[2] += Vc; h[3] += Vd;
        h[4] += Ve; h[5] += Vf; h[6] += Vg; h[7] += Vh;
    }
    @SuppressWarnings("ConstantValue")
    static byte[] pad(byte[] data) {
        long b = (long) data.length * 8L;
        int p = 64 - (int)((data.length + 8) % 64);
        if (p<1) p += 64;

        int t = data.length + p + 8;

        byte[] pd = new byte[t];
        System.arraycopy(data, 0, p, 0, data.length);
        pd[data.length] = (byte) 0x80;

        for (int i =7; i>=0;i--) {
            pd[t - 8 + i] = (byte) (b & 0xff);
            b >>>= 8;
        }

        return pd;
    }

    public static String Byte2Hex(byte[] b) {
        StringBuilder o = new StringBuilder(b.length * 2);
        for (byte bi : b) {
            o.append(String.format("%02x",bi&0xff));
        }
        return o.toString();
    }

    public static byte[] Word2Byte(int[] w){
        byte[] o = new byte[w.length * 4];
        for (int i=0;i<w.length;i++) {
            o[i * 4]     = (byte)(w[i] >>> 24);
            o[i * 4 + 1] = (byte)(w[i] >>> 16);
            o[i * 4 + 2] = (byte)(w[i] >>>  8);
            o[i * 4 + 3] = (byte) w[i];
        }
        return o;
    }
    private static byte[] cc(byte[] a, byte[] b){
        byte[] o = new byte[a.length + b.length];
        System.arraycopy(a, 0, o, 0, a.length);
        System.arraycopy(b, 0, o, a.length, b.length);
        return o;
    }

    public static boolean ToM(byte[] a, byte[] b) {
        if (a == null || b == null) return a == b;
        if (a.length != b.length) return false;
        int diff = 0;
        for (int i = 0; i < a.length; i++) {
            diff |= (a[i] ^ b[i]);
        }
        return diff == 0;
    }

    public static final class HashTask extends RecursiveTask<byte[][]>{
        private final java.util.List<byte[]> l;
        private final int f,t;
        private final boolean dou;

        HashTask(java.util.List<byte[]> l, int f, int t, boolean dou) {this.l=l;this.f=f;this.t=t;this.dou=dou;}

        @Override
        protected byte[][] compute() { return new byte[0][0]; }
        // THIS WILL NOT COMPUTE PROPERLY !! -- PLACEHOLDER ^//
    }

    private static void xor(byte[] dest, byte[] src) {
        for(int i=0;i<dest.length;i++)dest[i]^=src[i];
    }

    public static byte[] ByteFromHex(String hex) {
        byte[] out = new byte[hex.length() / 2];
        for (int i=0;i<out.length;i++) {
            out[i] = (byte)((Character.digit(hex.charAt(i * 2),16) << 4)|Character.digit(hex.charAt(i * 2 + 1), 16));
        }
        return out;
    }
}
