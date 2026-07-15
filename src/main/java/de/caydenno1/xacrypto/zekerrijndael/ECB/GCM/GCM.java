package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.misc.ToM;
import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.misc.isNull;

import java.util.Arrays;

public class GCM {
    private final GHASH gh;
    private final BlockCipher cipher;

    public GCM(BlockCipher cipher) throws XACryptoException {
        this.cipher = cipher;
        byte[] H = cipher.encryptBlock(new byte[16]);
        this.gh = new GHASH(H);
    }

    public Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException {
        if (iv.length <= 0) throw new XACryptoException("iv does not have data or is corrupted :[");
        if (pln == null) pln = new byte[0];
        if (aad == null) aad = new byte[0];

        byte[] J0 = j0(iv);
        byte[] ct  = gctr(inc32(J0), pln);
        byte[] tag = tag(aad, ct, J0);

        byte[] packaged = new byte[iv.length + ct.length];
        System.arraycopy(iv, 0, packaged, 0, iv.length);
        System.arraycopy(ct, 0, packaged, iv.length, ct.length);

        return new Result(packaged, tag);
    }

    public byte[] decrypt(Result res, byte[] aad) throws XACryptoException {
        return dec(res, aad, 12);
    }

    public byte[] decrypt(Result res, byte[] aad, int ivLen) throws XACryptoException {
        return dec(res, aad, ivLen);
    }

    public byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException {
        return dec(res, aad, 12);
    }

    public byte[] decrypt(Result res, byte[] aad, int ivLen, String optflag) throws XACryptoException {
        return dec(res, aad, ivLen);
    }

    private byte[] dec(Result res, byte[] aad, int ivLen) throws XACryptoException {
        if (res.cip().length < ivLen) throw new XACryptoException("ciptext min len is ivLen");
        if (isNull.isNull(aad)) aad = new byte[0];

        byte[] iv = Arrays.copyOfRange(res.cip(), 0, ivLen);
        byte[] ct = Arrays.copyOfRange(res.cip(), ivLen, res.cip().length);

        byte[] J0 = j0(iv);
        byte[] expectedTag = tag(aad, ct, J0);

        boolean corr = ToM.ToM(res.tag(), expectedTag);
        if (!corr) throw new XACryptoException("GCM tag does not match.", (byte) -1);

        return gctr(inc32(J0), ct);
    }

    private byte[] j0(byte[] iv) {
        if (iv.length == 12) {
            byte[] J0 = new byte[16];
            System.arraycopy(iv, 0, J0, 0, 12);
            J0[15] = 0x01;
            return J0;
        } else {
            return gh.compute(new byte[0], iv);
        }
    }

    private byte[] tag(byte[] aad, byte[] ct, byte[] J0) throws XACryptoException {
        byte[] S   = gh.compute(aad, ct);
        byte[] EJ0 = cipher.encryptBlock(J0);
        for (int i = 0; i < 16; i++) S[i] ^= EJ0[i];
        return S;
    }

    private byte[] gctr(byte[] icb, byte[] in) throws XACryptoException {
        byte[] o = new byte[in.length];
        byte[] cnt = Arrays.copyOf(icb, 16);
        for (int i = 0; i < in.length; i += 16) {
            byte[] ks = cipher.encryptBlock(cnt);
            int len = Math.min(16, in.length - i);
            for (int j = 0; j < len; j++) o[i + j] = (byte) (in[i + j] ^ ks[j]);
            if (i + 16 < in.length) cnt = inc32(cnt);
        }
        return o;
    }

    private static byte[] inc32(byte[] b) {
        byte[] o = Arrays.copyOf(b, 16);
        for (int i = 15; i >= 12; i--) if (++o[i] != 0) break;
        return o;
    }
}
