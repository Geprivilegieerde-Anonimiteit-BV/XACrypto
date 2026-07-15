package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GHASH;
import de.caydenno1.xacrypto.zekerrijndael.GCM.AES;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

import java.util.Arrays;

import static de.caydenno1.xacrypto.misc.ToM.ToM;

public class AESGCM {
    public Result encryptBlock(byte[] pln, byte[] key, byte[] nonce, byte[] aad) throws XACryptoException {
        AES aes = new AES(key, getKeySize(key));
        GHASH gh = aesGHASH(aes);

        byte[] J0 = j0(nonce, gh);
        byte[] cip = gctr(aes, inc32(J0), pln);

        byte[] S = gh.compute(aad, cip);
        byte[] TB = aes.encryptBlock(J0);
        byte[] Tag = gh.xor(TB, S);

        return new Result(cip, Tag);
    }

    public byte[] decryptBlock(byte[] cip, byte[] key, byte[] nonce, byte[] aad, byte[] tag) throws XACryptoException {
        AES aes = new AES(key, getKeySize(key));
        GHASH gh = aesGHASH(aes);

        byte[] J0 = j0(nonce, gh);

        byte[] S = gh.compute(aad, cip);
        byte[] TB = aes.encryptBlock(J0);
        byte[] expectedTag = gh.xor(TB, S);

        if (!ToM(tag, expectedTag)) throw new XACryptoException("Tag does not match.");
        return gctr(aes, inc32(J0), cip);
    }

    public byte[] decryptBlock(byte[] cip, byte[] key, byte[] nonce, byte[] aad, byte[] tag, String flag) throws XACryptoException {
        return decryptBlock(cip, key, nonce, aad, tag);
    }

    private static int getKeySize(byte[] key) throws XACryptoException {
        return switch (key.length) {
            case 16 -> 128;
            case 24 -> 192;
            case 32 -> 256;
            default -> throw new XACryptoException("Invalid AES key length. Expected 16, 24, or 32 bytes.");
        };
    }

    private static GHASH aesGHASH(AES aes) throws XACryptoException {
        return new GHASH(aes.encryptBlock(new byte[16]));
    }

    private static byte[] j0(byte[] nonce, GHASH gh) {
        if (nonce.length == 12) {
            byte[] J0 = new byte[16];
            System.arraycopy(nonce, 0, J0, 0, 12);
            J0[15] = 1;
            return J0;
        } else {
            return gh.compNonce(gh.H(), nonce);
        }
    }

    private static byte[] gctr(AES aes, byte[] icb, byte[] in) throws XACryptoException {
        byte[] o = new byte[in.length];
        byte[] cnt = Arrays.copyOf(icb, 16);
        for (int i = 0; i < in.length; i += 16) {
            byte[] ks = aes.encryptBlock(cnt);
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
