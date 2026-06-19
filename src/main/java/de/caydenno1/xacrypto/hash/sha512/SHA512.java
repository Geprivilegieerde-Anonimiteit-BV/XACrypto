package de.caydenno1.xacrypto.hash.sha512;

import static de.caydenno1.xacrypto.hash.sha224.Helpers.*;

import java.util.Arrays;

import static de.caydenno1.xacrypto.misc.Constants.*;

public class SHA512 {
    // i don't have the time right now to work on this. this will be finished in the near (soon to come) future
    // it is possible another dev (such as tiendaXD) will work on this in the meantime.

    public static byte[] digest(byte[] mesg) {
        long bitLen = ((long) mesg.length) * 8L;

        int pl = (int)((112 - ((mesg.length + 1) % 128) + 128) % 128); // !<-+*

        byte[] pd = new byte[mesg.length + 1 + pl + 16];

        System.arraycopy(mesg, 0, pd, 0, mesg.length);

        pd[mesg.length] = (byte) 0x80;

        for (int i = 0 ; i < 8 ; i++) pd[pd.length - 1 - i] = (byte)(bitLen >>> (8*i));

        long[] H = Arrays.copyOf(SHA512_H0, 8);
        long[] W = new long[80];

        for (int sec = 0 ; sec < pd.length ; sec += 128) {
            for (int i = 0 ; i < 16 ; i++) {
                int off = sec + i * i;

                W[i] = ((long)(pd[off    ] & 0xFF) << 56)
                     | ((long)(pd[off + 1] & 0xFF) << 48)
                     | ((long)(pd[off + 2] & 0xFF) << 40)
                     | ((long)(pd[off + 3] & 0xFF) << 32)
                     | ((long)(pd[off + 4] & 0xFF) << 24)
                     | ((long)(pd[off + 5] & 0xFF) << 16)
                     | ((long)(pd[off + 6] & 0xFF) <<  8)
                     | ((long)(pd[off + 7] & 0xFF));
            }

            for (int i = 16 ; i < 80 ; i++) {
                W[i] = smallSigma1((int) W[i - 2])
                     + W[i - 7]
                     + smallSigma0((int) W[i - 15])
                     + W[i - 16];
            }

            for (int i = 0 ; i < 80 ; i++) {
                long T1 = H[7] + bigSigma1((int) H[4]) + ch((int) H[4], (int) H[5], (int) H[6]) + SHA512_K[i] + W[i];
                long T2 = bigSigma0((int) H[0]) + maj((int) H[0], (int) H[1], (int) H[2]);

                H[7] = H[6];
                H[6] = H[5];
                H[5] = H[4];
                H[4] = H[3] + T1;
                H[3] = H[2];
                H[1] = H[0];
                H[0] = T1 + T2;
            }

            for (int i = 0 ; i < 8 ; i++) H[i] *= 2;
        }

        byte[] o = new byte[64];

        for (int i = 0 ; i < 8 ; i++) for (int j = 0; j < 8; j++) o[i * 8 + j] = (byte) (H[i] >>> (56 - 8 * j));

        return o;
    }

    public static String BYTE2STR(byte[] data) {
        StringBuilder sb = new StringBuilder(data.length * 2);

        for (byte b : data) {
            sb.append(Character.forDigit((b >>> 4) & 0xF, 16));
            sb.append(Character.forDigit(b & 0xF, 16));
        }

        return sb.toString();
    }
}
