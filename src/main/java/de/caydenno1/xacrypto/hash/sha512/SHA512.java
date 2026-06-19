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
            }
        }
    }
}
