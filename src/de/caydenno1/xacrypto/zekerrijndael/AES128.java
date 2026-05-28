package de.caydenno1.xacrypto.zekerrijndael;

import java.util.Arrays;

import static de.caydenno1.xacrypto.zekerrijndael.UnchangingData.*;

public final class AES128 {

    private final byte[][] keys = new byte[44][4];

    public AES128(byte[] key) {
        keyExpansion(key);
    }

    public byte[] encryptBlock(byte[] input) {

        byte[][] s = new byte[4][4];

        for (int i = 0; i < 16; i++) {
            s[i & 3][i >> 2] = input[i];
        }

        addRoundKey(s, 0);

        for (int r = 1; r < 10; r++) {
            sub(s);
            shift(s);
            mixColumns(s);
            addRoundKey(s, r);
        }

        sub(s);
        shift(s);
        addRoundKey(s, 10);

        byte[] o = new byte[16];

        for (int i = 0; i < 16; i++) {
            o[i] = s[i & 3][i >> 2];
        }

        return o;
    }

    private void sub(byte[][] s) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                s[r][c] = SBOX[s[r][c] & 0xFF];
            }
        }
    }

    private void shift(byte[][] s) {

        byte t;

        t = s[1][0];
        s[1][0] = s[1][1];
        s[1][1] = s[1][2];
        s[1][2] = s[1][3];
        s[1][3] = t;

        t = s[2][0];
        byte t2 = s[2][1];
        s[2][0] = s[2][2];
        s[2][1] = s[2][3];
        s[2][2] = t;
        s[2][3] = t2;

        t = s[3][3];
        s[3][3] = s[3][2];
        s[3][2] = s[3][1];
        s[3][1] = s[3][0];
        s[3][0] = t;
    }

    private void mixColumns(byte[][] s) {

        for (int c = 0; c < 4; c++) {

            byte a0 = s[0][c];
            byte a1 = s[1][c];
            byte a2 = s[2][c];
            byte a3 = s[3][c];

            s[0][c] = (byte)(gm2(a0) ^ gm3(a1) ^ a2 ^ a3);
            s[1][c] = (byte)(a0 ^ gm2(a1) ^ gm3(a2) ^ a3);
            s[2][c] = (byte)(a0 ^ a1 ^ gm2(a2) ^ gm3(a3));
            s[3][c] = (byte)(gm3(a0) ^ a1 ^ a2 ^ gm2(a3));
        }
    }

    private byte gm2(byte b) {
        int x = b & 0xFF;
        return (byte)(((x << 1) ^ ((x & 0x80) != 0 ? 0x1b : 0)) & 0xFF);
    }

    private byte gm3(byte b) {
        return (byte)(gm2(b) ^ b);
    }

    private void addRoundKey(byte[][] s, int round) {
        for (int c = 0; c < 4; c++) {
            for (int r = 0; r < 4; r++) {
                s[r][c] ^= keys[round * 4 + c][r];
            }
        }
    }

    private void keyExpansion(byte[] key) {

        for (int i = 0; i < 4; i++) {
            System.arraycopy(key, i * 4, keys[i], 0, 4);
        }

        for (int i = 4; i < 44; i++) {

            byte[] temp = Arrays.copyOf(keys[i - 1], 4);

            if (i % 4 == 0) {

                byte t = temp[0];
                temp[0] = temp[1];
                temp[1] = temp[2];
                temp[2] = temp[3];
                temp[3] = t;

                for (int j = 0; j < 4; j++) {
                    temp[j] = SBOX[temp[j] & 0xFF];
                }

                temp[0] ^= (byte)(RCON[i / 4] >>> 24);
            }

            for (int j = 0; j < 4; j++) {
                keys[i][j] = (byte)(keys[i - 4][j] ^ temp[j]);
            }
        }
    }


    public byte[] encryptCBC(byte[] pln, byte[] iv) {

        byte[] o = new byte[pln.length];
        byte[] prev = Arrays.copyOf(iv, 16);

        byte[] block = new byte[16];

        for (int i = 0; i < pln.length; i += 16) {

            for (int j = 0; j < 16; j++) {
                block[j] = (byte)(pln[i + j] ^ prev[j]);
            }

            byte[] enc = encryptBlock(block);

            System.arraycopy(enc, 0, o, i, 16);

            prev = enc;
        }

        return o;
    }
    
    public byte[] encryptCTR(byte[] pln, byte[] nonce) {

        byte[] o = new byte[pln.length];

        byte[] cnt = Arrays.copyOf(nonce, 16);
        byte[] ks;

        for (int i = 0; i < pln.length; i += 16) {

            int ctr = i >>> 4;

            cnt[12] = (byte)(ctr >>> 24);
            cnt[13] = (byte)(ctr >>> 16);
            cnt[14] = (byte)(ctr >>> 8);
            cnt[15] = (byte)(ctr);

            ks = encryptBlock(cnt);

            for (int j = 0; j < 16; j++) {
                o[i + j] = (byte) (pln[i + j] ^ ks[j]);
            }
        }

        return o;
    }
}