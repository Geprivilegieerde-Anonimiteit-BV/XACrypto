package de.caydenno1.xacrypto.zekerrijndael.Global;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.GCM.BlockCipher;
import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

public class Aria implements BlockCipher {
    private final int round;
    private final byte[][] encRK;
    private final byte[][] decRK;

    public Aria(boolean enc, byte[] key) throws XACryptoException {
        int kb = key.length * 8;
        round = switch(kb) {
            case 128 -> 12;
            case 192 -> 14;
            case 256 -> 16;
            default -> throw new XACryptoException(
                    "only 128, 192 and 256 bit ciphers are supported atm. sorry :%"
            );
        };

        encRK = new byte[round + 1][16];
        decRK = new byte[round + 1][16];

        encRK(key);
        SDK();
    }

    @Override
    public byte[] encryptBlock(byte[] in) throws XACryptoException {
        if (in.length != 16) throw new XACryptoException("input length is required to be 16 bytes", (byte)0x16);

        byte[] currentState = new byte[16];
        System.arraycopy(in, 0, currentState, 0, 16);

        procRound(currentState, this.encRK);

        return currentState;
    }

    public byte[] decryptBlock(byte[] in) throws XACryptoException {
        if (in.length != 16) throw new XACryptoException("input length is required to be 16 bytes", (byte)0x16);

        byte[] state = new byte[16];
        System.arraycopy(in, 0, state, 0, 16);

        procRound(state, this.decRK);

        return state;
    }

    private void SDK() {
        System.arraycopy(encRK[0], 0, decRK[round], 0, 16);
        System.arraycopy(encRK[round], 0, decRK[0], 0, 16);

        for (int i = 1; i < round; i++) {
            A(encRK[i], decRK[round - i]);
        }
    }

    private void procRound(byte[] state, byte[][] rK) {
        for (int r = 0; r < round - 1; r++) {
            AriaXOR(state, rK[r]);
            if ((r & 1) == 0) {
                SL1(state, state);
            } else {
                SL2(state, state);
            }
            A(state, state);
        }

        AriaXOR(state, rK[round - 1]);
        if (((round - 1) & 1) == 0) {
            SL1(state, state);
        } else {
            SL2(state, state);
        }

        AriaXOR(state, rK[round], state);
    }

    private void AriaXOR(byte[] blk, byte[] key) {
        for (int i = 0; i < 16; i++) {
            blk[i] ^= key[i];
        }
    }

    private void AriaXOR(byte[] a, byte[] b, byte[] o) {
        for (int i = 0; i < 16; i++) {
            o[i] = (byte) (a[i] ^ b[i]);
        }
    }

    public void SROTR128(byte[] i, int bits, byte[] o) {
        int byS = bits / 8;
        int biS = bits % 8;

        for (int _0 = 0; _0 < 16; _0++) {
            int idx1 = (_0 - byS + 32) & 15;
            int idx2 = (_0 - byS - 1 + 32) & 15;

            int b1 = i[idx1] & 0xFF;
            int b2 = i[idx2] & 0xFF;

            o[_0] = (byte) ((b1 >>> biS) | (b2 << (8 - biS)));
        }
    }

    private void FO(byte[] i, byte[] ck, byte[] o) {
        AriaXOR(i, ck, o);
        SL1(o, o);
        A(o, o);
    }

    private void FE(byte[] i, byte[] ck, byte[] o) {
        AriaXOR(i, ck, o);
        SL2(o, o);
        A(o, o);
    }

    private void SL1(byte[] i, byte[] o) {
        for (int k = 0; k < 16; k++) {
            int val = i[k] & 0xff;
            o[k] = switch (k & 3) {
                case 0 -> UnchangingData.ARIA_SB1[val];
                case 1 -> UnchangingData.ARIA_SB2[val];
                case 2 -> UnchangingData.ARIA_XB1[val];
                default -> UnchangingData.ARIA_XB2[val];
            };
        }
    }

    private void SL2(byte[] i, byte[] o) {
        for (int k = 0; k < 16; k++) {
            int val = i[k] & 0xff;
            o[k] = switch (k & 3) {
                case 0 -> UnchangingData.ARIA_XB1[val];
                case 1 -> UnchangingData.ARIA_XB2[val];
                case 2 -> UnchangingData.ARIA_SB1[val];
                default -> UnchangingData.ARIA_SB2[val];
            };
        }
    }

    private void A(byte[] i, byte[] o) {
        byte res0  = (byte)(i[3] ^ i[4] ^ i[9] ^ i[14]);
        byte res1  = (byte)(i[2] ^ i[5] ^ i[8] ^ i[15]);
        byte res2  = (byte)(i[1] ^ i[6] ^ i[11] ^ i[12]);
        byte res3  = (byte)(i[0] ^ i[7] ^ i[10] ^ i[13]);
        byte res4  = (byte)(i[0] ^ i[5] ^ i[11] ^ i[14]);
        byte res5  = (byte)(i[1] ^ i[4] ^ i[10] ^ i[15]);
        byte res6  = (byte)(i[2] ^ i[7] ^ i[9] ^ i[12]);
        byte res7  = (byte)(i[3] ^ i[6] ^ i[8] ^ i[13]);
        byte res8  = (byte)(i[1] ^ i[7] ^ i[11] ^ i[13]);
        byte res9  = (byte)(i[0] ^ i[6] ^ i[10] ^ i[12]);
        byte res10 = (byte)(i[3] ^ i[5] ^ i[9] ^ i[15]);
        byte res11 = (byte)(i[2] ^ i[4] ^ i[8] ^ i[14]);
        byte res12 = (byte)(i[2] ^ i[6] ^ i[9] ^ i[14]);
        byte res13 = (byte)(i[3] ^ i[7] ^ i[8] ^ i[15]);
        byte res14 = (byte)(i[0] ^ i[4] ^ i[11] ^ i[12]);
        byte res15 = (byte)(i[1] ^ i[5] ^ i[10] ^ i[13]);

        o[0]  = res0;  o[1]  = res1;  o[2]  = res2;  o[3]  = res3;
        o[4]  = res4;  o[5]  = res5;  o[6]  = res6;  o[7]  = res7;
        o[8]  = res8;  o[9]  = res9;  o[10] = res10; o[11] = res11;
        o[12] = res12; o[13] = res13; o[14] = res14; o[15] = res15;
    }

    private void encRK(byte[] key) throws XACryptoException {
        int size = key.length;

        byte[] KL = new byte[16];
        byte[] KR = new byte[16];
        byte[][] CK = new byte[4][16];

        if (size == 16 || size == 24 || size == 32) System.arraycopy(key, 0, KL, 0, 16);
        switch(size) {
            case 16: CK[1] = UnchangingData.ARIA_C1; CK[2] = UnchangingData.ARIA_C2; CK[3] = UnchangingData.ARIA_C3; break;
            case 24: {
                System.arraycopy(key, 16, KR, 0, 8);
                CK[1] = UnchangingData.ARIA_C2; CK[2] = UnchangingData.ARIA_C3; CK[3] = UnchangingData.ARIA_C1;
                break;
            }
            case 32: {
                System.arraycopy(key, 16, KR, 0, 16);
                CK[1] = UnchangingData.ARIA_C3; CK[2] = UnchangingData.ARIA_C1; CK[3] = UnchangingData.ARIA_C2;
                break;
            }
            default: throw new XACryptoException("only keysizes of 16,24,32 are supported atm :|");
        }

        byte[][] W = new byte[4][16];
        System.arraycopy(KL, 0, W[0], 0, 16);

        FO(W[0], CK[1], W[1]);
        AriaXOR(W[1], KR, W[1]);
        FE(W[1], CK[2], W[2]);
        AriaXOR(W[2], W[0], W[2]);
        FO(W[2], CK[3], W[3]);
        AriaXOR(W[3], W[1], W[3]);

        SROTR128(W[1], 19, encRK[0]);
        AriaXOR(W[0], encRK[0], encRK[0]);

        SROTR128(W[2], 19, encRK[1]);
        AriaXOR(W[1], encRK[1], encRK[1]);

        SROTR128(W[3], 19, encRK[2]);
        AriaXOR(W[2], encRK[2], encRK[2]);

        SROTR128(W[0], 19, encRK[3]);
        AriaXOR(encRK[3], W[3], encRK[3]);

        SROTR128(W[1], 31, encRK[4]);
        AriaXOR(W[0], encRK[4], encRK[4]);

        SROTR128(W[2], 31, encRK[5]);
        AriaXOR(W[1], encRK[5], encRK[5]);

        SROTR128(W[3], 31, encRK[6]);
        AriaXOR(W[2], encRK[6], encRK[6]);

        SROTR128(W[0], 31, encRK[7]);
        AriaXOR(encRK[7], W[3], encRK[7]);

        SROTR128(W[1], 67, encRK[8]);
        AriaXOR(W[0], encRK[8], encRK[8]);

        SROTR128(W[2], 67, encRK[9]);
        AriaXOR(W[1], encRK[9], encRK[9]);

        SROTR128(W[3], 67, encRK[10]);
        AriaXOR(W[2], encRK[10], encRK[10]);

        SROTR128(W[0], 67, encRK[11]);
        AriaXOR(encRK[11], W[3], encRK[11]);

        SROTR128(W[1], 97, encRK[12]);
        AriaXOR(W[0], encRK[12], encRK[12]);

        if (round >= 14) {
            SROTR128(W[2], 97, encRK[13]);
            AriaXOR(W[1], encRK[13], encRK[13]);

            SROTR128(W[3], 97, encRK[14]);
            AriaXOR(W[2], encRK[14], encRK[14]);
        }

        if (round == 16) {
            SROTR128(W[0], 97, encRK[15]);
            AriaXOR(encRK[15], W[3], encRK[15]);

            SROTR128(W[1], 109, encRK[16]);
            AriaXOR(W[0], encRK[16], encRK[16]);
        }
    }
}