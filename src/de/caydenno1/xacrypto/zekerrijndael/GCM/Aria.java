package de.caydenno1.xacrypto.zekerrijndael.GCM;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.UnchangingData;

public class Aria {
    // this is NOT a cipher, more or less and encryption type/method
    private int round;
    private byte[][] encRK;
    private byte[][] decRK;

    public void Aria(boolean enc, byte[] key) throws XACryptoException {
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

        GRK(key);
        SDK();
    }

    private void SDK() {
       System.arraycopy(encRK[0], 0, decRK[round], 0, 16);
       System.arraycopy(encRK[round], 0, decRK[0], 0, 16);

       byte[] _0 = new byte[16];
       for (int i = 1 ; i < round ; i++){
           A(encRK[i], _0);
           System.arraycopy(_0, 0, decRK[round-i], 0, 16);
       }
    }
    private void procRound(byte[] state, byte[][] rK){
        byte[] _0 = new byte[16];

        for (int r = 0 ; r < round - 1 ; r++){
            AriaXOR(state,rK[r]);
            if (r % 2 == 0) {
                SL1(state, _0);
            } else {
                SL2(state, _0);
            }
            A(_0, state);
        }

        AriaXOR(state, rK[round-1]);
        if((round-1) % 2 == 0) {
            SL1(state, _0);
        } else {
            SL2(state, _0);
        }

        AriaXOR(_0, rK[round], state);
    }

    private void AriaXOR(byte[] blk, byte[] key){
        for (int i = 0 ; i < 16 ; i++){
            blk[i] ^= key[i];
        }
    }

    private void AriaXOR(byte[] a, byte[] b, byte[] o) {
        for (int i = 0 ; i < 16 ; i++) {
            o[i] = (byte)(a[i] ^ b[i]);
        }
    }

    private void SL1(byte[] i,byte[] o){
        byte[][] tables = {
                UnchangingData.ARIA_SB1,
                UnchangingData.ARIA_SB2,
                UnchangingData.ARIA_XB1,
                UnchangingData.ARIA_XB2
        };

        for (int k = 0; k < 16; k++) {
            o[k] = tables[k & 3][i[k] & 0xff];
        }

    }

    private void GRK(byte[] key) {/*temp placeholder*/}

    private void SL2(byte[] i,byte[] o){
        byte[][] tables = {
                UnchangingData.ARIA_XB1,
                UnchangingData.ARIA_XB2,
                UnchangingData.ARIA_SB1,
                UnchangingData.ARIA_SB2
        };

        for (int k = 0; k < 16; k++) {
            o[k] = tables[k & 3][i[k] & 0xff];
        }

    }
    private void A(byte[] i, byte[] o) {
        // "diffusion layer" Matrix A
        o[0]  = (byte)(i[3] ^ i[4] ^ i[9] ^ i[14]);
        o[1]  = (byte)(i[2] ^ i[5] ^ i[8] ^ i[15]);
        o[2]  = (byte)(i[1] ^ i[6] ^ i[11] ^ i[12]);
        o[3]  = (byte)(i[0] ^ i[7] ^ i[10] ^ i[13]);
        o[4]  = (byte)(i[0] ^ i[5] ^ i[11] ^ i[14]);
        o[5]  = (byte)(i[1] ^ i[4] ^ i[10] ^ i[15]);
        o[6]  = (byte)(i[2] ^ i[7] ^ i[9] ^ i[12]);
        o[7]  = (byte)(i[3] ^ i[6] ^ i[8] ^ i[13]);
        o[8]  = (byte)(i[1] ^ i[7] ^ i[11] ^ i[13]);
        o[9]  = (byte)(i[0] ^ i[6] ^ i[10] ^ i[12]);
        o[10] = (byte)(i[3] ^ i[5] ^ i[9] ^ i[15]);
        o[11] = (byte)(i[2] ^ i[4] ^ i[8] ^ i[14]);
        o[12] = (byte)(i[2] ^ i[6] ^ i[9] ^ i[14]);
        o[13] = (byte)(i[3] ^ i[7] ^ i[8] ^ i[15]);
        o[14] = (byte)(i[0] ^ i[4] ^ i[11] ^ i[12]);
        o[15] = (byte)(i[1] ^ i[5] ^ i[10] ^ i[13]);
    }
}
