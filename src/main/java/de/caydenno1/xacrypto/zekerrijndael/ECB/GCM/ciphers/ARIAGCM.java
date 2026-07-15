package de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;
import de.caydenno1.xacrypto.zekerrijndael.GCM.GCM;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

public class ARIAGCM {
    private final GCM engine;

    public ARIAGCM(byte[] key) throws XACryptoException, NoSuchMethodException {
        this.engine = new GCM(new Aria(true, key));
    }

    public Result encrypt(byte[] pln, byte[] aad, byte[] iv) throws XACryptoException {
        return engine.encrypt(pln, aad, iv);
    }

    public byte[] decrypt(Result res, byte[] aad) throws XACryptoException {
        return engine.decrypt(res, aad);
    }

    public byte[] decrypt(Result res, byte[] aad, String optflag) throws XACryptoException {
        return engine.decrypt(res, aad, optflag);
    }
}
