package de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers;

import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.zekerrijndael.Global.Aria;

public class AriaECB {
    private final Aria engine;

    public AriaECB(byte[] key) throws XACryptoException {
        this.engine = new Aria(true,key);
    }

    
}
