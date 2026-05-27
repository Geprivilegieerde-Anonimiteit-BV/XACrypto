package de.caydenno1.xacrypto;

import de.caydenno1.xacrypto.hash.sha256.Hex;
import de.caydenno1.xacrypto.misc.XACryptoException;

public class XACrypto {
    private XACrypto() {}

    static void main(String[] args) throws XACryptoException {
        String res = Hex.hashPlain("test14");
        System.out.println(res);
    }
}
