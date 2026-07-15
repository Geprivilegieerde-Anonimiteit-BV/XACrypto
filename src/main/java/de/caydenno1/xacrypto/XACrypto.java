package de.caydenno1.xacrypto;

import de.caydenno1.xacrypto.hash.ROT;
import de.caydenno1.xacrypto.hash.sha.SHA1;
import de.caydenno1.xacrypto.hash.sha224.SHA224;
import de.caydenno1.xacrypto.hash.sha256.Digest;
import de.caydenno1.xacrypto.hash.sha256.HKDF;
import de.caydenno1.xacrypto.hash.sha256.HMAC;
import de.caydenno1.xacrypto.hash.sha256.Hex;
import de.caydenno1.xacrypto.hash.sha256.SHA256;
import de.caydenno1.xacrypto.hash.sha384.SHA384;
import de.caydenno1.xacrypto.misc.XACryptoException;
import de.caydenno1.xacrypto.misc.isNull;
import de.caydenno1.xacrypto.zekerrijndael.ECB.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.GCM.ciphers.*;
import de.caydenno1.xacrypto.zekerrijndael.GCM.Result;

import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

public class XACrypto {
    private XACrypto() {}

    static boolean debug = false;
    static String specific = null;

    static int passed = 0;
    static int failed = 0;

    static void log(String msg) {
        if (debug) System.out.println("[DEBUG] " + msg);
    }

    static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            if (debug) System.out.println("  PASS: " + name);
        } else {
            failed++;
            if (debug) System.out.println("  FAIL: " + name);
        }
    }

    static void result() {
        System.out.println(passed + " passed, " + failed + " failed");
        if (failed > 0) System.exit(1);
    }

    public static void main(String[] args) {
        boolean wantTest = false;
        for (String a : args) {
            if (a.equals("--test")) wantTest = true;
            else if (a.equals("--debug")) debug = true;
            else if (a.startsWith("--specifically:")) specific = a.substring("--specifically:".length()).replace("\"", "").trim();
        }
        if (wantTest) runTests();
    }

    static final Map<String, Runnable> TESTS = new LinkedHashMap<>();

    static {
        TESTS.put("SHA256", XACrypto::testSHA256);
        TESTS.put("SHA-256", XACrypto::testSHA256);
        TESTS.put("SHA256-Digest", XACrypto::testSHA256Digest);
        TESTS.put("SHA256-Vector", XACrypto::testSHA256KnownVector);
        TESTS.put("SHA256-Streaming", XACrypto::testDigestStreaming);
        TESTS.put("SHA256-ByteBuffer", XACrypto::testDigestByteBuffer);
        TESTS.put("SHA1", XACrypto::testSHA1);
        TESTS.put("SHA-1", XACrypto::testSHA1);
        TESTS.put("SHA224", XACrypto::testSHA224);
        TESTS.put("SHA-224", XACrypto::testSHA224);
        TESTS.put("SHA384", XACrypto::testSHA384);
        TESTS.put("SHA-384", XACrypto::testSHA384);
        TESTS.put("HMAC", XACrypto::testHMAC);
        TESTS.put("HMAC-SHA256", XACrypto::testHMAC);
        TESTS.put("HKDF", XACrypto::testHKDF);
        TESTS.put("HKDF-SHA256", XACrypto::testHKDF);
        TESTS.put("PBKDF2", XACrypto::testPBKDF2);
        TESTS.put("PBKDF2-SHA256", XACrypto::testPBKDF2);
        TESTS.put("Hex", XACrypto::testHex);
        TESTS.put("ROT", XACrypto::testROTL);
        TESTS.put("ToM", XACrypto::testToM);
        TESTS.put("isNull", XACrypto::testIsNull);
        TESTS.put("AES-GCM", XACrypto::testAesGcm);
        TESTS.put("AESGCM", XACrypto::testAesGcm);
        TESTS.put("SM4-ECB", XACrypto::testSM4Ecb);
        TESTS.put("SM4", XACrypto::testSM4Ecb);
        TESTS.put("SM4-GCM", XACrypto::testSM4Gcm);
        TESTS.put("SM4GCM", XACrypto::testSM4Gcm);
        TESTS.put("Blowfish", XACrypto::testBlowfishEcb);
        TESTS.put("Blowfish-ECB", XACrypto::testBlowfishEcb);
        TESTS.put("Twofish", XACrypto::testTwofishEcb);
        TESTS.put("Twofish-ECB", XACrypto::testTwofishEcb);
        TESTS.put("RC6", XACrypto::testRC6Ecb);
        TESTS.put("RC6-ECB", XACrypto::testRC6Ecb);
        TESTS.put("Aria", XACrypto::testAriaEcb);
        TESTS.put("Aria-ECB", XACrypto::testAriaEcb);
        TESTS.put("ARIA-ECB", XACrypto::testAriaEcb);
        TESTS.put("Merkle", XACrypto::testMerkleTree);
        TESTS.put("MerkleTree", XACrypto::testMerkleTree);
        TESTS.put("GCM", XACrypto::testGCMWrapper);
        TESTS.put("GCM-Wrapper", XACrypto::testGCMWrapper);
        TESTS.put("ARIAGCM", XACrypto::testGCMWrapper);
        TESTS.put("CamelliaGCM", XACrypto::testGCMWrapper);
        TESTS.put("TwofishGCM", XACrypto::testGCMWrapper);
        TESTS.put("SerpentGCM", XACrypto::testGCMWrapper);
    }

    static void runTests() {
        if (specific != null) {
            Runnable test = TESTS.get(specific);
            if (test == null) {
                System.out.println("Unknown algorithm: " + specific);
                System.out.println("Available: " + String.join(", ", new java.util.LinkedHashSet<>(TESTS.keySet())));
                System.exit(1);
                return;
            }
            log("Running test for: " + specific);
            test.run();
        } else {
            log("Running all tests");
            for (Map.Entry<String, Runnable> e : TESTS.entrySet()) {
                if (!TESTS.containsKey(e.getKey())) continue;
                AtomicBoolean alreadyRan = new AtomicBoolean(false);
                String key = e.getKey();
                Runnable r = e.getValue();
                for (Map.Entry<String, Runnable> check : TESTS.entrySet()) {
                    if (check.getValue() == r && !check.getKey().equals(key)) {
                        alreadyRan.set(true);
                        break;
                    }
                }
                if (!alreadyRan.get()) {
                    log("Running: " + key);
                    r.run();
                }
            }
        }
        result();
    }

    static void testSHA256() {
        log("SHA-256 basic digest");
        try {
            byte[] h = Hex.hash("".getBytes());
            check("empty string hash is 32 bytes", h.length == 32);
            byte[] h2 = Hex.hash("abc".getBytes());
            check("'abc' hash is 32 bytes", h2.length == 32);
        } catch (Exception e) { check("SHA-256 basic threw", false); }
    }

    static void testSHA256KnownVector() {
        log("SHA-256 known test vector");
        try {
            byte[] h = Hex.hash("abc".getBytes());
            String hex = Hex.Byte2Hex(h);
            log("hash(abc) = " + hex);
            check("SHA-256('abc') = ba7816bf...", hex.startsWith("ba7816bf"));
            check("SHA-256('abc') full", hex.equals("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
        } catch (Exception e) { check("SHA-256 vector threw", false); }
    }

    static void testSHA256Digest() {
        log("SHA-256 digest streaming");
        try {
            Digest d1 = new Digest();
            d1.upd("a".getBytes());
            d1.upd("bc".getBytes());
            String h1 = Hex.Byte2Hex(d1.digest());
            String h2 = Hex.Byte2Hex(Hex.hash("abc".getBytes()));
            log("streaming=" + h1);
            log("batch   =" + h2);
            check("streaming 'a'+'bc' = batch 'abc'", h1.equals(h2));
        } catch (Exception e) { check("SHA-256 streaming threw", false); }
    }

    static void testDigestStreaming() {
        log("SHA-256 byte-at-a-time streaming");
        try {
            byte[] msg = "Hello, SHA-256 streaming test!".getBytes();
            Digest d = new Digest();
            for (byte b : msg) d.upd(new byte[]{b});
            String streaming = Hex.Byte2Hex(d.digest());
            String batch = Hex.Byte2Hex(Hex.hash(msg));
            log("streaming=" + streaming);
            log("batch   =" + batch);
            check("byte-at-a-time matches batch", streaming.equals(batch));
        } catch (Exception e) { check("byte-at-a-time threw", false); }
    }

    static void testDigestByteBuffer() {
        log("SHA-256 ByteBuffer digest");
        try {
            byte[] msg = "ByteBuffer test".getBytes();
            ByteBuffer bb = ByteBuffer.wrap(msg);
            Digest d = new Digest();
            d.upd(bb);
            String fromBB = Hex.Byte2Hex(d.digest());
            String fromBytes = Hex.Byte2Hex(Hex.hash(msg));
            log("ByteBuffer=" + fromBB);
            log("byte[]   =" + fromBytes);
            check("ByteBuffer input matches byte[] input", fromBB.equals(fromBytes));
        } catch (Exception e) { check("ByteBuffer threw", false); }
    }

    static void testSHA1() {
        log("SHA-1 known test vectors");
        try {
            String h1 = SHA1.hash("");
            log("hash(\"\") = " + h1);
            check("SHA-1('') = da39a3ee...", h1.startsWith("da39a3ee"));
            String h2 = SHA1.hash("abc");
            log("hash(abc) = " + h2);
            check("SHA-1('abc') = a9993e36...", h2.startsWith("a9993e36"));
            String h3 = SHA1.hash("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq");
            log("hash(448-bit) = " + h3);
            check("SHA-1(448-bit) = 84983e44...", h3.startsWith("84983e44"));
        } catch (Exception e) { check("SHA-1 threw", false); }
    }

    static void testSHA224() {
        log("SHA-224 known test vectors");
        try {
            byte[] h1 = SHA224.digest("".getBytes());
            check("SHA-224('') is 28 bytes", h1.length == 28);
            byte[] h2 = SHA224.digest("abc".getBytes());
            check("SHA-224('abc') is 28 bytes", h2.length == 28);
            String hex2 = Hex.Byte2Hex(h2);
            log("hash(abc) = " + hex2);
            check("SHA-224('abc') = 23097d22...", hex2.startsWith("23097d22"));
        } catch (Exception e) { check("SHA-224 threw", false); }
    }

    static void testSHA384() {
        log("SHA-384 basic tests");
        try {
            byte[] h1 = SHA384.digest("".getBytes());
            check("SHA-384('') is 48 bytes", h1.length == 48);
            byte[] h2 = SHA384.digest("abc".getBytes());
            check("SHA-384('abc') is 48 bytes", h2.length == 48);
        } catch (Exception e) { check("SHA-384 threw", false); }
    }

    static void testHMAC() {
        log("HMAC-SHA256 tests");
        try {
            byte[] mac = HMAC.hmac("key".getBytes(), "message".getBytes());
            log("hmac = " + Hex.Byte2Hex(mac));
            check("HMAC is 32 bytes", mac.length == 32);
            byte[] mac2 = HMAC.hmac("key".getBytes(), "message".getBytes());
            check("HMAC is deterministic", Arrays.equals(mac, mac2));
            byte[] mac3 = HMAC.hmac("different_key".getBytes(), "message".getBytes());
            check("Different key gives different MAC", !Arrays.equals(mac, mac3));
            byte[] mac4 = HMAC.hmac("key".getBytes(), "different_message".getBytes());
            check("Different message gives different MAC", !Arrays.equals(mac, mac4));
            byte[] mac5 = HMAC.hmac(new byte[128], "long_key_test".getBytes());
            log("hmac(long key) = " + Hex.Byte2Hex(mac5));
            check("Key > 64 bytes works (hashed)", mac5.length == 32);
        } catch (Exception e) { check("HMAC threw", false); }
    }

    static void testHKDF() {
        log("HKDF-SHA256 tests");
        try {
            byte[] prk = HKDF.extract(null, "ikm".getBytes());
            log("extract(null, ikm) = " + Hex.Byte2Hex(prk));
            check("extract with null salt is 32 bytes", prk.length == 32);
            byte[] okm = HKDF.expand(prk, "info".getBytes(), 64);
            log("expand(prk, info, 64) len=" + okm.length);
            check("expand 64 bytes is 64 bytes", okm.length == 64);
            byte[] okm2 = HKDF.expand(prk, "info".getBytes(), 64);
            check("expand is deterministic", Arrays.equals(okm, okm2));
            byte[] okm3 = HKDF.hkdf("ikm".getBytes(), "salt".getBytes(), "info".getBytes(), 32);
            log("hkdf(ikm, salt, info, 32) = " + Hex.Byte2Hex(okm3));
            check("hkdf shortcut is 32 bytes", okm3.length == 32);
            try {
                HKDF.expand(prk, "info".getBytes(), 255 * 32 + 1);
                check("expand rejects oversized output", false);
            } catch (XACryptoException e) { check("expand rejects oversized output", true); }
        } catch (Exception e) { check("HKDF threw", false); }
    }

    static void testPBKDF2() {
        log("PBKDF2-SHA256 tests");
        try {
            byte[] dk = HKDF.pbkdf2("password".getBytes(), "salt".getBytes(), 1000, 32);
            log("pbkdf2(password, salt, 1000, 32) = " + Hex.Byte2Hex(dk));
            check("PBKDF2 is 32 bytes", dk.length == 32);
            byte[] dk2 = HKDF.pbkdf2("password".getBytes(), "salt".getBytes(), 1000, 32);
            check("PBKDF2 is deterministic", Arrays.equals(dk, dk2));
            byte[] dk3 = HKDF.pbkdf2("password".getBytes(), "salt".getBytes(), 1000, 64);
            check("PBKDF2 64-byte output", dk3.length == 64);
            byte[] dk4 = HKDF.pbkdf2("password".getBytes(), "salt".getBytes(), 2000, 32);
            log("pbkdf2(2000 iters) = " + Hex.Byte2Hex(dk4));
            check("PBKDF2 different iterations differ", !Arrays.equals(dk, dk4));
        } catch (Exception e) { check("PBKDF2 threw", false); }
    }

    static void testHex() {
        log("Hex conversion tests");
        try {
            check("Byte2Hex of {0x00} = '00'", Hex.Byte2Hex(new byte[]{0x00}).equals("00"));
            check("Byte2Hex of {0xFF} = 'ff'", Hex.Byte2Hex(new byte[]{(byte) 0xFF}).equals("ff"));
            check("Byte2Hex of {0xAB, 0xCD} = 'abcd'", Hex.Byte2Hex(new byte[]{(byte) 0xAB, (byte) 0xCD}).equals("abcd"));
            String roundtrip = Hex.Byte2Hex("test".getBytes());
            log("Byte2Hex(\"test\") = " + roundtrip);
            check("Byte2Hex produces output", roundtrip.length() > 0);
            byte[] doubleHashed = Hex.doubleHash("test".getBytes());
            log("doubleHash(\"test\") = " + Hex.Byte2Hex(doubleHashed));
            check("doubleHash is 32 bytes", doubleHashed.length == 32);
        } catch (Exception e) { check("Hex threw", false); }
    }

    static void testROTL() {
        log("ROT rotation tests");
        check("ROTR(x,0) == x", ROT.ROTR(0x12345678, 0) == 0x12345678);
        check("ROTL(x,0) == x", ROT.ROTL(0x12345678, 0) == 0x12345678);
        check("ROTR(x,32) == x", ROT.ROTR(0x12345678, 32) == 0x12345678);
        check("ROTL(1,1) == 2", ROT.ROTL(1, 1) == 2);
        check("ROTR(2,1) == 1", ROT.ROTR(2, 1) == 1);
        check("ROTR64(x,0) == x", ROT.ROTR64(0x123456789ABCDEF0L, 0) == 0x123456789ABCDEF0L);
        check("ROTL32(1,1) == 2", ROT.ROTL32(1L, 1) == 2L);
        check("ROTL32 truncates to 32 bits", (ROT.ROTL32(0x1_00000001L, 4) >>> 32) == 0);
    }

    static void testToM() {
        log("ToM constant-time comparison");
        check("equal arrays", de.caydenno1.xacrypto.misc.ToM.ToM(new byte[]{1, 2, 3}, new byte[]{1, 2, 3}));
        check("different arrays", !de.caydenno1.xacrypto.misc.ToM.ToM(new byte[]{1, 2, 3}, new byte[]{1, 2, 4}));
        check("different lengths", !de.caydenno1.xacrypto.misc.ToM.ToM(new byte[]{1, 2}, new byte[]{1, 2, 3}));
        check("both null", de.caydenno1.xacrypto.misc.ToM.ToM(null, null));
        check("one null", !de.caydenno1.xacrypto.misc.ToM.ToM(null, new byte[]{1}));
        check("empty arrays", de.caydenno1.xacrypto.misc.ToM.ToM(new byte[0], new byte[0]));
    }

    static void testIsNull() {
        log("isNull checks");
        check("null is null", isNull.isNull(null));
        check("not null", !isNull.isNull("hello"));
        check("isValidText(null)", !isNull.isValidText(null));
        check("isValidText(\"\")", !isNull.isValidText(""));
        check("isValidText(\"  \")", !isNull.isValidText("  "));
        check("isValidText(\"hi\")", isNull.isValidText("hi"));
    }

    static void testAesGcm() {
        log("AES-GCM roundtrip + edge cases");
        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] aad = "header".getBytes();
            byte[] plaintext = "Hello AES-GCM!".getBytes();
            log("key=" + Hex.Byte2Hex(key) + " nonce=" + Hex.Byte2Hex(nonce));
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            log("cip=" + Hex.Byte2Hex(enc.cip()) + " tag=" + Hex.Byte2Hex(enc.tag()));
            byte[] dec = aesgcm.decryptBlock(enc.cip(), key, nonce, aad, enc.tag());
            log("dec=" + new String(dec));
            check("16-byte key roundtrip", new String(dec).equals("Hello AES-GCM!"));
        } catch (Exception e) { check("16-byte key roundtrip threw", false); }

        try {
            byte[] key = new byte[32];
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] aad = new byte[0];
            byte[] plaintext = "32-byte key test".getBytes();
            log("32-byte key, empty AAD");
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            byte[] dec = aesgcm.decryptBlock(enc.cip(), key, nonce, aad, enc.tag());
            check("32-byte key + empty AAD", new String(dec).equals("32-byte key test"));
        } catch (Exception e) { check("32-byte key threw", false); }

        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] aad = "header".getBytes();
            byte[] plaintext = "tamper".getBytes();
            log("Testing tampered tag detection");
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            byte[] badTag = enc.tag().clone();
            badTag[0] ^= 0xFF;
            log("modified tag[0] ^= 0xFF");
            aesgcm.decryptBlock(enc.cip(), key, nonce, aad, badTag);
            check("detects tampered tag", false);
        } catch (XACryptoException e) { check("detects tampered tag", true); }
          catch (Exception e) { check("detects tampered tag", true); }

        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] aad = "header".getBytes();
            byte[] plaintext = new byte[100];
            Arrays.fill(plaintext, (byte) 0xAB);
            log("multi-block test: 100 bytes filled with 0xAB");
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            byte[] dec = aesgcm.decryptBlock(enc.cip(), key, nonce, aad, enc.tag());
            check("multi-block 100 bytes", Arrays.equals(dec, plaintext));
        } catch (Exception e) { check("multi-block threw", false); }

        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] plaintext = new byte[0];
            byte[] aad = new byte[0];
            log("empty plaintext test");
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            byte[] dec = aesgcm.decryptBlock(enc.cip(), key, nonce, aad, enc.tag());
            check("empty plaintext roundtrip", dec.length == 0);
        } catch (Exception e) { check("empty plaintext threw", false); }

        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] plaintext = "wrong nonce".getBytes();
            byte[] aad = "header".getBytes();
            log("wrong nonce detection test");
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            byte[] wrongNonce = "0000000000000000".getBytes();
            aesgcm.decryptBlock(enc.cip(), key, wrongNonce, aad, enc.tag());
            check("detects wrong nonce", false);
        } catch (XACryptoException e) { check("detects wrong nonce", true); }
          catch (Exception e) { check("detects wrong nonce", true); }

        try {
            byte[] key = "0123456789abcdef".getBytes();
            byte[] nonce = "abcdef9876543210".getBytes();
            byte[] aad = "header".getBytes();
            byte[] plaintext = "wrong key".getBytes();
            log("wrong key detection test");
            AESGCM aesgcm = new AESGCM();
            Result enc = aesgcm.encryptBlock(plaintext, key, nonce, aad);
            byte[] wrongKey = "fedcba9876543210".getBytes();
            aesgcm.decryptBlock(enc.cip(), wrongKey, nonce, aad, enc.tag());
            check("detects wrong key", false);
        } catch (XACryptoException e) { check("detects wrong key", true); }
          catch (Exception e) { check("detects wrong key", true); }
    }

    static void testSM4Ecb() {
        log("SM4-ECB roundtrip");
        try {
            byte[] key = "0123456789abcde".getBytes();
            byte[] key16 = new byte[16];
            System.arraycopy(key, 0, key16, 0, 15);
            key16[15] = 'f';
            log("key=" + Hex.Byte2Hex(key16));
            SM4ECB sm4 = new SM4ECB(key16);
            byte[] enc = sm4.encrypt("SM4 ECB test!!".getBytes());
            log("enc=" + Hex.Byte2Hex(enc));
            byte[] dec = sm4.decrypt(enc);
            log("dec=" + new String(dec));
            check("SM4-ECB roundtrip", new String(dec).equals("SM4 ECB test!!"));
        } catch (Exception e) { check("SM4-ECB threw", false); }
    }

    static void testSM4Gcm() {
        log("SM4-GCM roundtrip via GCM wrapper");
        try {
            byte[] key = new byte[16];
            byte[] nonce = new byte[12];
            byte[] aad = "aad".getBytes();
            byte[] pln = "SM4-GCM test".getBytes();
            SM4GCM sm4gcm = new SM4GCM(key);
            de.caydenno1.xacrypto.zekerrijndael.GCM.GCM gcm = new de.caydenno1.xacrypto.zekerrijndael.GCM.GCM(sm4gcm);
            Result enc = gcm.encrypt(pln, aad, nonce);
            log("enc=" + Hex.Byte2Hex(enc.cip()) + " tag=" + Hex.Byte2Hex(enc.tag()));
            byte[] dec = gcm.decrypt(enc, aad);
            log("dec=" + new String(dec));
            check("SM4-GCM roundtrip", new String(dec).equals("SM4-GCM test"));
        } catch (Exception e) { check("SM4-GCM threw", false); }
    }

    static void testBlowfishEcb() {
        log("Blowfish-ECB roundtrip (pre-existing issues known)");
        try {
            byte[] key = "blowfish_key_1234567890".getBytes();
            BlowfishECB bf = new BlowfishECB(key);
            byte[] enc = bf.encrypt("Blowfish!".getBytes());
            log("enc=" + Hex.Byte2Hex(enc));
            byte[] dec = bf.decrypt(enc);
            log("dec=" + new String(dec));
            check("Blowfish-ECB roundtrip", new String(dec).equals("Blowfish!"));
        } catch (Exception e) { check("Blowfish-ECB roundtrip (pre-existing fail)", false); }
    }

    static void testTwofishEcb() {
        log("Twofish-ECB roundtrip + padding");
        try {
            byte[] key = new byte[16];
            TwofishECB tf = new TwofishECB(key);
            byte[] enc = tf.encrypt("twofish".getBytes());
            log("enc=" + Hex.Byte2Hex(enc));
            byte[] dec = tf.decrypt(enc);
            log("dec=" + new String(dec));
            check("Twofish-ECB roundtrip", new String(dec).equals("twofish"));
        } catch (Exception e) { check("Twofish-ECB roundtrip threw", false); }

        try {
            byte[] key = new byte[16];
            TwofishECB tf = new TwofishECB(key);
            byte[] enc = tf.encrypt(new byte[48]);
            log("48-byte zeros enc len=" + enc.length);
            byte[] dec = tf.decrypt(enc);
            check("Twofish-ECB all-zeros 48 bytes", dec.length == 48);
        } catch (Exception e) { check("Twofish-ECB 48-byte threw", false); }

        try {
            byte[] key = new byte[16];
            TwofishECB tf = new TwofishECB(key);
            byte[] badCip = new byte[32];
            badCip[31] = (byte) 0x10;
            log("bad padding test: cip[31]=0x10");
            tf.decrypt(badCip);
            check("rejects bad padding", false);
        } catch (XACryptoException e) { check("rejects bad padding", true); }
          catch (Exception e) { check("rejects bad padding", true); }
    }

    static void testRC6Ecb() {
        log("RC6-ECB roundtrip (pre-existing issues known)");
        try {
            byte[] key = new byte[16];
            RC6ECB rc6 = new RC6ECB(key);
            byte[] enc = rc6.encrypt("RC6 test data!".getBytes());
            log("enc=" + Hex.Byte2Hex(enc));
            byte[] dec = rc6.decrypt(enc);
            log("dec=" + new String(dec));
            check("RC6-ECB roundtrip", new String(dec).equals("RC6 test data!"));
        } catch (Exception e) { check("RC6-ECB roundtrip (pre-existing fail)", false); }
    }

    static void testAriaEcb() {
        log("ARIA-ECB roundtrip (pre-existing issues known)");
        try {
            byte[] key = new byte[16];
            AriaECB aria = new AriaECB(key);
            byte[] enc = aria.encrypt("ARIA ECB test".getBytes());
            log("enc=" + Hex.Byte2Hex(enc));
            byte[] dec = aria.decrypt(enc);
            log("dec=" + new String(dec));
            check("ARIA-ECB roundtrip", new String(dec).equals("ARIA ECB test"));
        } catch (Exception e) { check("ARIA-ECB roundtrip (pre-existing fail)", false); }
    }

    static void testMerkleTree() {
        log("Merkle tree various sizes");
        try {
            List<byte[]> leaves = new ArrayList<>();
            for (int i = 0; i < 8; i++) leaves.add(("leaf" + i).getBytes());
            byte[] root = SHA256.merkRoot(leaves);
            log("merkRoot(8 leaves) = " + Hex.Byte2Hex(root));
            check("merkRoot 8 leaves, length=32", root.length == 32);
        } catch (Exception e) { check("merkRoot threw", false); }

        try {
            List<byte[]> leaves = new ArrayList<>();
            leaves.add("single".getBytes());
            byte[] root = SHA256.merkRoot(leaves);
            log("merkRoot(1 leaf) = " + Hex.Byte2Hex(root));
            check("merkRoot 1 leaf, length=32", root.length == 32);
        } catch (Exception e) { check("merkRoot 1 leaf threw", false); }

        try {
            List<byte[]> leaves = new ArrayList<>();
            for (int i = 0; i < 4; i++) leaves.add(("duo" + i).getBytes());
            byte[] root = SHA256.merkRootDuo(leaves);
            log("merkRootDuo(4 leaves) = " + Hex.Byte2Hex(root));
            check("merkRootDuo 4 leaves, length=32", root.length == 32);
        } catch (Exception e) { check("merkRootDuo threw", false); }

        try {
            List<byte[]> leaves = new ArrayList<>();
            for (int i = 0; i < 17; i++) leaves.add(("odd" + i).getBytes());
            byte[] root = SHA256.merkRoot(leaves);
            log("merkRoot(17 leaves) = " + Hex.Byte2Hex(root));
            check("merkRoot 17 leaves (odd), length=32", root.length == 32);
        } catch (Exception e) { check("merkRoot 17 leaves threw", false); }

        try {
            List<byte[]> leaves = new ArrayList<>();
            for (int i = 0; i < 64; i++) leaves.add(("leaf" + i).getBytes());
            byte[] root = SHA256.merkRoot(leaves);
            log("merkRoot(64 leaves) = " + Hex.Byte2Hex(root));
            check("merkRoot 64 leaves, length=32", root.length == 32);
        } catch (Exception e) { check("merkRoot 64 leaves threw", false); }

        try {
            SHA256.merkRoot(new ArrayList<>());
            check("merkRoot empty list throws", false);
        } catch (XACryptoException e) { check("merkRoot empty list throws", true); }
          catch (Exception e) { check("merkRoot empty list throws", true); }
    }

    static void testGCMWrapper() {
        log("GCM wrapper roundtrips");
        try {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            byte[] aad = "header".getBytes();
            byte[] pln = "GCM wrapper test".getBytes();
            ARIAGCM aria = new ARIAGCM(key);
            Result enc = aria.encrypt(pln, aad, iv);
            log("ARIAGCM enc=" + Hex.Byte2Hex(enc.cip()) + " tag=" + Hex.Byte2Hex(enc.tag()));
            byte[] dec = aria.decrypt(enc, aad);
            log("ARIAGCM dec=" + new String(dec));
            check("ARIAGCM roundtrip", new String(dec).equals("GCM wrapper test"));
        } catch (Exception e) { check("ARIAGCM threw", false); }

        try {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            byte[] aad = "header".getBytes();
            byte[] pln = "CamelliaGCM".getBytes();
            CamelliaGCM cam = new CamelliaGCM(key);
            Result enc = cam.encrypt(pln, aad, iv);
            log("CamelliaGCM enc=" + Hex.Byte2Hex(enc.cip()));
            byte[] dec = cam.decrypt(enc, aad);
            check("CamelliaGCM roundtrip", new String(dec).equals("CamelliaGCM"));
        } catch (Exception e) { check("CamelliaGCM threw", false); }

        try {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            byte[] aad = "header".getBytes();
            byte[] pln = "TwofishGCM".getBytes();
            TwofishGCM tf = new TwofishGCM(key);
            Result enc = tf.encrypt(pln, aad, iv);
            log("TwofishGCM enc=" + Hex.Byte2Hex(enc.cip()));
            byte[] dec = tf.decrypt(enc, aad);
            check("TwofishGCM roundtrip", new String(dec).equals("TwofishGCM"));
        } catch (Exception e) { check("TwofishGCM threw", false); }

        try {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            byte[] aad = "header".getBytes();
            byte[] pln = "SerpentGCM".getBytes();
            SerpentGCM sp = new SerpentGCM(key);
            Result enc = sp.encrypt(pln, aad, iv);
            log("SerpentGCM enc=" + Hex.Byte2Hex(enc.cip()));
            byte[] dec = sp.decrypt(enc, aad);
            check("SerpentGCM roundtrip", new String(dec).equals("SerpentGCM"));
        } catch (Exception e) { check("SerpentGCM threw", false); }

        try {
            byte[] key = new byte[16];
            byte[] iv = new byte[12];
            byte[] aad = "header".getBytes();
            byte[] pln = "ARIAGCM tamper".getBytes();
            ARIAGCM aria = new ARIAGCM(key);
            Result enc = aria.encrypt(pln, aad, iv);
            byte[] badTag = enc.tag().clone();
            badTag[0] ^= 0xFF;
            log("ARIAGCM tamper test: modified tag[0]");
            aria.decrypt(new Result(enc.cip(), badTag), aad);
            check("ARIAGCM detects tampered tag", false);
        } catch (XACryptoException e) { check("ARIAGCM detects tampered tag", true); }
          catch (Exception e) { check("ARIAGCM detects tampered tag", true); }
    }
}
