package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;

public class CryptoTests {

    @Test
    public void testRandomDataGeneration() {
        
        byte[] testData = CryptoEngine.randomBytes(32);
		assertEquals("test data should not be empty",testData.length, 32);

		for (int i=0; i < 1000 ; i++) { 
			byte[] testNewData = CryptoEngine.randomBytes(32);
			assertFalse(Arrays.equals(testNewData, testData));
		}
        
    }

    @Test 
    public void testCipherDecipher() throws UnsupportedEncodingException
	{
		byte[] rndData = CryptoEngine.randomBytes(32);
		CipherKey key = CipherKey.fromComponents(Cipher.aes256Gcm(), rndData);
		assertNotNull(key);

		assertArrayEquals(key.getKeyData(), rndData);

		key = CryptoEngine.randomKey(Cipher.aes256Gcm());
		assertNotNull(key);

		byte[] testValue = "hello world".getBytes("UTF8");

		//Perform AES Cipher, NULL param means generate random IV
		CipherResult ciphered = CryptoEngine.cipher(testValue, null, key, null);

		assertNotNull(ciphered);
		//Keys are objects, you need to serialize them to bytes to store in db, send over network etc
		byte[] serializedKey = key.serialize();

		assertNotNull(serializedKey);

		//Cipher results are objects, you need to serialize them to bytes to store in db, send over network etc
		byte[] serializedCipherResult = ciphered.serialize();

		assertNotNull(serializedCipherResult);

		//To import a serialized key / cipher result into an object the from buffer method is used
		CipherKey deserializedKey = CipherKey.fromBuffer(serializedKey);

		assertNotNull(deserializedKey);

		CipherResult deserializedCipherResult = CipherResult.fromBuffer(serializedCipherResult);

		assertNotNull(deserializedCipherResult);

		// The decipher method returns the deciphered data directly
		byte[] deciphered = CryptoEngine.decipher(deserializedCipherResult, null, deserializedKey,true); //True means force GCM, do not accept CTR
		assertNotNull(deciphered);

		assertArrayEquals(deciphered, testValue);

	}

	@Test
	public void testSignatures() throws UnsupportedEncodingException {
		// Generate a random EC Key
		ECKey testECKey = CryptoEngine.randEcKey(ECCurve.p521());

		assertNotNull(testECKey);

		byte[] testPrivateKeyData = testECKey.getPriData();
		byte[] testPubKeyData = testECKey.getPubData();

		// Import a buffer into an EC Key object (true means private, false means public)
		ECKey restoreTestKeyPrivate = CryptoEngine.importEcKey(testPrivateKeyData, true);
		ECKey restoreTestKeyPublic = CryptoEngine.importEcKey(testPubKeyData, false);

		assertNotNull(restoreTestKeyPrivate);
		assertNotNull(restoreTestKeyPublic);

		byte[] testData = "HelloWorld".getBytes("UTF8");

		// Generate a signature using a private ec key, data, and a hashing method
		ECDSAResult testSignature = CryptoEngine.ecSign(restoreTestKeyPrivate, testData, Digest.sha512());
 		
 		assertNotNull(testSignature);

		// The test signature is an object, so we must serialize it into bytes for storage and network
		byte[] testSignatureData = testSignature.serialize();

		assertNotNull(testSignatureData);

		// Create a signature result from a buffer generated by serialize
		ECDSAResult testSignatureRestore = ECDSAResult.createFromBuffer(testSignatureData);

		assertNotNull(testSignatureRestore);

		// Verify a signature where testData is the expected data, restoreTestKeyPublic is the public key
		// and testSignatureRestore is a signature object
		boolean isValid = CryptoEngine.ecVerify(testSignatureRestore, restoreTestKeyPublic, testData);

		assertTrue(isValid);

		ECKey anotherECKey = CryptoEngine.randEcKey(ECCurve.p521());

		assertNotNull(anotherECKey);

		isValid = CryptoEngine.ecVerify(testSignatureRestore, anotherECKey, testData);

		assertFalse(isValid);
	}

    @Test
    public void testRawSignature() throws UnsupportedEncodingException {
		// Generate a random EC Key
		ECKey testECKey = CryptoEngine.randEcKey(ECCurve.p521());

        byte[] testData = "HelloWorld".getBytes("UTF8");

		// Generate a signature using a private ec key, data, and a hashing method
		ECDSAResult testSignature = CryptoEngine.ecSign(testECKey, testData, Digest.sha512());

        // Copy the raw signature data
        byte[] rawSignatureData = CryptoEngine.ecdsaToRaw(testSignature);
        assertNotNull(rawSignatureData);

        assertFalse(rawSignatureData.length == testSignature.serialize().length);

        // Import the signature data and validate the signature
        ECDSAResult received = CryptoEngine.ecdsaFromRaw(ECCurve.p521(), Digest.sha512(), rawSignatureData);

        boolean isValid = CryptoEngine.ecVerify(received, testECKey, testData);
		assertTrue(isValid);

        // Validate that checking a signature with the wrong key properly fails
        ECKey anotherECKey = CryptoEngine.randEcKey(ECCurve.p521());

		isValid = CryptoEngine.ecVerify(received, anotherECKey, testData);
		assertFalse(isValid);
    }

	@Test
	public void testHashing() throws UnsupportedEncodingException
	{
		byte[] hello = "Hello".getBytes("UTF8");
		byte[] world = "World".getBytes("UTF8");
		byte[] helloWorld = "HelloWorld".getBytes("UTF8");

		// Generate a hash
		byte[] hash256Salt = CryptoEngine.digest(hello, world, Digest.sha256());
		byte[] hash256NoSalt = CryptoEngine.digest(helloWorld, null, Digest.sha256());

		assertNotNull(hash256Salt);
		assertNotNull(hash256NoSalt);

		assertArrayEquals(hash256Salt, hash256NoSalt);

		String hash256SaltHex = bytesToHex(hash256Salt);

		assertEquals(hash256SaltHex, "872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4");
	}

	@Test
	public void testECDH()
	{
		ECKey theirKey = CryptoEngine.randEcKey(ECCurve.p521());
		ECKey ourKey = CryptoEngine.randEcKey(ECCurve.p521());

		assertNotNull(ourKey);
		assertNotNull(theirKey);

		byte[] outputSecret = CryptoEngine.ecdhGenSharedSecret(ourKey, theirKey);
		assertNotNull(outputSecret);

		ourKey = CryptoEngine.randEcKey(ECCurve.p521());
		assertNotNull(ourKey);

		byte[] outputSecret2 = CryptoEngine.ecdhGenSharedSecret(ourKey, theirKey);
		assertNotNull(outputSecret2);

		assertThat(outputSecret, not(equalTo(outputSecret2)));
	}

	@Test
	public void testKDF() throws UnsupportedEncodingException
	{
		byte[] passphrase = "password".getBytes("UTF8");
		byte[] testValue = "HelloWorld".getBytes("UTF8");

		byte[] scrypt = CryptoEngine.kdf(KDFAlgo.scrypt17(), passphrase);
		assertNotNull(scrypt);

		byte[] bcrypt = CryptoEngine.kdf(KDFAlgo.bcrypt15(), passphrase);
		assertNotNull(bcrypt);

		assertThat(scrypt, not(equalTo(bcrypt)));

		byte[] ciphered = CryptoEngine.kdfEncrypt(KDFAlgo.scrypt17(), Cipher.aes256Gcm(), testValue, passphrase);
		assertNotNull(ciphered);

		byte[] decipheredInvalidPass = CryptoEngine.kdfDecrypt(ciphered, "invalid password".getBytes("UTF8"));
		assertNull(decipheredInvalidPass);

		byte[] deciphered = CryptoEngine.kdfDecrypt(ciphered, passphrase);
		assertArrayEquals(deciphered, testValue);
	}

	@Test
	public void testKdfCustom() throws UnsupportedEncodingException
	{
		byte[] passphrase = "password".getBytes("UTF8");

        KDFResult kdf = CryptoEngine.kdfFull(KDFAlgo.scrypt17(), passphrase, 64);
        assertNotNull(kdf);
		assertEquals(kdf.getHash().length, 64);

        byte[] kdf2 = CryptoEngine.kdfSaltFull(kdf.getMeta(), passphrase, 64);
		assertArrayEquals(kdf2, kdf.getHash());
	}

	private final static char[] hexArray = "0123456789abcdef".toCharArray();
	
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

    static {
	    try {
	    	System.loadLibrary("WickrCrypto");
	    } catch (UnsatisfiedLinkError e) {
	      System.err.println("Native code library failed to load.\n" + e);
	      System.exit(1);
	    }
  	}
}
