package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;
import org.junit.Before;

public class ECDHCipherTests
{
	protected byte[] testInput;
	protected KDFMeta testKDFParams;
	protected ECDHCipherContext ctx;

	@Before
    public void setUp() throws UnsupportedEncodingException
    {
    	//Generate a context from only device info and an identifier
    	testInput = "hello world".getBytes("UTF8");
		testKDFParams = KDFMeta.fromComponents(KDFAlgo.hkdfSha512(), "salt".getBytes("UTF8"),"wickr".getBytes("UTF8"));
		ctx = ECDHCipherContext.gen(ECCurve.p521(), Cipher.aes256Gcm());
		assertNotNull(ctx);
		assertNotNull(testKDFParams);
    }

    @Test
    public void testContextGeneration()
    {
        ECDHCipherContext rndCipherCtx = ECDHCipherContext.gen(ECCurve.p521(), Cipher.aes256Gcm());
        assertNotNull(rndCipherCtx);
        assertFalse(Arrays.equals(rndCipherCtx.getLocalKey().getPubData(), ctx.getLocalKey().getPubData()));

		ECDHCipherContext anotherCipherCtx = ECDHCipherContext.fromComponents(rndCipherCtx.getLocalKey(), Cipher.aes256Gcm());
        assertNotNull(anotherCipherCtx);
		assertArrayEquals(rndCipherCtx.getLocalKey().getPubData(),anotherCipherCtx.getLocalKey().getPubData());
    }

    @Test
    public void testContextCipher() throws UnsupportedEncodingException
    {
        //Encrypt the test data with the public key 'remoteKey'
		ECKey remoteKey = CryptoEngine.randEcKey(ECCurve.p521());
		assertNotNull(remoteKey);
		CipherResult ciphertext = ctx.encrypt(testInput, remoteKey, testKDFParams);
		assertNotNull(ciphertext);

		//Do a decode using the proper key and validate the result matches the original input
		ECDHCipherContext decodeCtx = ECDHCipherContext.fromComponents(remoteKey, Cipher.aes256Gcm()); 
		assertNotNull(decodeCtx);
		byte[] decoded = decodeCtx.decrypt(ciphertext, ctx.getLocalKey(), testKDFParams);
		assertArrayEquals(decoded, testInput);

		//Test that supplying the incorrect sender public key leads to a null result
		ECKey incorrectKey = CryptoEngine.randEcKey(ECCurve.p521());
		assertNotNull(incorrectKey);
		decoded = decodeCtx.decrypt(ciphertext, incorrectKey, testKDFParams);
		assertNull(decoded);

		//Test that supplying the incorrect local private key leads to a null result
		ECDHCipherContext decodeCtxWrongKey = ECDHCipherContext.fromComponents(incorrectKey, Cipher.aes256Gcm());
		assertNotNull(decodeCtxWrongKey);
		decoded = decodeCtxWrongKey.decrypt(ciphertext,ctx.getLocalKey(),testKDFParams);
		assertNull(decoded);

		//Test that supplying the incorrect kdf meta leads to a null result
		KDFMeta incorrectKDFParams = KDFMeta.fromComponents(KDFAlgo.hkdfSha512(),"salt".getBytes("UTF8"), "notwickr".getBytes("UTF8"));
		assertNotNull(incorrectKDFParams);
		decoded = decodeCtx.decrypt(ciphertext, ctx.getLocalKey(), incorrectKDFParams);
		assertNull(decoded);
    }
}