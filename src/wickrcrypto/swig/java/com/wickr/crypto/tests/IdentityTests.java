package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import org.junit.Before;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;

public class IdentityTests
{
	protected byte[] identifier;
	
	@Before
    public void setUp() throws UnsupportedEncodingException
    {
        this.identifier = CryptoEngine.digest("wickr".getBytes("UTF8"), null, Digest.sha256());
    }

    @Test
	public void testIdentity() throws UnsupportedEncodingException
	{
		ECKey sigKey = CryptoEngine.randEcKey(ECCurve.p521());

		//Create an identity from an identifier and a key
		Identity testIdentity = Identity.fromValues(IdentityType.IDENTITY_TYPE_ROOT, identifier, sigKey, null);

		assertNotNull(testIdentity);

		//Generate a random node identity that is signed by testIdentity
		Identity testNode = testIdentity.genNode();

		assertNotNull(testNode);
		assertEquals(testNode.getType(), IdentityType.IDENTITY_TYPE_NODE);
		assertNotNull(testNode.getSignature());

		byte[] testSignatureData = "testdata".getBytes("UTF8");

		//Sign data using this node's signing key
		ECDSAResult testSignature = testNode.signData(testSignatureData);

		assertEquals(CryptoEngine.ecVerify(testSignature, testNode.getSigKey(), testSignatureData), true);

		//Create an identity chain from a root and node identity
		IdentityChain testChain = IdentityChain.fromIdentities(testIdentity, testNode);
		assertNotNull(testChain);

		//Validate the integrity of the chain by checking signing keys
		assertEquals(testChain.isValid(), true);

		sigKey = CryptoEngine.randEcKey(ECCurve.p521());
		testIdentity = Identity.fromValues(IdentityType.IDENTITY_TYPE_ROOT, identifier, sigKey, null);

		testChain = IdentityChain.fromIdentities(testIdentity, testNode);
		assertEquals(testChain.isValid(), false);
	}

}