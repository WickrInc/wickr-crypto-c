package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;
import java.math.BigInteger;

public class NodeTests
{
	@Test
	public void testNode() throws UnsupportedEncodingException
	{

		//Create a node from an identity chain, and a device identifier
		byte[] identifier = CryptoEngine.digest("wickr".getBytes("UTF8"), null, Digest.sha256());
		ECKey sigKey = CryptoEngine.randEcKey(ECCurve.p521());
		Identity testIdentity = Identity.fromValues(IdentityType.IDENTITY_TYPE_ROOT, identifier, sigKey, null);
		assertNotNull(testIdentity);

		Identity testNodeIdentity = testIdentity.genNode();
		assertNotNull(testNodeIdentity);

		IdentityChain testIdentityChain = IdentityChain.fromIdentities(testIdentity, testNodeIdentity);

		assertNotNull(testIdentityChain);

		ECKey ephemeralKey = CryptoEngine.randEcKey(ECCurve.p521());
		EphemeralKeypair keypair = EphemeralKeypair.fromValues(new BigInteger("1"), ephemeralKey, testNodeIdentity.signData(ephemeralKey.getPubData()));
		assertNotNull(keypair);

		Node testNode = Node.fromValues("testdevid".getBytes("UTF8"), testIdentityChain, keypair);

		assertNotNull(testNode);

		assertEquals(testNode.verify(), true);
	}
	
}