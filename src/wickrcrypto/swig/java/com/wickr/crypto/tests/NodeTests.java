package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import org.junit.Before;
import java.io.*;
import java.util.*;
import java.math.BigInteger;

public class NodeTests
{
	protected IdentityChain testIdentityChain;
	protected EphemeralKeypair testEphemeralKey;
	protected Node testNode;

	@Before
    public void setUp() throws UnsupportedEncodingException
    {
    	//Create a node from an identity chain, and a device identifier
		byte[] identifier = CryptoEngine.digest("wickr".getBytes("UTF8"), null, Digest.sha256());
		ECKey sigKey = CryptoEngine.randEcKey(ECCurve.p521());
		Identity testIdentity = Identity.fromValues(IdentityType.IDENTITY_TYPE_ROOT, identifier, sigKey, null);
		assertNotNull(testIdentity);

		Identity testNodeIdentity = testIdentity.genNode(null);
		assertNotNull(testNodeIdentity);

		this.testIdentityChain = IdentityChain.fromIdentities(testIdentity, testNodeIdentity);
        assertNotNull(testIdentityChain);

        ECKey ephemeralKey = CryptoEngine.randEcKey(ECCurve.p521());
		this.testEphemeralKey = EphemeralKeypair.fromValues(new BigInteger("1"), ephemeralKey, testNodeIdentity.signData(ephemeralKey.getPubData()));
		assertNotNull(testEphemeralKey);

		this.testNode = Node.fromValues("testdevid".getBytes("UTF8"), testIdentityChain, testEphemeralKey);
    }

	@Test
	public void testNode() throws UnsupportedEncodingException
	{
		assertNotNull(testNode);
		assertEquals(testNode.verify(), true);
	}

	@Test
	public void testSerilization()
	{
		byte[] serialized = testNode.serialize();
        assertNotNull(serialized);

        Node restoredNode = Node.fromBuffer(serialized);
        assertNotNull(restoredNode);

        // Check a couple values to ensure the call worked (more tests in wickr-crypto-c)
        assertEquals(restoredNode.getEphemeralKeypair().getIdentifier(), testEphemeralKey.getIdentifier());
        assertArrayEquals(restoredNode.getIdChain().getRoot().getIdentifier(), testNode.getIdChain().getRoot().getIdentifier());
	}
	
}