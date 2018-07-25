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
	protected ECKey sigKey;
	protected Identity testIdentity;
	
	@Before
    public void setUp() throws UnsupportedEncodingException
    {
        this.identifier = CryptoEngine.digest("wickr".getBytes("UTF8"), null, Digest.sha256());
        this.sigKey = CryptoEngine.randEcKey(ECCurve.p521());
        this.testIdentity = Identity.fromValues(IdentityType.IDENTITY_TYPE_ROOT, identifier, sigKey, null);
    }

    public Identity generateTestNode() {

    	Identity testNode = testIdentity.genNode();

		assertNotNull(testNode);
		assertEquals(testNode.getType(), IdentityType.IDENTITY_TYPE_NODE);
		assertNotNull(testNode.getSignature());

		return testNode;
    }

    @Test
	public void testIdentity() throws UnsupportedEncodingException
	{
		
		assertNotNull(testIdentity);
		assertArrayEquals(testIdentity.getIdentifier(), this.identifier);

		//Generate a random node identity that is signed by testIdentity
		Identity testNode = generateTestNode();

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

	@Test
	public void testSerialization() {

		// Serialize and deserialize an identity
		byte[] serialized = testIdentity.serialize();
		assertNotNull(serialized);
		assertTrue(serialized.length > 0);

		Identity restored = Identity.fromBuffer(serialized);
		assertNotNull(restored);

		//Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
		assertArrayEquals(restored.getIdentifier(), testIdentity.getIdentifier());
	}

	@Test
	public void testChainSerialization() {

		// Serialize and deserialize an identity chain
		Identity testNode = generateTestNode();
		IdentityChain testChain = IdentityChain.fromIdentities(testIdentity, testNode);
		assertNotNull(testChain);

		byte[] serialized = testChain.serialize();
		assertNotNull(serialized);
		assertTrue(serialized.length > 0);

		IdentityChain restored = IdentityChain.fromBuffer(serialized);
		assertNotNull(restored);

		//Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
		assertArrayEquals(restored.getRoot().getIdentifier(), testChain.getRoot().getIdentifier());
		assertArrayEquals(restored.getNode().getIdentifier(), testChain.getNode().getIdentifier());
	}

}