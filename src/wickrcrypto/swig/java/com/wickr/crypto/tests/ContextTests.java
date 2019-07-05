package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;
import org.junit.Before;
import java.math.BigInteger;

public class ContextTests
{
	protected DeviceInfo devinfo;
	protected byte[] identifier;
	protected Context ctx;

	@Before
    public void setUp() throws UnsupportedEncodingException
    {
    	//Generate a context from only device info and an identifier
    	devinfo = DeviceInfo.gen("sysid".getBytes("UTF8"));
        identifier = CryptoEngine.digest("wickr".getBytes("UTF8"), null, Digest.sha256());
        ContextGenResult testGeneration = ContextGenResult.genNew(devinfo, identifier);
		assertNotNull(testGeneration);
		ctx = testGeneration.getCtx();
		assertNotNull(ctx);
    }

    @Test
    public void testContextFromValues() {
		Context testFromValues = Context.fromValues(ctx.getDevInfo(), ctx.getIdChain(), ctx.getStorageKeys());
    	assertNotNull(testFromValues);
	}

    @Test
	public void testContextGeneration() throws UnsupportedEncodingException
	{

		ECKey existingSigKey = CryptoEngine.randEcKey(ECCurve.p521());

		//Generate a context from an existing signing key, device info, and an identifier
		ContextGenResult testGenerationSig = ContextGenResult.genNewWithSigKey(devinfo, existingSigKey, identifier);
		assertNotNull(testGenerationSig);
		assertArrayEquals(testGenerationSig.getCtx().getIdChain().getRoot().getSigKey().getPubData(), existingSigKey.getPubData());

		RootKeys testKeys = RootKeys.gen();

		//Generate a context from existing root keys, device info, and an identifier
		ContextGenResult testGenerationRootKeys = ContextGenResult.genWithRootKeys(devinfo, testKeys, identifier);
		assertNotNull(testGenerationRootKeys);

		assertArrayEquals(testKeys.getNodeStorageRoot().getKeyData(), testGenerationRootKeys.getRootKeys().getNodeStorageRoot().getKeyData());
		assertArrayEquals(testKeys.getRemoteStorageRoot().getKeyData(), testGenerationRootKeys.getRootKeys().getRemoteStorageRoot().getKeyData());
		assertArrayEquals(testKeys.getNodeSignatureRoot().getPubData(), testGenerationRootKeys.getRootKeys().getNodeSignatureRoot().getPubData());

		//Create recovery data so the context can be regenerated with a recovery key
		byte[] recoveryData = testGenerationRootKeys.makeRecovery();
		assertNotNull(recoveryData);

		//Export the recovery key of a context with a passphrase
		byte[] exportedRecoveryKey = testGenerationRootKeys.exportRecoveryKeyPassphrase("password".getBytes("UTF8"));
		assertNotNull(exportedRecoveryKey);

		assertNull(ContextGenResult.importRecoveryKeyPassphrase(exportedRecoveryKey, "password2".getBytes("UTF8")));

		//Import a recovery key with a passphrase
		CipherKey importedRecoveryKey = ContextGenResult.importRecoveryKeyPassphrase(exportedRecoveryKey, "password".getBytes("UTF8"));
		assertNotNull(importedRecoveryKey);

		assertArrayEquals(importedRecoveryKey.getKeyData(), testGenerationRootKeys.getRecoveryKey().getKeyData());

		//Regenerate a context with a recovery key, recovery information, device info, and an identifier
		ContextGenResult testRecoveryGeneration = ContextGenResult.genWithRecovery(devinfo, recoveryData, importedRecoveryKey, identifier);

		assertNotNull(testRecoveryGeneration);

		assertNull(ContextGenResult.genWithPassphrase(devinfo, exportedRecoveryKey, "password2".getBytes("UTF8"), recoveryData, identifier));

		//Regenerate a context with a passphrase, exported recovery key, device info, an identifier, and recovery data
		ContextGenResult testPassphraseGeneration = ContextGenResult.genWithPassphrase(devinfo, exportedRecoveryKey, "password".getBytes("UTF8"), recoveryData, identifier);

		assertNotNull(testPassphraseGeneration);
	}

	@Test
	public void testContextCipherOps() throws UnsupportedEncodingException
	{
		byte[] testData = "test".getBytes("UTF8");

		//Cipher local data using the context
		CipherResult ciphered = ctx.cipherLocal(testData);
		assertNotNull(ciphered);

		//Decipher local data using the context
		byte[] deciphered = ctx.decipherLocal(ciphered);
		assertArrayEquals(testData, deciphered);

		//Cipher remote data using the context
		ciphered = ctx.cipherRemote(testData);
		assertNotNull(ciphered);

		//Decipher remote data using the context
		deciphered = ctx.decipherRemote(ciphered);
		assertArrayEquals(testData, deciphered);
	}

	@Test
	public void testContextGenKeys() throws UnsupportedEncodingException
	{
		//Generate ephemeral keypairs to distribute for message sending
		EphemeralKeypair testKey1 = ctx.ephemeralKeypairGen(new BigInteger("1"));
		assertNotNull(testKey1);
		assertEquals(testKey1.getIdentifier().toString(), "1");

		EphemeralKeypair testKey2 = ctx.ephemeralKeypairGen(new BigInteger("2"));
		assertNotNull(testKey2);
		assertEquals(testKey2.getIdentifier().toString(), "2");
		assertNotEquals(testKey1.getEcKey().getPubData(), testKey2.getEcKey().getPubData());
		assertNotEquals(testKey1.getEcKey().getPriData(), testKey2.getEcKey().getPriData());

		//Erase the public key of the ephemeral keypair
		testKey1.makePublic();
		assertNull(testKey1.getEcKey().getPriData());

	}

	@Test
	public void testStorageKeys() throws UnsupportedEncodingException
	 {
		//Export a storage key with a passphrase
		byte[] exported = ctx.exportStorageKeys("password".getBytes("UTF8"));
		assertNotNull(exported);

		//Import a storage key with a passphrase
		assertNull(ctx.importStorage(exported, "password2".getBytes("UTF8")));
		StorageKeys imported = ctx.importStorage(exported, "password".getBytes("UTF8"));
		assertNotNull(imported);
	}

	@Test
	public void testGenerateMessages() throws UnsupportedEncodingException
	{

		//Generate a context to 'send' messages to
		DeviceInfo devinfo = DeviceInfo.gen("sysid2".getBytes("UTF8"));
        byte[] identifier = CryptoEngine.digest("wickr2".getBytes("UTF8"), null, Digest.sha256());
        ContextGenResult testGeneration = ContextGenResult.genNew(devinfo, identifier);
		assertNotNull(testGeneration);

		Context receiverCtx = testGeneration.getCtx();
		assertNotNull(ctx);

		EphemeralKeypair msgKey = receiverCtx.ephemeralKeypairGen(new BigInteger("1"));
		assertNotNull(msgKey);

		Node receiverNode = Node.fromValues(devinfo.getMsgProtoId(), receiverCtx.getIdChain(), msgKey);
		assertNotNull(receiverNode);

		byte[] message = "Wickr".getBytes("UTF8");
		int messageType = 1000;
		byte[] channel = "12345".getBytes("UTF8");
		EphemeralInfo ephemerality = EphemeralInfo.fromValues(new BigInteger("86400"), new BigInteger("500"));

		//Create metadata for this message
		PacketMeta meta = PacketMeta.fromValues(ephemerality, channel, messageType);
		assertNotNull(meta);

		//Construct a payload with a message body and metadata
		Payload payload = Payload.fromValues(meta, message);
		assertNotNull(payload);

		WickrArray nodes = WickrArray.allocateNode(1);
		nodes.setNode(0, receiverNode);

		//Encode the message for a set of node receivers
		EncoderResult encodeResult = ctx.encodePacket(payload, nodes);
		assertNotNull(encodeResult);

		//Use the receiver context created above to parse a packet for non decoding purposes
		ContextParseResult parsed = receiverCtx.parsePacketNoDecode(encodeResult.getPacket().serialize(), ctx.getIdChain());
		assertNotNull(parsed);
		assertEquals(parsed.getParseResult().getErr(), DecodeError.E_SUCCESS);
		assertEquals(parsed.getParseResult().getSignatureStatus(), PacketSignatureStatus.PACKET_SIGNATURE_VALID);

		//Use the receiver context created above to parse a packet for decoding purposes
		parsed = receiverCtx.parsePacket(encodeResult.getPacket().serialize(), ctx.getIdChain());
		assertNotNull(parsed);
		assertEquals(parsed.getParseResult().getErr(), DecodeError.E_SUCCESS);
		assertEquals(parsed.getParseResult().getSignatureStatus(), PacketSignatureStatus.PACKET_SIGNATURE_VALID);

		//Decode the packet, and extract the original message
		ContextDecodeResult decoded = receiverCtx.decodePacket(parsed, msgKey.getEcKey());
		assertNotNull(decoded);
		assertEquals(decoded.getErr(), DecodeError.E_SUCCESS);
		assertArrayEquals(decoded.getDecryptedPayload().getBody(), message);
	}

	@Test
	public void testContextSerialization() {

		//Serialize and deserialize the context
		byte[] serializedContext = ctx.serialize();
		assertNotNull(serializedContext);
		assertTrue(serializedContext.length > 0);

		Context restoredContext = Context.fromBuffer(devinfo, serializedContext);
		assertNotNull(restoredContext);

		//Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
		assertArrayEquals(restoredContext.getDevInfo().getMsgProtoId(), devinfo.getMsgProtoId());
		assertArrayEquals(restoredContext.getIdChain().getRoot().getIdentifier(), identifier);

	}

	@Test
	public void testContextExport() throws UnsupportedEncodingException {

		byte[] password = "password".getBytes("UTF8");
		//Serialize and deserialize the context
		byte[] exportedContext = ctx.exportPassphrase(password);
		assertNotNull(exportedContext);
		assertTrue(exportedContext.length > 0);

		Context restoredContext = Context.importFromBuffer(devinfo, exportedContext, password);
		assertNotNull(restoredContext);

		//Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
		assertArrayEquals(restoredContext.getDevInfo().getMsgProtoId(), devinfo.getMsgProtoId());
		assertArrayEquals(restoredContext.getIdChain().getRoot().getIdentifier(), identifier);

	}
}