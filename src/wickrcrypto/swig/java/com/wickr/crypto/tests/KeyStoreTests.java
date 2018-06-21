package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;

public class KeyStoreTests
{
	@Test
	public void testStorageKeys() throws UnsupportedEncodingException
	{
		CipherKey local = CryptoEngine.randomKey(Cipher.aes256Gcm());
		CipherKey remote = CryptoEngine.randomKey(Cipher.aes256Gcm());

		assertNotNull(local);
		assertNotNull(remote);

		//Create storage keys from a local and remote key
		StorageKeys testStorageKeys = StorageKeys.createFromKeys(local, remote);
		assertNotNull(testStorageKeys);

		assertArrayEquals(testStorageKeys.getLocal().getKeyData(), local.getKeyData());
		assertArrayEquals(testStorageKeys.getRemote().getKeyData(), remote.getKeyData());

		//Serialize storage keys to bytes
		byte[] serialized = testStorageKeys.serialize();

		assertNotNull(serialized.length);

		//Generate storage keys from serialized bytes
		StorageKeys restored = StorageKeys.createFromBuffer(serialized);

		assertNotNull(restored);
		assertArrayEquals(restored.getLocal().getKeyData(), local.getKeyData());
		assertArrayEquals(restored.getRemote().getKeyData(), remote.getKeyData());
	}

	@Test
	public void testRootKeys() throws UnsupportedEncodingException
	{
		//Generate a random set of root keys
		RootKeys testKeys = RootKeys.gen();
		assertNotNull(testKeys);

		//Serialize root keys to bytes
		byte[] serialized = testKeys.serialize();
		assertNotNull(serialized);

		//Create root keys from serialized root key data
		RootKeys restored = RootKeys.fromBuffer(serialized);
		assertNotNull(restored);
		assertArrayEquals(testKeys.getNodeStorageRoot().getKeyData(), restored.getNodeStorageRoot().getKeyData());
		assertArrayEquals(testKeys.getRemoteStorageRoot().getKeyData(), restored.getRemoteStorageRoot().getKeyData());
		assertArrayEquals(testKeys.getNodeSignatureRoot().getPubData(), restored.getNodeSignatureRoot().getPubData());

		DeviceInfo devInfo = DeviceInfo.gen("sysid".getBytes("UTF8"));

		//Convert root keys to storage keys by mixing in device specific info
		StorageKeys storageKeys = testKeys.toStorageKeys(devInfo);
		assertNotNull(storageKeys);
		assertArrayEquals(testKeys.getRemoteStorageRoot().getKeyData(), storageKeys.getRemote().getKeyData());
		assertThat(testKeys.getNodeStorageRoot().getKeyData(), not(equalTo(storageKeys.getLocal().getKeyData())));

		CipherKey testEncKey = CryptoEngine.randomKey(Cipher.aes256Gcm());
		assertNotNull(testEncKey);

		//Encrypt the set of root keys with a key
		CipherResult encrypted = testKeys.encrypt(testEncKey);

		assertNotNull(encrypted);

		//Construct root keys from components
		RootKeys testConstruct = RootKeys.fromKeys(testKeys.getNodeSignatureRoot(), testKeys.getNodeStorageRoot(), testKeys.getRemoteStorageRoot());

		assertNotNull(testConstruct);
		assertArrayEquals(testKeys.getNodeStorageRoot().getKeyData(), testConstruct.getNodeStorageRoot().getKeyData());
		assertArrayEquals(testKeys.getRemoteStorageRoot().getKeyData(), testConstruct.getRemoteStorageRoot().getKeyData());
		assertArrayEquals(testKeys.getNodeSignatureRoot().getPubData(), testConstruct.getNodeSignatureRoot().getPubData());
	}
}