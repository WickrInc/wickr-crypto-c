package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import com.wickr.crypto.*;
import org.junit.Before;
import java.io.*;
import java.util.*;
import java.math.BigInteger;

public class PayloadTests
{
    protected Payload testPayload;
    protected EphemeralInfo testSettings;
    protected PacketMeta testMetadata;
    protected byte[] testTag;
    protected byte[] testBody;
    protected int testContentType;

    @Before
    public void setUp()
    {
        //Create a payload
        testSettings = EphemeralInfo.fromValues(new BigInteger("32"),new BigInteger("64"));
        testTag = CryptoEngine.randomBytes(32);
        testBody = CryptoEngine.randomBytes(64);
        testContentType = 1000;
        testMetadata = PacketMeta.fromValues(testSettings, testTag, 1000);
        testPayload = Payload.fromValues(testMetadata, testBody);
    }

    @Test
    public void testCreation()
    {
        assertNotNull(testSettings);
        assertNotNull(testTag);
        assertNotNull(testBody);
        assertNotNull(testMetadata);
        assertNotNull(testPayload);

        /* Check a couple values to ensure the call worked (more tests in wickr-crypto-c) */
        assertArrayEquals(testPayload.getBody(), testBody);
        assertArrayEquals(testPayload.getMeta().getChannelTag(), testTag);
        assertEquals(testPayload.getMeta().getEphemeralitySettings().getTtl(), new BigInteger("32"));
    }

    @Test
    public void testSerilization()
    {
        byte[] serialized = testPayload.serialize();
        assertNotNull(serialized);

        Payload restored = Payload.createFromBuffer(serialized);
        assertNotNull(restored);

        // Check a couple values to ensure the call worked (more tests in wickr-crypto-c)
        assertArrayEquals(testPayload.getBody(), restored.getBody());
        assertArrayEquals(testPayload.getMeta().getChannelTag(), restored.getMeta().getChannelTag());
        assertEquals(testPayload.getMeta().getEphemeralitySettings().getTtl(), restored.getMeta().getEphemeralitySettings().getTtl());
    }

    @Test
    public void testEncryption()
    {
        CipherKey testKey = CryptoEngine.randomKey(Cipher.aes256Gcm());
        CipherKey testIncorrectKey = CryptoEngine.randomKey(Cipher.aes256Gcm());

        CipherResult encrypted = testPayload.cipher(testKey);
        assertNotNull(encrypted);

        Payload restored = Payload.fromCiphertext(encrypted, testKey);
        assertNotNull(restored);

        // Check a couple values to ensure the call worked (more tests in wickr-crypto-c)
        assertArrayEquals(testPayload.getBody(), restored.getBody());
        assertArrayEquals(testPayload.getMeta().getChannelTag(), restored.getMeta().getChannelTag());
        assertEquals(testPayload.getMeta().getEphemeralitySettings().getTtl(), restored.getMeta().getEphemeralitySettings().getTtl());

        // Verify we can handle a decryption failure
        assertNull(Payload.fromCiphertext(encrypted, testIncorrectKey));
    }
    
}