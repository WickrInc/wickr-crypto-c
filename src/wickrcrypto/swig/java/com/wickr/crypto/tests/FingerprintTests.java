package com.wickr.crypto.tests;

import static org.junit.Assert.*;
import static org.hamcrest.CoreMatchers.*;
import org.junit.Test;
import org.junit.Before;
import com.wickr.crypto.*;
import java.io.*;
import java.util.*;

public class FingerprintTests
{

    protected Fingerprint testFingerprint;
        
    @Before
    public void setUp() throws UnsupportedEncodingException
    {
        byte[] identifier = CryptoEngine.digest("wickr".getBytes("UTF8"), null, Digest.sha256());
        ECKey sigKey = CryptoEngine.randEcKey(ECCurve.p521());
        Identity testIdentity = Identity.fromValues(IdentityType.IDENTITY_TYPE_ROOT, identifier, sigKey, null);
        this.testFingerprint = testIdentity.fingerprint();
    }

    @Test
    public void testEncodings() throws UnsupportedEncodingException
    {

        // Verify that encodings are working correctly
        String hexStringShort = testFingerprint.getHexString(FingerprintOutputType.FINGERPRINT_OUTPUT_SHORT);
        String base32StringShort = testFingerprint.getBase32String(FingerprintOutputType.FINGERPRINT_OUTPUT_SHORT);

        String hexStringLong = testFingerprint.getHexString(FingerprintOutputType.FINGERPRINT_OUTPUT_LONG);
        String base32StringLong = testFingerprint.getBase32String(FingerprintOutputType.FINGERPRINT_OUTPUT_LONG);

        assertTrue(hexStringLong.length() != testFingerprint.getData().length);
        assertTrue(hexStringLong.length() > hexStringShort.length());

        assertTrue(base32StringLong.length() != testFingerprint.getData().length);
        assertTrue(base32StringLong.length() > base32StringShort.length());

    }


}

