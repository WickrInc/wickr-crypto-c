<?php

use PHPUnit\Framework\TestCase;

include 'WickrCrypto.php';

final class EngineTests extends TestCase
{
    public function testRandomData()
    {
        $testData = CryptoEngine::randomBytes(32);
        $this->assertNotEmpty($testData);

        for ($i=0; $i < 1000 ; $i++) { 
            $testNewData = CryptoEngine::randomBytes(32);
            $this->assertNotEquals($testNewData, $testData);
        }
    }

    public function testCipherDecipher() 
    {
        $rndData = CryptoEngine::randomBytes(32);
        $key = CipherKey::fromComponents(Cipher::aes256Gcm(), $rndData);

        $this->assertInstanceOf('CipherKey', $key);
        $this->assertEquals($key->keyData, $rndData);

        $key = CryptoEngine::randomKey(Cipher::aes256Gcm());
        $this->assertInstanceOf('CipherKey', $key);

        $testValue = "hello world";

        //Perform AES Cipher, NULL param means generate random IV
        $ciphered = CryptoEngine::cipher($testValue,NULL, $key, NULL);

        $this->assertInstanceOf('CipherResult', $ciphered);
        //Keys are objects, you need to serialize them to bytes to store in db, send over network etc
        $serializedKey = $key->serialize();

        $this->assertNotEmpty($serializedKey);

        //Cipher results are objects, you need to serialize them to bytes to store in db, send over network etc
        $serializedCipherResult = $ciphered->serialize();

        $this->assertNotEmpty($serializedCipherResult);

        //To import a serialized key / cipher result into an object the from buffer method is used
        $deserializedKey = CipherKey::fromBuffer($serializedKey);

        $this->assertInstanceOf('CipherKey', $deserializedKey);

        $deserializedCipherResult = CipherResult::fromBuffer($serializedCipherResult);

        $this->assertInstanceOf('CipherResult', $deserializedCipherResult);
        // The decipher method returns the deciphered data directly
        $deciphered = CryptoEngine::decipher($deserializedCipherResult, NULL, $deserializedKey,true); //True means force GCM, do not accept CTR
        $this->assertNotEmpty($deciphered);

        $this->assertEquals($deciphered, $testValue);

    }

    public function testSignatures() {
        // Generate a random EC Key
        $testECKey = CryptoEngine::randEcKey(ECCurve::p521());

        $this->assertInstanceOf('ECKey', $testECKey);

        $testPrivateKeyData = $testECKey->priData;
        $testPubKeyData = $testECKey->pubData;

        // Import a buffer into an EC Key object (true means private, false means public)
        $restoreTestKeyPrivate = CryptoEngine::importEcKey($testPrivateKeyData, true);
        $restoreTestKeyPublic = CryptoEngine::importEcKey($testPubKeyData, false);

        $this->assertInstanceOf('ECKey', $restoreTestKeyPrivate);
        $this->assertInstanceOf('ECKey', $restoreTestKeyPublic);

        $testData = "HelloWorld";

        // Generate a signature using a private ec key, data, and a hashing method
        $testSignature = CryptoEngine::ecSign($restoreTestKeyPrivate, $testData, Digest::sha512());
        
        $this->assertInstanceOf('ECDSAResult', $testSignature);

        // The test signature is an object, so we must serialize it into bytes for storage and network
        $testSignatureData = $testSignature->serialize();

        $this->assertNotEmpty($testSignatureData);

        // Create a signature result from a buffer generated by serialize
        $testSignatureRestore = ECDSAResult::createFromBuffer($testSignatureData);

        $this->assertInstanceOf('ECDSAResult', $testSignature);

        // Verify a signature where testData is the expected data, restoreTestKeyPublic is the public key
        // and testSignatureRestore is a signature object
        $isValid = CryptoEngine::ecVerify($testSignatureRestore, $restoreTestKeyPublic, $testData);

        $this->assertEquals($isValid, true);

        $anotherECKey = CryptoEngine::randEcKey(ECCurve::p521());

        $this->assertInstanceOf('ECKey', $anotherECKey);

        $isValid = CryptoEngine::ecVerify($testSignatureRestore, $anotherECKey, $testData);

        $this->assertEquals($isValid, false);
    }

    public function testHashing() 
    {
        // Generate a hash
        $hash256Salt = CryptoEngine::digest("Hello", "World", Digest::sha256());
        $hash256NoSalt = CryptoEngine::digest("HelloWorld", NULL, Digest::sha256());

        $this->assertNotEmpty($hash256Salt);
        $this->assertNotEmpty($hash256NoSalt);

        // Hashes are generated in binary format, bin2hex will convert them into strings
        $hash256Salt = bin2hex($hash256Salt);
        $hash256NoSalt = bin2hex($hash256NoSalt);

        $this->assertEquals($hash256Salt, $hash256NoSalt);
        $this->assertEquals($hash256Salt, "872e4e50ce9990d8b041330c47c9ddd11bec6b503ae9386a99da8584e9bb12c4");
    }

    public function testECDH()
    {
        $theirKey = CryptoEngine::randEcKey(ECCurve::p521());
        $ourKey = CryptoEngine::randEcKey(ECCurve::p521());

        $this->assertInstanceOf('ECKey', $ourKey);
        $this->assertInstanceOf('ECKey', $theirKey);

        $outputSharedSecret = CryptoEngine::ecdhGenSharedSecret($ourKey, $theirKey);
        $this->assertNotEmpty($outputSharedSecret);

        $ourKey = CryptoEngine::randEcKey(ECCurve::p521());

        $outputSharedSecret2 = CryptoEngine::ecdhGenSharedSecret($ourKey, $theirKey);
        $this->assertNotEmpty($outputSharedSecret2);

        $this->assertNotEquals($outputSharedSecret, $outputSharedSecret2);
    }

    public function testKDF()
    {
        $passphrase = "password";
        $testValue = "HelloWorld";

        //Generate an scrypt hash
        $kdf = CryptoEngine::kdf(KDFAlgo::scrypt17(), $passphrase);
        $this->assertNotEmpty($kdf);

        //Generate a bcrypt hash
        $bcrypt = CryptoEngine::kdf(KDFAlgo::bcrypt15(), $passphrase);
        $this->assertNotEmpty($bcrypt);

        //Cipher using a passphrase with Scrypt as a kdf
        $ciphered = CryptoEngine::kdfEncrypt(KDFAlgo::scrypt17(), Cipher::aes256Gcm(), $testValue, $passphrase);
        $this->assertNotEmpty($bcrypt);

        $decipheredInvalidPass = CryptoEngine::kdfDecrypt($ciphered, "invalid password" );
        $this->assertEmpty($decipheredInvalidPass);

        //Decipher the scrypt protected data
        $deciphered = CryptoEngine::kdfDecrypt($ciphered, $passphrase);
        $this->assertEquals($deciphered, $testValue);
    }

    public function testKdfCustomLength() {
        $passphrase = "password";
        $kdf = CryptoEngine::kdfFull(KDFAlgo::scrypt17(), $passphrase, 64);
        $this->assertNotEmpty($kdf);
        $this->assertEquals(strlen($kdf->hash), 64);

        $kdf2 = CryptoEngine::kdfSaltFull($kdf->meta, $passphrase, 64);
        $this->assertEquals($kdf->hash, $kdf2);
    }
}

?>
