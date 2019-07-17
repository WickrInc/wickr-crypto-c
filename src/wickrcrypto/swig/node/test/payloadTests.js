'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Payload Tests", function() {

    var testPayload
    var testSettings
    var testMetadata
    var testTag
    var testBody
    var testContentType

    beforeEach(function() {
        //Create a payload
        testSettings = wickrcrypto.EphemeralInfo.fromValues(32,64)
        testTag = wickrcrypto.CryptoEngine.randomBytes(32)
        testBody = wickrcrypto.CryptoEngine.randomBytes(64)
        testContentType = 1000
        testMetadata = wickrcrypto.PacketMeta.fromValues(testSettings, testTag, 1000)
        testPayload = wickrcrypto.Payload.fromValues(testMetadata, testBody)
    })

    it ("should be able to create a valid payload", function() {
        expect(testSettings).to.be.a("object")
        expect(testTag).to.be.a("object")
        expect(testBody).to.be.a("object")
        expect(testMetadata).to.be.a("object")
        expect(testPayload).to.be.a("object")

        /* Check a couple values to ensure the call worked (more tests in wickr-crypto-c) */
        expect(testPayload.body).to.eql(testBody)
        expect(testPayload.meta.channelTag).to.eql(testTag)
        expect(testPayload.meta.ephemeralitySettings.ttl).to.eql(32)
    })

    it("can be serialized", function() {

        var serialized = testPayload.serialize()
        expect(serialized).to.be.a("object")

        var restored = wickrcrypto.Payload.createFromBuffer(serialized)
        expect(restored).to.be.a("object")

        // Check a couple values to ensure the call worked (more tests in wickr-crypto-c)
        expect(testPayload.body).to.eql(restored.body)
        expect(testPayload.meta.channelTag).to.eql(restored.meta.channelTag)
        expect(testPayload.meta.ephemeralitySettings.ttl).to.eql(restored.meta.ephemeralitySettings.ttl)

    })

    it("can be encrypted", function() {

        var testKey = wickrcrypto.CryptoEngine.randomKey(wickrcrypto.Cipher.aes256Gcm())
        var testIncorrectKey = wickrcrypto.CryptoEngine.randomKey(wickrcrypto.Cipher.aes256Gcm())

        var encrypted = testPayload.cipher(testKey)
        expect(encrypted).to.be.a("object")

        var restored = wickrcrypto.Payload.fromCiphertext(encrypted, testKey)
        expect(restored).to.be.a("object")

        // Check a couple values to ensure the call worked (more tests in wickr-crypto-c)
        expect(testPayload.body).to.eql(restored.body)
        expect(testPayload.meta.channelTag).to.eql(restored.meta.channelTag)
        expect(testPayload.meta.ephemeralitySettings.ttl).to.eql(restored.meta.ephemeralitySettings.ttl)

        // Verify we can handle a decryption failure
        expect(wickrcrypto.Payload.fromCiphertext(encrypted, testIncorrectKey)).to.not.be.a("object")

    })

})