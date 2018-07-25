'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Root Keys Tests", function() {
    it ("should be able to create root keys", function() {

        //Generate a random set of root keys
        var testKeys = wickrcrypto.RootKeys.gen()
        expect(testKeys).to.be.a("object")

        //Serialize root keys to bytes
        var serialized = testKeys.serialize()
        expect(serialized).to.be.a("object")

        //Create root keys from serialized root key data
        var restored = wickrcrypto.RootKeys.fromBuffer(serialized)
        expect(restored).to.be.a("object")


        expect(testKeys.nodeStorageRoot.keyData).to.eql(restored.nodeStorageRoot.keyData)
        expect(testKeys.remoteStorageRoot.keyData).to.eql(restored.remoteStorageRoot.keyData)
        expect(testKeys.nodeSignatureRoot.pubData).to.eql(restored.nodeSignatureRoot.pubData)

        var devInfo = wickrcrypto.DeviceInfo.gen(Buffer.from("sysid"))

        //Convert root keys to storage keys by mixing in device specific info
        var storageKeys = testKeys.toStorageKeys(devInfo)
        expect(storageKeys).to.be.a("object")


        expect(testKeys.remoteStorageRoot.keyData).to.eql(storageKeys.remote.keyData)
        expect(testKeys.nodeStorageRoot.keyData).to.not.eql(storageKeys.local.keyData)

        var testEncKey = wickrcrypto.CryptoEngine.randomKey(wickrcrypto.Cipher.aes256Gcm())
        expect(testEncKey).to.be.a("object")


        //Encrypt the set of root keys with a key
        var encrypted = testKeys.encrypt(testEncKey)

        expect(encrypted).to.be.a("object")

        //Construct root keys from components
        var testConstruct = wickrcrypto.RootKeys.fromKeys(testKeys.nodeSignatureRoot, testKeys.nodeStorageRoot, testKeys.remoteStorageRoot)

        expect(testConstruct).to.be.a("object")

        expect(testKeys.nodeStorageRoot.keyData).to.eql(testConstruct.nodeStorageRoot.keyData)
        expect(testKeys.remoteStorageRoot.keyData).to.eql(testConstruct.remoteStorageRoot.keyData)
        expect(testKeys.nodeSignatureRoot.pubData).to.eql(testConstruct.nodeSignatureRoot.pubData)
    })

})