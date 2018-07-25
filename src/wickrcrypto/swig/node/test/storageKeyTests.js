'use strict';

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Storage Keys Tests", function() {
    it ("should be able to create storage keys", function() {

        var local = wickrcrypto.CryptoEngine.randomKey(wickrcrypto.Cipher.aes256Gcm())
        var remote = wickrcrypto.CryptoEngine.randomKey(wickrcrypto.Cipher.aes256Gcm())
        expect(local).to.be.a("object")
        expect(remote).to.be.a("object")

        //Create storage keys from a local and remote key
        var testStorageKeys = wickrcrypto.StorageKeys.createFromKeys(local, remote)
        expect(testStorageKeys).to.be.a("object")

        expect(testStorageKeys.local.keyData).to.eql(local.keyData)
        expect(testStorageKeys.remote.keyData).to.eql(remote.keyData)

        //Serialize storage keys to bytes
        var serialized = testStorageKeys.serialize()

        expect(serialized).to.be.a("object")

        //Generate storage keys from serialized bytes
        var restored = wickrcrypto.StorageKeys.createFromBuffer(serialized)

        expect(restored).to.be.a("object")

        expect(restored.local.keyData).to.eql(local.keyData)
        expect(restored.remote.keyData).to.eql(remote.keyData)
    })

});