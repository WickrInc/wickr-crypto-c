'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("ECDH Cipher Tests", function() {

    var testInput 
    var testKDFParams
    var ctx

    beforeEach(function() {
        testInput = Buffer.from("hello world")
        testKDFParams = wickrcrypto.KDFMeta.fromComponents(wickrcrypto.KDFAlgo.hkdfSha512(), Buffer.from("salt"), Buffer.from("wickr"))
        ctx = wickrcrypto.ECDHCipherContext.gen(wickrcrypto.ECCurve.p521(), wickrcrypto.Cipher.aes256Gcm())
        expect(ctx).to.be.a("object")
        expect(testKDFParams).to.be.a("object")
    })

    it ("can be generated", function() {
        var rndCipherCtx = wickrcrypto.ECDHCipherContext.gen(wickrcrypto.ECCurve.p521(), wickrcrypto.Cipher.aes256Gcm())
        expect(rndCipherCtx).to.be.a("object")
        expect(rndCipherCtx.localKey.pubData).to.not.eql(ctx.localKey.pubData)

        var anotherCipherCtx = wickrcrypto.ECDHCipherContext.fromComponents(rndCipherCtx.localKey, wickrcrypto.Cipher.aes256Gcm())
        expect(anotherCipherCtx).to.be.a("object")
        expect(rndCipherCtx.localKey.pubData).to.eql(anotherCipherCtx.localKey.pubData)
    })

    it ("can cipher data", function() {
        //Encrypt the test data with the public key 'remoteKey'
        var remoteKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        expect(remoteKey).to.be.a("object")
        var ciphertext = ctx.encrypt(testInput, remoteKey, testKDFParams)
        expect(ciphertext).to.be.a("object")

        //Do a decode using the proper key and validate the result matches the original input
        var decodeCtx = wickrcrypto.ECDHCipherContext.fromComponents(remoteKey, wickrcrypto.Cipher.aes256Gcm()) 
        expect(decodeCtx).to.be.a("object")
        var decoded = decodeCtx.decrypt(ciphertext, ctx.localKey, testKDFParams)
        expect(decoded).to.eql(testInput)

        //Test that supplying the incorrect sender public key leads to a null result
        var incorrectKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        expect(incorrectKey).to.be.a("object")
        decoded = decodeCtx.decrypt(ciphertext, incorrectKey, testKDFParams)
        expect(decoded).to.not.be.a("object")

        //Test that supplying the incorrect local private key leads to a null result
        var decodeCtxWrongKey = wickrcrypto.ECDHCipherContext.fromComponents(incorrectKey, wickrcrypto.Cipher.aes256Gcm())
        expect(decodeCtxWrongKey).to.be.a("object")
        decoded = decodeCtxWrongKey.decrypt(ciphertext,ctx.localKey,testKDFParams)
        expect(decoded).to.not.be.a("object")

        //Test that supplying the incorrect kdf meta leads to a null result
        var incorrectKDFParams = wickrcrypto.KDFMeta.fromComponents(wickrcrypto.KDFAlgo.hkdfSha512(), Buffer.from("salt"), Buffer.from("notwickr"))
        expect(incorrectKDFParams).to.be.a("object")
        decoded = decodeCtx.decrypt(ciphertext, ctx.localKey, incorrectKDFParams)
        expect(decoded).to.not.be.a("object")
    })
})