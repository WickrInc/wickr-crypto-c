'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Context Tests", function() {
    
    var devinfo
    var identifier
    var ctx

    beforeEach(function() {
        //Generate a context from only device info and an identifier
        devinfo = wickrcrypto.DeviceInfo.gen(Buffer.from("sysid"))
        identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())
        var testGeneration = wickrcrypto.ContextGenResult.genNew(devinfo, identifier)
        expect(testGeneration).to.be.a("object")
        ctx = testGeneration.ctx
        expect(ctx.idChain.root.signature).to.eql(testGeneration.ctx.idChain.root.signature)
        expect(ctx).to.be.a("object")
    })

    it ("can be created from individual values", function() {
        var testFromValues = wickrcrypto.Context.fromValues(ctx.devInfo, ctx.idChain, ctx.storageKeys)
        expect(testFromValues).to.be.a("object")
    })

    it ("can be generated", function() {
        
        this.timeout(15000)

        var existingSigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())

        //Generate a context from an existing signing key, device info, and an identifier
        var testGenerationSig = wickrcrypto.ContextGenResult.genNewWithSigKey(devinfo, existingSigKey, identifier)
        expect(testGenerationSig).to.be.a("object")
        expect(testGenerationSig.ctx.idChain.root.sigKey.pubData).to.eql(existingSigKey.pubData)

        var testKeys = wickrcrypto.RootKeys.gen()

        //Generate a context from existing root keys, device info, and an identifier
        var testGenerationRootKeys = wickrcrypto.ContextGenResult.genWithRootKeys(devinfo, testKeys, identifier)
        expect(testGenerationRootKeys).to.be.a("object")

        expect(testKeys.nodeStorageRoot.keyData).to.eql(testGenerationRootKeys.rootKeys.nodeStorageRoot.keyData)
        expect(testKeys.remoteStorageRoot.keyData).to.eql(testGenerationRootKeys.rootKeys.remoteStorageRoot.keyData)
        expect(testKeys.nodeSignatureRoot.pubData).to.eql(testGenerationRootKeys.rootKeys.nodeSignatureRoot.pubData)

        //Create recovery data so the context can be regenerated with a recovery key
        var recoveryData = testGenerationRootKeys.makeRecovery()
        expect(recoveryData).to.be.a("object")

        //Export the recovery key of a context with a passphrase
        var exportedRecoveryKey = testGenerationRootKeys.exportRecoveryKeyPassphrase(Buffer.from("password"))
        expect(exportedRecoveryKey).to.be.a("object")

        expect(wickrcrypto.ContextGenResult.importRecoveryKeyPassphrase(exportedRecoveryKey, Buffer.from("password2"))).to.not.be.a("object")

        //Import a recovery key with a passphrase
        var importedRecoveryKey = wickrcrypto.ContextGenResult.importRecoveryKeyPassphrase(exportedRecoveryKey, Buffer.from("password"))
        expect(importedRecoveryKey).to.be.a("object")

        expect(importedRecoveryKey.keyData).to.eql(testGenerationRootKeys.recoveryKey.keyData)

        //Regenerate a context with a recovery key, recovery information, device info, and an identifier
        var testRecoveryGeneration = wickrcrypto.ContextGenResult.genWithRecovery(devinfo, recoveryData, importedRecoveryKey, identifier)

        expect(testRecoveryGeneration).to.be.a("object")

        expect(wickrcrypto.ContextGenResult.genWithPassphrase(devinfo, exportedRecoveryKey, Buffer.from("password2"), recoveryData, identifier)).to.not.be.a("object")

        //Regenerate a context with a passphrase, exported recovery key, device info, an identifier, and recovery data
        var testPassphraseGeneration = wickrcrypto.ContextGenResult.genWithPassphrase(devinfo, exportedRecoveryKey, Buffer.from("password"), recoveryData, identifier)

        expect(testPassphraseGeneration).to.be.a("object")
    })

    it ("can perform cipher ops", function() {
        var testData = Buffer.from("test")

        //Cipher local data using the context
        var ciphered = ctx.cipherLocal(testData)
        expect(ciphered).to.be.a("object")

        //Decipher local data using the context
        var deciphered = ctx.decipherLocal(ciphered)
        expect(testData).to.eql(deciphered)

        //Cipher remote data using the context
        ciphered = ctx.cipherRemote(testData)
        expect(ciphered).to.be.a("object")

        //Decipher remote data using the context
        deciphered = ctx.decipherRemote(ciphered)
        expect(testData).to.eql(deciphered)
    })

    it ("can generate keys", function() {
        //Generate ephemeral keypairs to distribute for message sending
        var testKey1 = ctx.ephemeralKeypairGen(1)
        expect(testKey1).to.be.a("object")
        expect(testKey1.identifier).to.eql(1)

        var testKey2 = ctx.ephemeralKeypairGen(2)
        expect(testKey2).to.be.a("object")
        expect(testKey2.identifier).to.eql(2)
        expect(testKey1.ecKey.pubData).to.not.eql(testKey2.ecKey.pubData)
        expect(testKey1.ecKey.priData).to.not.eql(testKey2.ecKey.priData)

        //Erase the public key of the ephemeral keypair
        testKey1.makePublic()
        expect(testKey1.ecKey.priData).to.not.be.a("object")
    })

    it ("can export storage keys", function() {
        this.timeout(15000)
        //Export a storage key with a passphrase
        var exported = ctx.exportStorageKeys(Buffer.from("password"))
        expect(exported).to.be.a("object")

        //Import a storage key with a passphrase
        expect(wickrcrypto.Context.importStorage(exported, Buffer.from("password2"))).to.not.be.a("object")
        var imported = wickrcrypto.Context.importStorage(exported, Buffer.from("password"))
        expect(imported).to.be.a("object")
    })

    it ("can encode and decode messages", function() {
        //Generate a context to 'send' messages to
        var devinfo = wickrcrypto.DeviceInfo.gen(Buffer.from("sysid2"))
        var identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())
        var testGeneration = wickrcrypto.ContextGenResult.genNew(devinfo, identifier)
        expect(testGeneration).to.be.a("object")

        var receiverCtx = testGeneration.ctx
        expect(receiverCtx).to.be.a("object")

        var msgKey = receiverCtx.ephemeralKeypairGen(1)
        expect(msgKey).to.be.a("object")

        var receiverNode = wickrcrypto.Node.fromValues(devinfo.msgProtoId, receiverCtx.idChain, msgKey)
        expect(receiverNode).to.be.a("object")

        var message = Buffer.from("wickr")
        var messageType = 1000
        var channel = Buffer.from("12345")
        var ephemerality = wickrcrypto.EphemeralInfo.fromValues(86400, 500)

        //Create metadata for this message
        var meta = wickrcrypto.PacketMeta.fromValues(ephemerality, channel, messageType)
        expect(meta).to.be.a("object")

        //Construct a payload with a message body and metadata
        var payload = wickrcrypto.Payload.fromValues(meta, message)
        expect(payload).to.be.a("object")

        var nodes = wickrcrypto.WickrArray.allocateNode(1)
        nodes.setNode(0,receiverNode)
        expect(nodes.getItemCount()).to.eql(1)

        //Encode the message for a set of node receivers
        var encodeResult = ctx.encodePacket(payload, nodes)
        expect(encodeResult).to.be.a("object")

        //Use the receiver context created above to parse a packet for non decoding purposes
        var parsed = receiverCtx.parsePacketNoDecode(encodeResult.encodedPacket, ctx.idChain)
        expect(parsed).to.be.a("object")
        expect(parsed.parseResult.err).to.eql(wickrcrypto.E_SUCCESS)
        expect(parsed.parseResult.signatureStatus).to.eql(wickrcrypto.PACKET_SIGNATURE_VALID)

        //Use the receiver context created above to parse a packet for decoding purposes
        parsed = receiverCtx.parsePacket(encodeResult.encodedPacket, ctx.idChain)
        expect(parsed).to.be.a("object")
        expect(parsed.parseResult.err).to.eql(wickrcrypto.E_SUCCESS)
        expect(parsed.parseResult.signatureStatus).to.eql(wickrcrypto.PACKET_SIGNATURE_VALID)

        //Decode the packet, and extract the original message
        var decoded = receiverCtx.decodePacket(parsed, msgKey.ecKey)
        expect(decoded).to.be.a("object")
        expect(decoded.err).to.eql(wickrcrypto.E_SUCCESS)
        expect(decoded.decryptedPayload.body).to.eql(message)

    })

    it("can be serialized and deserialized", function() {

        //Serialize and deserialize the context
        var serializedContext = ctx.serialize()
        expect(serializedContext).to.be.a("object")

        var restoredContext = wickrcrypto.Context.fromBuffer(devinfo, serializedContext)
        expect(restoredContext).to.be.a("object")

        //Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
        expect(restoredContext.devInfo.msgProtoId).to.eql(devinfo.msgProtoId)
        expect(restoredContext.idChain.root.identifier).to.eql(identifier)

    })

    it("can be exported and imported", function() {

        var password = Buffer.from('password')
        //Serialize and deserialize the context
        var exportedContext = ctx.exportPassphrase(password)
        expect(exportedContext).to.be.a("object")

        var restoredContext = wickrcrypto.Context.importFromBuffer(devinfo, exportedContext, password)
        expect(restoredContext).to.be.a("object")

        //Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
        expect(restoredContext.devInfo.msgProtoId).to.eql(devinfo.msgProtoId)
        expect(restoredContext.idChain.root.identifier).to.eql(identifier)

    })

})