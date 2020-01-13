'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

function generateRandomNode(identifier) {
    const sigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
    const testRootIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)
    expect(testRootIdentity).to.be.a("object")

    //Create a node from an identity chain, and a device identifier
    const testNodeIdentity = testRootIdentity.genNode(null)
    expect(testNodeIdentity).to.be.a("object")

    // Create an identity chain
    const testIdentityChain = wickrcrypto.IdentityChain.fromIdentities(testRootIdentity, testNodeIdentity)
    expect(testIdentityChain).to.be.a("object")

    // Create an ephemeral keypair
    const ephemeralKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
    const keypair = wickrcrypto.EphemeralKeypair.fromValues(1, ephemeralKey, testNodeIdentity.signData(ephemeralKey.pubData))
    expect(keypair).to.be.a("object")

    return {
        testRootIdentity: testRootIdentity,
        testNodeIdentity: testNodeIdentity,
        testIdentityChain: testIdentityChain,
        ephemeralKey: ephemeralKey,
        keypair: keypair,
        node: wickrcrypto.Node.fromValues(Buffer.from("testdevid"), testIdentityChain, keypair)
    } 
}

describe ("Node Tests", function() {

    var identifier
    var testNode
    var keypair

    beforeEach(function() {
        // Create a root identity
        identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())
        
        // Create a node
        var nodeGeneration = generateRandomNode(identifier)
        testNode = nodeGeneration.node
        keypair = nodeGeneration.keypair
    })

    it ("should be able to create a valid node", function() {
        expect(testNode).to.be.a("object")
        expect(testNode.verify()).to.eql(true)
    })

    it("can be serialized", function() {

        var serialized = testNode.serialize()
        expect(serialized).to.be.a("object")

        var restoredNode = wickrcrypto.Node.fromBuffer(serialized)
        expect(restoredNode).to.be.a("object")

        // Check a couple values to ensure the call worked (more tests in wickr-crypto-c)
        expect(restoredNode.ephemeralKeypair.identifier).to.eql(keypair.identifier)
        expect(restoredNode.idChain.root.identifier).to.eql(testNode.idChain.root.identifier)

    })

})

module.exports.generateRandomNode = generateRandomNode