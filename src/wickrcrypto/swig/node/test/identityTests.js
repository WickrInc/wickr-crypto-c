'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

function generateTestNode(identity) {

    var testNode = identity.genNode()

    expect(testNode).to.be.a("object")

    expect(testNode.type).to.eql(wickrcrypto.IDENTITY_TYPE_NODE)
    expect(testNode.signature).to.be.a("object")

    return testNode
}

describe ("Identity Tests", function() {

    var identifier 
    var sigKey
    var testIdentity

    beforeEach(function() {
        identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())
        sigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        testIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)
    })

    it ("should be able to create an identity", function() {

        //Create an identity from an identifier and a key
        expect(testIdentity).to.be.a("object")

        //Generate a random node identity that is signed by testIdentity
        var testNode = generateTestNode(testIdentity)

        var testSignatureData = Buffer.from("testdata")

        //Sign data using this node's signing key
        var testSignature = testNode.signData(testSignatureData)

        expect(wickrcrypto.CryptoEngine.ecVerify(testSignature, testNode.sigKey, testSignatureData)).to.eql(true)

        //Create an identity chain from a root and node identity
        var testChain = wickrcrypto.IdentityChain.fromIdentities(testIdentity, testNode)
        expect(testChain).to.be.a("object")


        //Validate the integrity of the chain by checking signing keys
        expect(testChain.isValid()).to.eql(true)

        var sigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        testIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)

        var testChain = wickrcrypto.IdentityChain.fromIdentities(testIdentity, testNode)
        expect(testChain.isValid()).to.eql(false)
    })

    it("should be able to serialize an identity", function() {

        // Serialize and deserialize an identity
        var serialized = testIdentity.serialize()
        expect(serialized).to.be.a("object")

        var restored = wickrcrypto.Identity.fromBuffer(serialized)
        expect(restored).to.be.a("object")

        //Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
        expect(restored.identifier).to.eql(testIdentity.identifier)
    })

    it("should be able to serialize an identity chain", function() {

        // Serialize and deserialize an identity chain
        var testNode = generateTestNode(testIdentity)
        var testChain = wickrcrypto.IdentityChain.fromIdentities(testIdentity, testNode)
        expect(testChain).to.be.a("object")

        var serialized = testChain.serialize()
        expect(serialized).to.be.a("object")

        var restored = wickrcrypto.IdentityChain.fromBuffer(serialized)
        expect(restored).to.be.a("object")

        //Test some properties to ensure proper wrapping, this is heavily tested in the wickr-crypto-c library tests
        expect(restored.root.identifier).to.eql(testChain.root.identifier)
        expect(restored.node.identifier).to.eql(testChain.node.identifier)
    })

})