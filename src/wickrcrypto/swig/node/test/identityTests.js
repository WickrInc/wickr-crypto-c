'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../build_node/src/wickrcrypto/swig/node/lib/wickrcrypto')

describe ("Identity Tests", function() {
    it ("should be able to create an identity", function() {

        var identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())

        var sigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())

        //Create an identity from an identifier and a key
        var testIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)

        expect(testIdentity).to.be.a("object")

        //Generate a random node identity that is signed by testIdentity
        var testNode = testIdentity.genNode()

        expect(testNode).to.be.a("object")

        expect(testNode.type).to.eql(wickrcrypto.IDENTITY_TYPE_NODE)
        expect(testNode.signature).to.be.a("object")

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
        var testIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)

        var testChain = wickrcrypto.IdentityChain.fromIdentities(testIdentity, testNode)
        expect(testChain.isValid()).to.eql(false)
    })

})