'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Node Tests", function() {
    it ("should be able to create a node", function() {

        //Create a node from an identity chain, and a device identifier
        var identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())
        var sigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        var testIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)
        expect(testIdentity).to.be.a("object")

        var testNodeIdentity = testIdentity.genNode()
        expect(testNodeIdentity).to.be.a("object")

        var testIdentityChain = wickrcrypto.IdentityChain.fromIdentities(testIdentity, testNodeIdentity)

        expect(testIdentityChain).to.be.a("object")

        var ephemeralKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        var keypair = wickrcrypto.EphemeralKeypair.fromValues(1, ephemeralKey, testNodeIdentity.signData(ephemeralKey.pubData))
        expect(keypair).to.be.a("object")


        var testNode = wickrcrypto.Node.fromValues(Buffer.from("testdevid"), testIdentityChain, keypair)

        expect(testNode).to.be.a("object")

        expect(testNode.verify()).to.eql(true)
    })

})