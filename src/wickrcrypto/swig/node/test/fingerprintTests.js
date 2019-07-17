'use strict';

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Fingerprint Encoding Tests", function() {

    var testFingerprint

    beforeEach(function() {
        var identifier = wickrcrypto.CryptoEngine.digest(Buffer.from("wickr"), null, wickrcrypto.Digest.sha256())
        var sigKey = wickrcrypto.CryptoEngine.randEcKey(wickrcrypto.ECCurve.p521())
        var testIdentity = wickrcrypto.Identity.fromValues(wickrcrypto.IDENTITY_TYPE_ROOT, identifier, sigKey, null)
        testFingerprint = testIdentity.fingerprint()
    })

    it ("should be able to encode fingerprints in various formats", function() {

        var hexStringShort = testFingerprint.getHex(wickrcrypto.FINGERPRINT_OUTPUT_SHORT).toString('utf8')
        var base32StringShort = testFingerprint.getB32(wickrcrypto.FINGERPRINT_OUTPUT_SHORT).toString('utf8')

        var hexStringLong = testFingerprint.getHex(wickrcrypto.FINGERPRINT_OUTPUT_LONG);
        var base32StringLong = testFingerprint.getB32(wickrcrypto.FINGERPRINT_OUTPUT_LONG);

        expect(hexStringLong.length != testFingerprint.data.length).to.be.true
        expect(hexStringLong.length > hexStringShort.length).to.be.true

        expect(base32StringLong.length != testFingerprint.data.length).to.be.true
        expect(base32StringLong.length > base32StringShort.length).to.be.true

    })

});