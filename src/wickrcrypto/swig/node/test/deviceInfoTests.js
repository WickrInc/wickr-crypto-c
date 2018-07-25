
'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

describe ("Device Info Tests", function() {
    it ("should be able to create device info", function() {

        //Generate device info with a random salt using only a system identifier
        var sysid = Buffer.from("testsysid")
        var devinfo = wickrcrypto.DeviceInfo.gen(sysid)

        expect(devinfo).to.be.a("object")

        //Compute device info from an existing salt and system identifier
        var devinfocompute = wickrcrypto.DeviceInfo.compute(devinfo.devSalt, sysid)
        expect(devinfocompute).to.be.a("object")

        expect(devinfo.msgProtoId).to.eql(devinfocompute.msgProtoId)
        expect(devinfo.srvCommId).to.eql(devinfocompute.srvCommId)

        var anotherInfo = wickrcrypto.DeviceInfo.gen(Buffer.from("anothersysid"))
        expect(anotherInfo).to.be.a("object")

        expect(anotherInfo.msgProtoId).to.not.eql(devinfocompute.msgProtoId)
        expect(anotherInfo.srvCommId).to.not.eql(devinfocompute.srvCommId)
    })

})