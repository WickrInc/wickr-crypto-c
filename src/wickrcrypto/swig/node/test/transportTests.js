'use strict'

var expect = require('expect.js')
var wickrcrypto = require('../../../../../node/lib/wickrcrypto')

var generateRandomNode = require('./nodeTests').generateRandomNode

describe ("Transport Tests", function() {

    var testLocalNode
    var testRemoteNode
    var testAliceTransport
    var testBobTransport
    
    var aliceTxEvent
    var aliceRxEvent
    var aliceStateChangedEvent
    var aliceIdentityEvent
    var aliceLastDecoded

    var bobTxEvent
    var bobRxEvent
    var bobStateChangedEvent
    var bobIdentityEvent
    var bobLastDecoded

    const resetEvents = function() {
        aliceTxEvent = []
        aliceRxEvent = []
        aliceStateChangedEvent = []
        aliceIdentityEvent = []
        aliceLastDecoded = null

        bobTxEvent = []
        bobRxEvent = []
        bobStateChangedEvent = []
        bobIdentityEvent = []
        bobLastDecoded = null
    }

    const txAliceCallback = function(data, type) {
        aliceTxEvent.push({data: data, type: type})
        bobLastDecoded = testBobTransport.processRxBuffer(data)
    }

    const rxAliceCallback = function(data) {
        aliceRxEvent.push(data)
    }

    const stateChangeAliceCallback = function(newState) {
        aliceStateChangedEvent.push(newState)
    }

    const identityVerifyAliceRequested = function(identity, onComplete) {
        aliceIdentityEvent.push(identity)
        onComplete(true)
    }

    const aliceCallbacks = {
        onTx: txAliceCallback,
        onRx: rxAliceCallback,
        onStateChanged: stateChangeAliceCallback,
        identityVerify: identityVerifyAliceRequested
    }

    const txBobCallback = function(data, type) {
        bobTxEvent.push({data: data, type: type})
        aliceLastDecoded = testAliceTransport.processRxBuffer(data)
    }

    const rxBobCallback = function(data) {
        bobRxEvent.push(data)
    }

    const stateChangeBobCallback = function(newState) {
        bobStateChangedEvent.push(newState)
    }

    const identityVerifyBobRequested = function(identity, onComplete) {
        bobIdentityEvent.push(identity)
        onComplete(true)
    }

    const bobCallbacks = {
        onTx: txBobCallback,
        onRx: rxBobCallback,
        onStateChanged: stateChangeBobCallback,
        identityVerify: identityVerifyBobRequested
    }

    beforeEach(function() {

        resetEvents()

        testLocalNode = generateRandomNode(Buffer.from("alice"))
        testRemoteNode = generateRandomNode(Buffer.from("bob"))

        testAliceTransport = wickrcrypto.TransportCtx.createTransport(testLocalNode.node, testRemoteNode.node, aliceCallbacks)
        testBobTransport = wickrcrypto.TransportCtx.createTransport(testRemoteNode.node, null, bobCallbacks);
    })

    describe("establishing a transport", function() {

        it ("should get created propertly", function() {
            expect(testAliceTransport).to.be.a("object")
            expect(testBobTransport).to.be.a("object")
    
            expect(testAliceTransport.getStatus()).to.eql(0)
            expect(testBobTransport.getStatus()).to.eql(0)
        })
    
        it("should be able to be started", function() {
            testAliceTransport.start()
            
            expect(aliceTxEvent.length).to.eql(2)
            expect(aliceTxEvent[0].data.length).to.eql(791)
            expect(aliceTxEvent[0].type).to.eql(0)
            expect(aliceTxEvent[1].data.length).to.eql(400)
            expect(aliceTxEvent[1].type).to.eql(0)
    
            expect(aliceRxEvent.length).to.eql(0)
            expect(aliceIdentityEvent.length).to.eql(0)
            expect(aliceStateChangedEvent).to.eql([1,3])
    
            expect(bobTxEvent.length).to.eql(1)
            expect(bobTxEvent[0].data.length).to.eql(1035)
            expect(bobTxEvent[0].type).to.eql(0)
    
            expect(bobRxEvent.length).to.eql(0)
    
            expect(bobIdentityEvent.length).to.eql(1)
            expect(bobIdentityEvent[0].root.identifier).to.eql(testLocalNode.testIdentityChain.root.identifier)
    
            expect(bobStateChangedEvent).to.eql([2,3])
        })
    })

    describe("sending packets", function() {

        beforeEach(function() {
            testAliceTransport.start()
            resetEvents()
        })

        it("should be able to send data packets from alice to bob", function() {

            const testData = Buffer.from("Hello World!")
            testAliceTransport.processTxBuffer(testData)

            /* Verify that no state changes or unwanted callbacks have fired */
            expect(aliceStateChangedEvent.length).to.eql(0)
            expect(bobStateChangedEvent.length).to.eql(0)
            expect(testAliceTransport.getStatus()).to.eql(3)
            expect(testBobTransport.getStatus()).to.eql(3)
            expect(aliceRxEvent.length).to.eql(0)
            expect(aliceIdentityEvent.length).to.eql(0)
            expect(bobIdentityEvent.length).to.eql(0)
            expect(bobTxEvent.length).to.eql(0)

            /* The transport should have produced an encrypted packet to transfer to bob, and bob should have received it */
            expect(aliceTxEvent.length).to.eql(1)
            expect(aliceTxEvent[0].data.length).to.eql(50)
            expect(aliceTxEvent[0].type).to.eql(1)

            expect(bobRxEvent.length).to.eql(1)
            expect(bobRxEvent[0]).to.eql(testData)
            expect(bobLastDecoded).to.eql(testData)

        })

        it("should be able to send data packets from bob to alice", function() {

            const testData = Buffer.from("Hello World!")
            testBobTransport.processTxBuffer(testData)

            /* Verify that no state changes or unwanted callbacks have fired */
            expect(aliceStateChangedEvent.length).to.eql(0)
            expect(bobStateChangedEvent.length).to.eql(0)
            expect(testAliceTransport.getStatus()).to.eql(3)
            expect(testBobTransport.getStatus()).to.eql(3)
            expect(bobRxEvent.length).to.eql(0)
            expect(aliceIdentityEvent.length).to.eql(0)
            expect(bobIdentityEvent.length).to.eql(0)
            expect(aliceTxEvent.length).to.eql(0)

            /* The transport should have produced an encrypted packet to transfer to alice, and alice should have received it */
            expect(bobTxEvent.length).to.eql(1)
            expect(bobTxEvent[0].data.length).to.eql(50)
            expect(bobTxEvent[0].type).to.eql(1)

            expect(aliceRxEvent.length).to.eql(1)
            expect(aliceRxEvent[0]).to.eql(testData)
            expect(aliceLastDecoded).to.eql(testData)

        })
    })

    describe("error conditions", function() {

        it("should allow you to deny a connection based on identity", function() {

            const identityVerifyBobRequestedFail = function(identity, onComplete) {
                bobIdentityEvent.push(identity)
                onComplete(false)
            }
    
            const bobCallbacks = {
                onTx: txBobCallback,
                onRx: rxBobCallback,
                onStateChanged: stateChangeBobCallback,
                identityVerify: identityVerifyBobRequestedFail
            }

            testBobTransport = wickrcrypto.TransportCtx.createTransport(testRemoteNode.node, null, bobCallbacks);
            testAliceTransport.start()

            expect(bobStateChangedEvent).eql([4])
            expect(testBobTransport.getStatus()).to.eql(4)

        })
    
        it("should set it's status to error upon error conditions", function() {
    
            testAliceTransport.start()
            resetEvents()

            var processingResponse = testBobTransport.processRxBuffer(Buffer.from("bad data"))
            expect(processingResponse).to.be.null

            expect(bobRxEvent.length).to.eql(0)
            expect(testBobTransport.getStatus()).to.eql(4)
            expect(bobStateChangedEvent).to.eql([4])

        })
    })

    

})