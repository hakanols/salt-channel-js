import saltChannelSession from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import test from './tap-esm.js';


let serverSecret =
	util.hex2ab('7a772fa9014b423300076a2ff646463952f141e2aa8d98263c690c0d72eed52d' +
						'07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b')

let serverSigKeyPair = nacl.sign.keyPair.fromSecretKey(serverSecret)

function createMockSocket(){

    let readQueue = util.waitQueue();
    let closeQueue = util.waitQueue();

	let mockSocketInterface = {
		onerror: (e) => console.error('ERROR: ', e),
		onclose: () => {},
        onmessage: (e) => {},
		close: function(){
            closeQueue.push("");
        },
		send: function(event){
            readQueue.push(event);
        },
        //https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/readyState
		CONNECTING: 0,
		OPEN: 1,
		CLOSING: 2,
		CLOSED: 3,
		readyState: undefined
	}

    let testInterface = {
        receive: async function(waitTime){
            return (await readQueue.pull(waitTime))[0];
        },
        send: function(message){
            mockSocketInterface.onmessage({data: message})
        },
        receiveClose: async function(waitTime){
            await closeQueue.pull(waitTime)
            return
        },
        sendClose: function(){
            mockSocketInterface.onclose()
        },
        sendError: function(message){
            mockSocketInterface.onerror(message)
        },
        setState: function(state){
            mockSocketInterface.readyState = state
        },
        serverData: undefined
    }

	return [ mockSocketInterface, testInterface ]
}

const PacketTypeA1  = 8
const PacketTypeA2  = 9
const LastFlag = 128

let expectedProtCount
let errorMsg


test('oneProt', async function (t) {
    let sc = await runTest(t, validateA1Any, create1Prot)
	t.equal(sc.getState(), 'closed', 'Check stateAfterA1A2' )
	t.end();
})

test('twoProts', async function (t) {
    await runTest(t, validateA1Any, create2Prots)
	t.end();
})

test('maxProts', async function (t) {
	await runTest(t, validateA1Any, create127Prots)
	t.end();
})
test('nonInit', async function (t) {
	const  expectedError = 'A1A2: Invalid internal state: a1a2'
	let [mockSocket, testSocket] = createMockSocket()
    testSocket.setState(mockSocket.OPEN)

    let serverPromise = async function(){
        await util.sleep(500)
		let a2 = create1Prot()
        testSocket.send(a2)
    }()

	let sc = saltChannelSession(mockSocket)
	sc.setOnError(onError(t, expectedError))
	sc.setOnClose(doNothing)

	let a1a2Promise = sc.a1a2()

    t.throws(async function(){
        await sc.a1a2()
    }, expectedError)

	let a2 = await a1a2Promise;
	validateA2Response(t, a2)

	await serverPromise;
	t.end();
})

test('badPacketLength', async function (t) {
	errorMsg = 'A2: Expected packet length 23 was 43'
	t.throws(async function(){
    	await runTest(t, validateA1Any, createBadPacketLength)
	}, errorMsg)
	t.end();
})

test('badPacketHeader1', async function (t) {
	errorMsg = 'A2: Bad packet header. Expected 9 128, was 0 128'
	t.throws(async function(){
		await runTest(t, validateA1Any, createBadPacketHeader1)
	}, errorMsg)
	t.end();
})

test('badPacketHeader2', async function (t) {
	errorMsg = 'A2: Bad packet header. Expected 9 128, was 9 0'
	t.throws(async function(){
		await runTest(t, validateA1Any, createBadPacketHeader2)
	}, errorMsg)
	t.end();
})

test('addressPub', async function (t) {
    await runTest(t, validateA1Pub, create1Prot, 1, serverSigKeyPair.publicKey)
	t.end();
})
test('noSuchServer', async function (t) {
	errorMsg = 'A2: NoSuchServer exception'
	t.throws(async function(){
		await runTest(t, validateA1ZeroPub, createNoSuchServer, 1, new Uint8Array(32))
	}, errorMsg)
	t.end();
})

test('badAdressType', async function (t) {
	errorMsg = 'A1A2: Unsupported adress type: 2'
	t.throws(async function(){
		await runTest(t, doNothing, doNothing, null, 2, null)
	}, errorMsg)
	t.end();
})

test('badCharInP1', async function (t) {
	errorMsg = 'A2: Invalid char in p1 " "'
	t.throws(async function(){
		await runTest(t, validateA1Any, createBadCharInP1)
	}, errorMsg)
	t.end();
})

test('badCharInP2', async function (t) {
	errorMsg = 'A2: Invalid char in p2 " "'
	t.throws(async function(){
		await runTest(t, validateA1Any, createBadCharInP2)
	}, errorMsg)
	t.end();
})

test('badCount1', async function (t) {
	errorMsg = 'A2: Count must be in range [1, 127], was: 0'
	t.throws(async function(){
		await runTest(t, validateA1Any, createBadCount1)
	}, errorMsg)
	t.end();
})

test('badCount2', async function (t) {
	errorMsg = 'A2: Count must be in range [1, 127], was: 128'
	t.throws(async function(){
		await runTest(t, validateA1Any, createBadCount2)
	}, errorMsg)
	t.end();
})

async function runTest(t, validateA1, createaA2, adressType, adress) {
	let [mockSocket, testSocket] = createMockSocket()
    testSocket.setState(mockSocket.OPEN)

    let serverPromise = async function(){
        let a1 = await testSocket.receive(1000)
        validateA1(t, a1)
		let a2 = createaA2()
        testSocket.send(a2)
    }()

	let sc = saltChannelSession(mockSocket)
	sc.setOnError(onError(t, errorMsg))
	sc.setOnClose(doNothing)

	let a2 = await sc.a1a2(adressType, adress)
	validateA2Response(t, a2)

	await serverPromise;

	return sc
}

function doNothing() {
	// Do nothing
}

/*
 * Creates a minimal correct A2 message containing a single
 * protocol tuple
 */
function create1Prot() {
	let a2 = new Uint8Array(23)

	expectedProtCount = 1

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCc2------'
	let p2 = '----------'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p1.charCodeAt(i)
		a2[13+i] = p2.charCodeAt(i)
	}
	return a2
}

/*
 * Creates an A2 message containing two protocol tuples
 */
function create2Prots() {
	let a2 = new Uint8Array(43)

	expectedProtCount = 2

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p11 = 'SCv2------'
	let p12 = '-._AZaz9--'
	let p21 = 'SCv3------'
	let p22 = 'unicorns--'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p11.charCodeAt(i)
		a2[13+i] = p12.charCodeAt(i)
		a2[23+i] = p21.charCodeAt(i)
		a2[33+i] = p22.charCodeAt(i)
	}
	return a2
}

/*
 * Creates an A2 message containing 127 protocol tuples
 */
function create127Prots() {
	let a2 = new Uint8Array(2543)

	expectedProtCount = 127

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCv2------'
	let p2 = '----------'


	for (let i = 0; i < 127; i++) {
		for (let j = 0; j < 10; j++) {
			a2[3+10*i+j] = p1.charCodeAt(j)
			a2[13+10*i+j] = p2.charCodeAt(j)
		}
	}
	return a2
}


function createBadPacketLength() {
	let a2 = new Uint8Array(43)

	expectedProtCount = 1

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCv2------'
	let p2 = '----------'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p1.charCodeAt(i)
		a2[13+i] = p2.charCodeAt(i)
	}
	return a2
}

function createBadPacketHeader1() {
	const badByte = 0
	let a2 = new Uint8Array(23)

	expectedProtCount = 1

	a2[0] = badByte // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCv2------'
	let p2 = '----------'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p1.charCodeAt(i)
		a2[13+i] = p2.charCodeAt(i)
	}
	return a2
}

function createBadPacketHeader2() {
	const badByte = 0
	let a2 = new Uint8Array(23)

	expectedProtCount = 1

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = badByte // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCv2------'
	let p2 = '----------'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p1.charCodeAt(i)
		a2[13+i] = p2.charCodeAt(i)
	}
	return a2
}


function createNoSuchServer() {
	let a2 = new Uint8Array(3)
	a2[0] = 9
	a2[1] = 129
	return a2
}

function createBadCharInP1() {
	let a2 = new Uint8Array(23)

	expectedProtCount = 1

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCv2 -----'
	let p2 = '----------'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p1.charCodeAt(i)
		a2[13+i] = p2.charCodeAt(i)
	}
	return a2
}

function createBadCharInP2() {
	let a2 = new Uint8Array(23)

	expectedProtCount = 1

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count

	let p1 = 'SCv2------'
	let p2 = '--- ------'

	for (let i = 0; i < 10; i++) {
		a2[3+i] = p1.charCodeAt(i)
		a2[13+i] = p2.charCodeAt(i)
	}
	return a2
}

function createBadCount1() {
	let a2 = new Uint8Array(3)

	expectedProtCount = 0

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count
	return a2
}

function createBadCount2() {
	let a2 = new Uint8Array(23)

	expectedProtCount = 128

	a2[0] = PacketTypeA2 // Packet type
	a2[1] = LastFlag // LastFlag
	a2[2] = expectedProtCount // Count
	return a2
}

/*
 * Validates A1 message.
 * Always {0x08, 0x00}
 */
function validateA1Any(t, message) {
	let a1 = new Uint8Array(message)

	t.equal(a1.length, 5, 'Check A1 length')
	t.equal(a1[0], PacketTypeA1, 'Check first byte.')
	t.equal(a1[1],  0, 'Check second byte.')
	t.equal(a1[2], 0, 'Check address type.')
	t.arrayEqual(a1.slice(3, 6), [0, 0], 'Check address size.')
}

function validateA1Pub(t, message) {
	let a1 = new Uint8Array(message)

	t.equal(a1.length, 37, 'Check A1 length.')
	t.equal(a1[0], PacketTypeA1, 'Check first byte.')
	t.equal(a1[1], 0, 'Check second byte.')
	t.equal(a1[2], 1, 'Check address type.')
	t.arrayEqual(a1.slice(3, 5), [32, 0], 'Check address size.')
	t.arrayEqual(a1.slice(5, 37), serverSigKeyPair.publicKey, 'Check adress')
}

function validateA1ZeroPub(t, message) {
	let a1 = new Uint8Array(message)

	t.equal(a1.length, 37, 'Check A1 length.')
	t.equal(a1[0], PacketTypeA1, 'Check first byte.')
	t.equal(a1[1], 0, 'Check second byte.')
	t.equal(a1[2], 1, 'Check address type.')
	t.arrayEqual(a1.slice(3, 5), [32, 0], 'Check address size.')
	t.arrayEqual(a1.slice(5, 37), new Uint8Array(32), 'Check adress')
}

function validateA2Response(t, prots) {
	t.equal(prots.length, expectedProtCount, 'Check protocol tuple count')
	prots.forEach((prot, index) => {
		// Duble check to minimize printout for testcases with many prots
		if (!util.isString(prot.p1)) {
			t.ok(util.isString(prot.p1), 'Check prot '+index+' p1 is string')
		}
		if (prot.p1.length !== 10) {
			t.equal(prot.p1.length, 10, 'Check prot '+index+' p1 length')
		}
		if (!util.isString(prot.p2)) {
			t.ok(util.isString(prot.p2), 'Check prot '+index+' p2 is string')
		}
		if (prot.p2.length !== 10) {
			t.equal(prot.p2.length, 10, 'Check prot '+index+' p2 length')
		}
    });
}

function onError(t, expectedErr) {
	return function (err){
		t.equal(err.message, expectedErr, 'Check error')

	}
}
