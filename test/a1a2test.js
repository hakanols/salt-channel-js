import * as saltChannel from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import test from './tap-esm.js';
import * as misc from './misc.js'

const serverSecret =
	util.hex2ab('7a772fa9014b423300076a2ff646463952f141e2aa8d98263c690c0d72eed52d' +
						'07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b')

const serverSigKeyPair = nacl.sign.keyPair.fromSecretKey(serverSecret)

const PacketTypeA1  = 8
const PacketTypeA2  = 9
const LastFlag = 128

//////////////////////////////////////////////////

test('oneProt', async function (t) {
	let [a2, expectedProtCount] = create1Prot()
	await runTest(t, validateA1Any, a2, expectedProtCount)
	t.end();
})

test('twoProts', async function (t) {
	const expectedProtCount = 2

	const p11 = [...'SCv2------'].map(letter=>letter.charCodeAt(0))
	const p12 = [...'-._AZaz9--'].map(letter=>letter.charCodeAt(0))
	const p21 = [...'SCv3------'].map(letter=>letter.charCodeAt(0))
	const p22 = [...'unicorns--'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount,
		...p11,
		...p12,
		...p21,
		...p22
	])
	await runTest(t, validateA1Any, a2, expectedProtCount)
	t.end();
})

test('maxProts', async function (t) {

	const expectedProtCount = 127

	const p1 = [...'SCv2------'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'----------'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount,
	])
	for (let i = 0; i < expectedProtCount; i++) {
		a2 = new Uint8Array([
			...a2,
			...p1,
			...p2
		])
	}

	await runTest(t, validateA1Any, a2, expectedProtCount)
	t.end();
})
test('nonInit', async function (t) {
	const  expectedError = new Error('Invalid state: a1a2')
	let [mockSocket, testSocket] = misc.createMockSocket()
	testSocket.setState(mockSocket.OPEN)
	let[a2, expectedProtCount] = create1Prot()

	let serverPromise = async function(){
		await util.sleep(500)
		testSocket.send(a2)
	}()

	let sc = saltChannel.client(mockSocket)

	let a1a2Promise = sc.a1a2()

	await misc.asyncThrows(t, async function(){
		await sc.a1a2()
	}, expectedError)

	let prots = await a1a2Promise;
	validateA2Response(t, prots, expectedProtCount)

	await serverPromise;
	t.end();
})

test('badPacketLength', async function (t) {
	const expectedError = new Error('A2: Expected packet length 23 was 43')
	const expectedProtCount = 1

	const p1 = [...'SCc2------'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'----------'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount,
		...p1,
		...p2,
		...new Uint8Array(20)
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

test('badPacketHeader1', async function (t) {
	const expectedError = new Error('A2: Bad packet header. Message type was: 0')
	const badByte = 0
	const expectedProtCount = 1

	const p1 = [...'SCc2------'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'----------'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		badByte,
		LastFlag,
		expectedProtCount,
		...p1,
		...p2,
		...new Uint8Array(20)
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

test('badPacketHeader2', async function (t) {
	const expectedError = new Error('A2: Unsupported adress type: 0')
	const badByte = 0
	const expectedProtCount = 1

	const p1 = [...'SCc2------'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'----------'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		PacketTypeA2,
		badByte,
		expectedProtCount,
		...p1,
		...p2,
		...new Uint8Array(20)
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

test('addressPub', async function (t) {
	let [a2, expectedProtCount] = create1Prot()
	await runTest(t, validateA1Pub, a2, expectedProtCount, serverSigKeyPair.publicKey)
	t.end();
})

test('noSuchServer', async function (t) {
	const expectedError = new Error('A2: NoSuchServer exception')
	let a2 = new Uint8Array([
		PacketTypeA2,
		129,
		0
	])
	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1ZeroPub, a2, 0, new Uint8Array(32))
	}, expectedError)
	t.end();
})

test('badAdressType', async function (t) {
	const expectedError = new Error('A2: Unsupported adress type: 68')
	let a2 = new Uint8Array([PacketTypeA2, 68])
	await misc.asyncThrows(t, async function(){
		await runTest(t, doNothing, a2, 0, null)
	}, expectedError)
	t.end();
})

test('badCharInP1', async function (t) {
	const expectedError = new Error('A2: Invalid char in p1 "32"')
	const expectedProtCount = 1

	const p1 = [...'SCc2 -----'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'----------'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount,
		...p1,
		...p2
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

test('badCharInP2', async function (t) {
	const expectedError = new Error('A2: Invalid char in p2 "32"')
	const expectedProtCount = 1

	const p1 = [...'SCc2------'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'--- ------'].map(letter=>letter.charCodeAt(0))
	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount,
		...p1,
		...p2
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

test('badCount1', async function (t) {
	const expectedError = new Error('A2: Count must be in range [1, 127], was: 0')
	const expectedProtCount = 0

	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

test('badCount2', async function (t) {
	const expectedError  = new Error('A2: Count must be in range [1, 127], was: 128')
	const expectedProtCount = 128

	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount
	])

	await misc.asyncThrows(t, async function(){
		await runTest(t, validateA1Any, a2, expectedProtCount)
	}, expectedError)
	t.end();
})

//////////////////////////////////////////////////

async function runTest(t, validateA1, a2, expectedProtCount, adress) {
	let [mockSocket, testSocket] = misc.createMockSocket()
	testSocket.setState(mockSocket.OPEN)

	let serverPromise = async function(){
		let a1 = await testSocket.receive(1000)
		validateA1(t, a1)
		testSocket.send(a2)
	}()

	let sc = saltChannel.client(mockSocket)

	let prots = await sc.a1a2(adress)
	validateA2Response(t, prots, expectedProtCount)

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
	const expectedProtCount = 1

	const p1 = [...'SCc2------'].map(letter=>letter.charCodeAt(0))
	const p2 = [...'----------'].map(letter=>letter.charCodeAt(0))

	let a2 = new Uint8Array([
		PacketTypeA2,
		LastFlag,
		expectedProtCount,
		...p1,
		...p2
	])
	return [a2, expectedProtCount]
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

function validateA2Response(t, prots, expectedProtCount) {
	t.equal(prots.length, expectedProtCount, 'Check protocol tuple count')
	for ( const[index, prot] of prots.entries()){
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
	}
}