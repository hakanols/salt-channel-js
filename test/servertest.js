import * as saltChannel from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import test from './tap-esm.js';
import * as misc from './misc.js'

const session1M1Bytes = util.hex2ab('534376320100000000008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
const session1M2Bytes = util.hex2ab('020000000000de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
const session1M3Bytes = util.hex2ab('0600e47d66e90702aa81a7b45710278d02a8c6cddb69b86e299a47a9b1f1c18666e5cf8b000742bad609bfd9bf2ef2798743ee092b07eb32a45f27cda22cbbd0f0bb7ad264be1c8f6e080d053be016d5b04a4aebffc19b6f816f9a02e71b496f4628ae471c8e40f9afc0de42c9023cfcd1b07807f43b4e25')
const session1M4Bytes = util.hex2ab('0600b4c3e5c6e4a405e91e69a113b396b941b32ffd053d58a54bdcc8eef60a47d0bf53057418b6054eb260cca4d827c068edff9efb48f0eb8454ee0b1215dfa08b3ebb3ecd2977d9b6bde03d4726411082c9b735e4ba74e4a22578faf6cf3697364efe2be6635c4c617ad12e6d18f77a23eb069f8cb38173')
const session1AppBytes = util.hex2ab('06005089769da0def9f37289f9e5ff6e78710b9747d8a0971591abf2e4fb')
const session1EchoBytes = util.hex2ab('068082eb9d3660b82984f3c1c1051f8751ab5585b7d0ad354d9b5c56f755')
const request = util.hex2ab('010505050505')

const clientSecret = util.hex2ab('55f4d1d198093c84de9ee9a6299e0f6891c2e1d0b369efb592a9e3f169fb0f79' +
'5529ce8ccf68c0b8ac19d437ab0f5b32723782608e93c6264f184ba152c2357b')
const clientSigKeyPair = nacl.sign.keyPair.fromSecretKey(clientSecret)
const clientEphKeyPair = {
publicKey: util.hex2ab('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a'),
secretKey: util.hex2ab('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a')
}

const serverSecret = util.hex2ab('7a772fa9014b423300076a2ff646463952f141e2aa8d98263c690c0d72eed52d' +
'07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b')
const serverSigKeyPair = nacl.sign.keyPair.fromSecretKey(serverSecret)
const serverEphKeyPair = {
publicKey: util.hex2ab('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f'),
secretKey: util.hex2ab('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb')
}

const sessionKey = util.hex2ab('1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389')

test('serverSession1', async function (t) {
	let [mockSocket, testSocket] = misc.createMockSocket()
	testSocket.setState(mockSocket.OPEN)

	let clientPromise = async function(){
		await util.sleep(100)
		testSocket.send(session1M1Bytes)
		let m2 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m2), session1M2Bytes, 'Check M2')
		let m3 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m3), session1M3Bytes, 'Check M3')
		testSocket.send(session1M4Bytes)
		testSocket.send(session1AppBytes)
		let app = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(app), session1EchoBytes, 'Check App')
	}()

	let sc = saltChannel.server(mockSocket, saltChannel.null_time_keeper())

	const VERSION = [...'SCv2'].map(letter=>letter.charCodeAt(0))
	let {protocol, message} = await sc.runA1A2([VERSION], 1000)
	t.arrayEqual(VERSION, protocol, 'Check protocol')
	let channel = await sc.handshake(message, serverSigKeyPair, serverEphKeyPair)
	let event = await channel.receive(1000)
	t.arrayEqual(new Uint8Array(event.message), request, 'Check echo')
	channel.send(true, request)

	await clientPromise;

	t.end();
})

test('serverA1A2', async function (t) {
	let [mockSocket, testSocket] = misc.createMockSocket()
	testSocket.setState(mockSocket.OPEN)

	let clientPromise = async function(){
		await util.sleep(100)
		let a1 = [8, 0, 0, 0, 0]
		testSocket.send(a1)
		let a2 = await testSocket.receive(1000)
		let expected = new Uint8Array([ 9, 128, 1,
			...[...'SCv2------'].map(letter=>letter.charCodeAt(0)),
			...[...'----------'].map(letter=>letter.charCodeAt(0))
		])

		t.arrayEqual(expected, new Uint8Array(a2), 'Check A2')
	}()

	let sc = saltChannel.server(mockSocket, saltChannel.null_time_keeper())

	const VERSION = [...'SCv2'].map(letter=>letter.charCodeAt(0))
	await sc.runA1A2([VERSION], 1000)
	await clientPromise;

	t.end();
})