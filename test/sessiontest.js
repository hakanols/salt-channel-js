import saltChannelSession from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import getTimeKeeper from '../src/time/typical-time-keeper.js';
import getNullTimeKeeper from '../src/time/null-time-keeper.js';
import test from './tap-esm.js';
import * as misc from './misc.js'

const session1M1Bytes = util.hex2ab('534376320100000000008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
const session1M2Bytes = util.hex2ab('020000000000de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
const session1M3Bytes = util.hex2ab('0600e47d66e90702aa81a7b45710278d02a8c6cddb69b86e299a47a9b1f1c18666e5cf8b000742bad609bfd9bf2ef2798743ee092b07eb32a45f27cda22cbbd0f0bb7ad264be1c8f6e080d053be016d5b04a4aebffc19b6f816f9a02e71b496f4628ae471c8e40f9afc0de42c9023cfcd1b07807f43b4e25')
const session1M4Bytes = util.hex2ab('0600b4c3e5c6e4a405e91e69a113b396b941b32ffd053d58a54bdcc8eef60a47d0bf53057418b6054eb260cca4d827c068edff9efb48f0eb8454ee0b1215dfa08b3ebb3ecd2977d9b6bde03d4726411082c9b735e4ba74e4a22578faf6cf3697364efe2be6635c4c617ad12e6d18f77a23eb069f8cb38173')
const session1AppBytes = util.hex2ab('06005089769da0def9f37289f9e5ff6e78710b9747d8a0971591abf2e4fb')
const session1EchoBytes = util.hex2ab('068082eb9d3660b82984f3c1c1051f8751ab5585b7d0ad354d9b5c56f755')
const request = util.hex2ab('010505050505')

const session2A1Bytes = util.hex2ab('08000120000808080808080808080808080808080808080808080808080808080808080808')
const session2A2Bytes = util.hex2ab('098001534376322d2d2d2d2d2d4543484f2d2d2d2d2d2d')
const adress = util.hex2ab('0808080808080808080808080808080808080808080808080808080808080808')
const p1 = 'SCv2------'
const p2 = 'ECHO------'

const session3M1Bytes = util.hex2ab('534376320100010000008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a')
const session3M2Bytes = util.hex2ab('020001000000de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
const session3M3Bytes = util.hex2ab('06005f545037bc60f771254bb562a5545193c6cdd969b86e299a47a9b1f1c18666e5cf8b000742bad609bfd9bf2ef2798743ee092b07eb32f55c386d4c5f986a22a793f2886c407756e9c16f416ad6a039bec1f546c28e53e3cdd8b6a0b728e1b576dc73c0826fde10a8e8fa95dd840f27887fad9c43e523')
const session3M4Bytes = util.hex2ab('06002541b8476e6f38c121f9f4fb63d99c09b32fff053d58a54bdcc8eef60a47d0bf53057418b6054eb260cca4d827c068edff9efb48f0eb93170c3dd24c413625f3a479a4a3aeef72b78938dd6342954f6c5deaa6046a2558dc4608c8eea2e95eee1d70053428193ab4b89efd6c6d731fe89281ffe7557f')
const session3App1Bytes = util.hex2ab('0600fc874e03bdcfb575da8035aef06178ac0b9744d8a0971591abf2e4fb')
const session3Echo1Bytes = util.hex2ab('060045bfb5a275a3d9e175bfb1acf36cc10a5585b4d0ad354d9b5c56f755')
const session3MultiBytes = util.hex2ab('060051f0396cdadf6e74adb417b715bf3e93cc27e6aef94d2852fd4229970630df2c34bb76ec4c')
const session3Echo2Bytes = util.hex2ab('06808ab0c2c5e3a660e3767d28d4bc0fda2d23fd515aaef131889c0a4b4b3ce8ccefcd95c2c5b9')
const multi1 = util.hex2ab('0104040404')
const multi2 = util.hex2ab('03030303')

const session4M1Bytes = util.hex2ab('534376320101000000008520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b')
const session4M2Bytes = util.hex2ab('020000000000de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f')
const session4M3Bytes = util.hex2ab('06000dfa318c6337d600252260503124352ec6cddb69b86e299a47a9b1f1c18666e5cf8b000742bad609bfd9bf2ef2798743ee092b07eb3207d89eb0ec2da1f0c21e5c744a12757e6c0e71c752d67cc866257ef47f5d80bf9517203d2326737f1355fafd73d50b01c50a306b09cebed4c68d0a7cd6938a2a')
const session4M4Bytes = util.hex2ab('060002bc1cc5f1f04c93319e47602d442ec1b32ffd053d58a54bdcc8eef60a47d0bf53057418b6054eb260cca4d827c068edff9efb48f0ebfd3ad7a2b6718d119bb64dbc149d002100f372763a43f1e81ed9d557f9958240d627ae0b78c89fd87a7e1d49800e9fa05452cb142cbf4b39635bf19b2f91ba7a')
const session4AppBytes = util.hex2ab('06005089769da0def9f37289f9e5ff6e78710b9747d8a0971591abf2e4fb')
const session4EchoBytes = util.hex2ab('068082eb9d3660b82984f3c1c1051f8751ab5585b7d0ad354d9b5c56f755')


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

//////////////////////////////////////////////////////////

test('session1', async function (t) {
	let [mockSocket, testSocket] = misc.createMockSocket()
    testSocket.setState(mockSocket.OPEN)

    let serverPromise = async function(){
        let m1 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m1), session1M1Bytes, 'Check M1')
        testSocket.send(session1M2Bytes)
        testSocket.send(session1M3Bytes)
		let m4 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m4), session1M4Bytes, 'Check M4')
		let app = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(app), session1AppBytes, 'Check App')
        testSocket.send(session1EchoBytes)
    }()

	let sc = saltChannelSession(mockSocket, getNullTimeKeeper())

	let channel = await sc.handshake(clientSigKeyPair, clientEphKeyPair)
	channel.send(false, request)
	let event = await channel.receive(1000)
	t.arrayEqual(new Uint8Array(event.message), request, 'Check echo')

	await serverPromise;
	t.end();
})

test('session2', async function (t) {
	let [mockSocket, testSocket] = misc.createMockSocket()
    testSocket.setState(mockSocket.OPEN)

    let serverPromise = async function(){
        let a1 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(a1), session2A1Bytes, 'Check A1')
        testSocket.send(session2A2Bytes)
    }()

	let sc = saltChannelSession(mockSocket)

	let prots = await sc.a1a2(adress)
	t.equal(prots.length, 1, 'Check prots length')
	t.arrayEqual(prots[0].p1, p1, 'Check p1')
	t.arrayEqual(prots[0].p2, p2, 'Check p2')

	await serverPromise;
	t.end();
})

test('session3', async function (t) {
	let [mockSocket, testSocket] = misc.createMockSocket()
    testSocket.setState(mockSocket.OPEN)

	let time = 0;
	function getTime() {
		if (time === 0) {
			time++
			return 0
		}
		time++
		return time
	}

    let serverPromise = async function(){
        let m1 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m1), session3M1Bytes, 'Check M1')
        testSocket.send(session3M2Bytes)
        testSocket.send(session3M3Bytes)
		let m4 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m4), session3M4Bytes, 'Check M4')
		let app = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(app), session3App1Bytes, 'Check App')
        testSocket.send(session3Echo1Bytes)
		let multi = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(multi), session3MultiBytes, 'Check App')
        testSocket.send(session3Echo2Bytes)
    }()

	let sc = saltChannelSession(mockSocket, getTimeKeeper(getTime))

	let channel = await sc.handshake(clientSigKeyPair, clientEphKeyPair)
	channel.send(false, request)
	let event1 = await channel.receive(1000)
	t.arrayEqual(new Uint8Array(event1.message), request, 'Check echo')
	channel.send(false, multi1, multi2)
	let event2 = await channel.receive(1000)
	t.arrayEqual(new Uint8Array(event2.message), multi1, 'Check multi1')
	let event3 = await channel.receive(1000)
	t.arrayEqual(new Uint8Array(event3.message), multi2, 'Check multi2')

	await serverPromise;
	t.end();
})

test('session4', async function (t) {
	let [mockSocket, testSocket] = misc.createMockSocket()
    testSocket.setState(mockSocket.OPEN)

    let serverPromise = async function(){
        let m1 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m1), session4M1Bytes, 'Check M1')
        testSocket.send(session4M2Bytes)
        testSocket.send(session4M3Bytes)
		let m4 = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(m4), session4M4Bytes, 'Check M4')
		let app = await testSocket.receive(1000)
		t.arrayEqual(new Uint8Array(app), session4AppBytes, 'Check App')
        testSocket.send(session4EchoBytes)
    }()

	let sc = saltChannelSession(mockSocket, getNullTimeKeeper())

	let  channel = await sc.handshake(clientSigKeyPair, clientEphKeyPair, serverSigKeyPair.publicKey)
	channel.send(false, request)
	let event = await channel.receive(1000)
	t.arrayEqual(new Uint8Array(event.message), request, 'Check echo')

	await serverPromise;
	t.end();
})