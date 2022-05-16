import saltChannelSession from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import getTimeChecker from '../src/time/typical-time-checker.js';
import test from './tap-esm.js'

let clientSecret =
    util.hex2ab('fd2956eb37782aabddc97eaf3b9e1b075f4976770db56c11e866e8763fa073d8' +
                        '9cace2ed6af2e108bbabc69c0bb7f3e62a4c0bf59ac2296811a09e480bf7b0f7')
let clientSigKeyPair = nacl.sign.keyPair.fromSecretKey(clientSecret)
let clientEphKeyPair = {
    publicKey: util.hex2ab('159205ede53fe5334eaf26f15f80710453b6600e6df5c96bfb85dd593c86cf4f'),
    secretKey: util.hex2ab('e9f639ffd6cc1c1edd5ba28e0aecbbe15ad88478dbfcebc09ad80300880a3fa2')
    }

let serverSecret =
    util.hex2ab('7a772fa9014b423300076a2ff646463952f141e2aa8d98263c690c0d72eed52d' +
                        '07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b')
let serverSigKeyPair = nacl.sign.keyPair.fromSecretKey(serverSecret)
let serverEphKeyPair = {
    publicKey: util.hex2ab('354200647ecfbcb1d5feeb7b2f59127fe1278ab4a632b505691f9a2f6a465065'),
    secretKey: util.hex2ab('942d5f9bb23b8380ce9a86ae52600ec675b922b64b1b294c8f94c44255a26fe0')
    }

let mockSocket = {
    close: closeMockSocket,
    readyState: 1
}

function closeMockSocket() {
    mockSocket.readyState = 3
}

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
        }
    }

	return [ mockSocketInterface, testInterface ]
}

async function testServerSide(t, testInterface, validateM1){
        
    eNonce = new Uint8Array(nacl.secretbox.nonceLength)
    dNonce = new Uint8Array(nacl.secretbox.nonceLength)
    eNonce[0] = 2
    dNonce[0] = 1
    lastFlag = false

    let m1 = await testInterface.receive(1000)
    validateM1(t, m1)
    testInterface.send(sendM2())
    testInterface.send(sendM3())
    let m4 = await testInterface.receive(1000)
    validateM4(t, m4)
}


let sessionKey
let eNonce
let dNonce

let cEpoch
let sEpoch
let threshold

let sc
let m1Hash
let m2Hash

const SIG_STR_1 = 'SC-SIG01'
const SIG_STR_2 = 'SC-SIG02'
const sigBytes1 = [...SIG_STR_1].map(letter=>letter.charCodeAt(0))
const sigBytes2 = [...SIG_STR_2].map(letter=>letter.charCodeAt(0))

let badData
let multiAppPacketCount
let multiAppPacketFailed
let lastFlag

let bigPayload = util.hex2ab('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccc' +
    'ddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +
    'ffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000' +
    '11111111111111111111111111111111111111112222222222222222222222222222222222222222' +
    '33333333333333333333333333333333333333334444444444444444444444444444444444444444' +
    '55555555555555555555555555555555555555556666666666666666666666666666666666666666' +
    '77777777777777777777777777777777777777778888888888888888888888888888888888888888' +
    '9999999999999999999999999999999999999999ffffffffffffffffffffffffffffffffffffffff')

let timeKeeper
let timeChecker

test('minimal', async function (t) {
    await standardHandshake(t)
	t.end();
});

test('withServSigKey', async function (t) {
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    sc.setOnError(function(err) {
        t.fail('Got error: '+err)
    })
    sc.setOnClose(doNothing)

    let serverPromise = testServerSide(t, testInterface, validateM1WithServSigKey)

    await sc.handshake(clientSigKeyPair, clientEphKeyPair, serverSigKeyPair.publicKey);

    t.equal(sc.getState(), 'ready', 'State is OPEN')

    await serverPromise;

	t.end();
});

test('sendAppPacket1', async function (t) {
    let [sc, testInterface] = await standardHandshake(t)

    sc.send(false, new Uint8Array([0]).buffer)
    let app1 = await testInterface.receive(1000)
    validateAppPacket(t, app1)

	t.end();
});

test('sendAppPacket2', async function (t) {
    let [sc, testInterface] = await standardHandshake(t)

    sc.send(false, [new Uint8Array([0])])
    let app2 = await testInterface.receive(1000)
    validateAppPacket(t, app2)

	t.end();
});

test('receiveAppPacket', async function (t) {
    let [sc, testInterface] = await standardHandshake(t)

    let appPacket = getAppPacket()
    let encrypted = encrypt(appPacket)
    testInterface.send(encrypted)

    let message = await sc.receive(1000)
    receiveZeroByte(t, message)

	t.end();
});

test('sendMultiAppPacket1', async function (t) {
    let [sc, testInterface] = await standardHandshake(t)

    sc.send(false, [new Uint8Array([0]).buffer, new Uint8Array([1])])
    let multiApp = await testInterface.receive(1000)
    validateMultiAppPacket(t, multiApp)
	t.end();
});

test('sendMultiAppPacket2', async function (t) {
    let [sc, testInterface] = await standardHandshake(t)

    sc.send(false, new Uint8Array([0]), new Uint8Array([1]).buffer)
    let multiApp = await testInterface.receive(1000)
    validateMultiAppPacket(t, multiApp)
	t.end();
});

test('testSendBigMultiAppPacket', async function (t) {
    let [sc, testInterface] = await standardHandshake(t)

    sc.send(false, new Uint8Array([0]), bigPayload)
    let multiApp = await testInterface.receive(1000)
    validateBigMultiAppPacket(t, multiApp)
	t.end();
});

test('receiveMultiAppPacket', async function (t) {
    multiAppPacketCount = 0;
    multiAppPacketFailed = false;

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey)

    sc.setOnMessage(receiveTwoAppPacketData)
    receiveMultiAppPacket()
	t.end();
});

test('receiveBadEncryption', async function (t) {
    const errorMsg = 'EncryptedMessage: Could not decrypt message'

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey, errorMsg)

    receiveBadEncryption()
	t.end();
});

test('receiveAfterError', async function (t) {
    const errorMsg = 'Received message when salt channel was not ready'

    receiveAppPacket()
	t.end();
});

test('receiveDelayed', async function (t) {
    const errorMsg = '(Multi)AppPacket: Detected a delayed packet'

    threshold = 20
    timeChecker = getTimeChecker(util.currentTimeMs, 10)
    await newSaltChannelAndHandshake(t, validateM1NoServSigKey)

    receiveDelayedPacket()
    timeChecker = undefined
    threshold = undefined
	t.end();
});

test('handShakeAfterError', async function (t) {
    await handshakeAfterError(t)
	t.end();
});

test('receiveLastFlag', async function (t) {
    await newSaltChannelAndHandshake(t, validateM1NoServSigKey)
    sc.setOnMessage(receiveZeroByte)

    receiveLastFlag()
	t.end();
});

test('stateAfterReceivedLastFlag', function (t) {
    t.ok(sc.getState() === 'closed', 'State not closed, state: ' + sc.getState())
	t.end();
});

test('sendLastFlag', async function (t) {
    await newSaltChannelAndHandshake(t, validateM1NoServSigKey)

    mockSocket.send = validateAppPacketWithLastFlag

    sendLastFlag()
	t.end();
});

test('stateAfterSentLastFlag', function (t) {
    t.ok(sc.getState() === 'closed', 'State not closed, state: ' + sc.getState())
	t.end();
});

test('withBadServSigKey', async function (t) {
    throws(await newSaltChannelAndHandshake(t, validateM1BadServSigKey, null, new Uint8Array(32)),
        'M2: NoSuchServer exception')
});

test('receiveBadHeaderEnc1', async function (t) {
    const errorMsg = 'EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was 1 0'
    badData = new Uint8Array([1, 0])

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey, errorMsg)
    receivebadHeaderEnc()
	t.end();
});

test('receiveBadHeaderEnc2', async function (t) {
    const errorMsg = 'EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was 6 2'
    badData = new Uint8Array([6, 2])

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey, errorMsg)
    receivebadHeaderEnc()
	t.end();
});

test('receiveBadHeaderApp1', async function (t) {
    const errorMsg = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 0 0'
    badData = new Uint8Array([0, 0])

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey, errorMsg)
    receivebadHeaderApp()
	t.end();
});

test('receiveBadHeaderApp2', async function (t) {
    const errorMsg = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 5 1'
    badData = new Uint8Array([5, 1])

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey, errorMsg)
    receivebadHeaderApp()
	t.end();
});

test('receiveBadHeaderApp3', async function (t) {
    const errorMsg = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 11 1'
    badData = new Uint8Array([11, 1])

    await newSaltChannelAndHandshake(t, validateM1NoServSigKey, errorMsg)
    receivebadHeaderApp()
	t.end();
});

test('receiveBadHeaderM21', async function (t) {
    const errorMsg = 'M2: Bad packet header. Expected 2 0 or 2 129, was 3 0'
    badData = new Uint8Array([3, 0])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM2, errorMsg),
        errorMsg)
	t.end();
});

test('receiveBadHeaderM22', async function (t) {
    const errorMsg = 'M2: Bad packet header. Expected 2 0 or 2 129, was 2 50'
    badData = new Uint8Array([2, 50])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM2, errorMsg),
        errorMsg)
	t.end();
});

test('receiveBadTimeM2', async function (t) {
    const errorMsg = 'M2: Invalid time value 20'
    badData = new Uint8Array([2, 0, 20])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM2, errorMsg),
        errorMsg)
	t.end();
});

test('receiveBadHeaderM31', async function (t) {
    const errorMsg = 'M3: Bad packet header. Expected 3 0, was 0 0'
    badData = new Uint8Array([0, 0])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM3, errorMsg),
        errorMsg)
	t.end();
});

test('receiveBadHeaderM32', async function (t) {
    const errorMsg = 'M3: Bad packet header. Expected 3 0, was 3 1'
    badData = new Uint8Array([3, 1])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM3, errorMsg),
        errorMsg)
	t.end();
});

test('receiveBadHeaderM33', async function (t) {
    const errorMsg = 'M3: ServerSigKey does not match expected'
    badData = new Uint8Array([3, 0, 20, 0, 0, 0, 12, 23, 34, 56])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM3, errorMsg, serverSigKeyPair.publicKey),
        errorMsg)
	t.end();
});

test('receiveBadHeaderM34', async function (t) {
    const errorMsg = 'M3: Could not verify signature'
    badData = new Uint8Array([3, 0, 20, 0, 0, 0, 12, 23, 34, 56])

    t.throws(await newSaltChannelAndHandshake(t, sendBadM3, errorMsg),
        errorMsg)
	t.end();
});

test('receiveBadPubEph', async function (t) {
    const errorMsg = 'EncryptedMessage: Could not decrypt message'
    t.throws(await newSaltChannelAndHandshake(t, sendBadEphM2, errorMsg),
        errorMsg)
	t.end();
});

async function newSaltChannelAndHandshake(t, validateM1, errorMsg, sigKey) {
    eNonce = new Uint8Array(nacl.secretbox.nonceLength)
    dNonce = new Uint8Array(nacl.secretbox.nonceLength)
    eNonce[0] = 2
    dNonce[0] = 1
    lastFlag = false

    mockSocket.send = validateM1
    mockSocket.readyState = 1

    sc = saltChannelSession(mockSocket, timeKeeper, timeChecker)
    sc.setOnError(function(err) {
        if (!errorMsg){
            t.equal(err.message, errorMsg, err.message)
        }
    })
    sc.setOnClose(doNothing)

    await sc.handshake(clientSigKeyPair, clientEphKeyPair, sigKey)
}

async function handshakeAfterError(t) {
    eNonce = new Uint8Array(nacl.secretbox.nonceLength)
    dNonce = new Uint8Array(nacl.secretbox.nonceLength)
    eNonce[0] = 2
    dNonce[0] = 1
    lastFlag = false

    const errorMsg = 'Handshake: Invalid internal state: closed'

    mockSocket.send = validateM1NoServSigKey

    sc.setOnHandshakeComplete(doNothing)

    t.throws(await sc.handshake(clientSigKeyPair, clientEphKeyPair),
        errorMsg)
}

function doNothing() {
    // Do nothing
}

function receiveAppPacket() {
    let appPacket = getAppPacket()
    let encrypted = encrypt(appPacket)

    sendOnMockSocket(encrypted)
}

function getAppPacket() {
    let appPacket = new Uint8Array(7)
    appPacket[0] = 5

    let time = new Int32Array([util.currentTimeMs() - sEpoch])
    time = new Uint8Array(time.buffer)

    appPacket.set(time, 2)

    return appPacket
}

function receiveZeroByte(t, message) {
    t.ok((message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    t.arrayEqual(new Uint8Array(message), new Uint8Array(1), 'Expected 1 zero byte, was ' + util.ab2hex(message));
}

function receiveMultiAppPacket() {
    let multiAppPacket = getMultiAppPacket()
    let encrypted = encrypt(multiAppPacket)

    sendOnMockSocket(encrypted)
}

function getMultiAppPacket() {
    let multiAppPacket = new Uint8Array(14)
    multiAppPacket[0] = 11  // Type

    multiAppPacket[6] = 2   // Count

    multiAppPacket[8] = 1   // Length

    multiAppPacket[11] = 1  // Length
    multiAppPacket[13] = 1  // Data

    let time = new Int32Array([util.currentTimeMs() - sEpoch])
    time = new Uint8Array(time.buffer)
    multiAppPacket.set(time, 2)

    return multiAppPacket
}

function receiveTwoAppPacketData(message) {
    if (!(message instanceof ArrayBuffer)) {
        outcome(false, '  Expected ArrayBuffer from Salt Channel')
        return
    }
    if (util.uint8ArrayEquals(new Uint8Array(message), new Uint8Array([multiAppPacketCount++]))) {
        if (multiAppPacketCount === 2 && !multiAppPacketFailed) {
            outcome(true);
        }
    } else {
        outcome(false, '  Expected 1 zero byte, was ' + util.buf2hex(message));
        multiAppPacketFailed = true
    }
}

function receiveBadEncryption() {
    if (sc.getState() !== 'ready') {
        outcome(false, 'Status: ' + sc.getState())
        return;
    }

    let appPacket = new Uint8Array(7)
    appPacket[0] = 5

    let time = new Int32Array([util.currentTimeMs() - sEpoch])
    time = new Uint8Array(time.buffer)

    appPacket.set(time, 2)

    let encrypted = encrypt(appPacket)

    encrypted[5] = 0
    encrypted[6] = 0
    encrypted[7] = 0

    sendOnMockSocket(encrypted)
}

function receiveDelayedPacket() {
    if (sc.getState() !== 'ready') {
        outcome(false, 'Status: ' + sc.getState())
        return;
    }

    let appPacket = getAppPacket()

    appPacket[2] = 2    // Time
    appPacket[3] = 0
    appPacket[4] = 0
    appPacket[5] = 0

    let encrypted = encrypt(appPacket)
    sendOnMockSocket(encrypted)
}

function receiveLastFlag() {
    let appPacket = getAppPacket()
    let encrypted = encrypt(appPacket, true)

    sendOnMockSocket(encrypted)
}

function sendLastFlag() {
    if (sc.getState() !== 'ready') {
        outcome(false, 'Status: ' + sc.getState())
        return
    }
    sc.send(true, new Uint8Array(1));
}

function receivebadHeaderEnc() {
    let appPacket = getAppPacket()
    let encrypted = encrypt(appPacket)
    encrypted.set(badData)

    sendOnMockSocket(encrypted)
}

function receivebadHeaderApp() {
    let appPacket = getAppPacket()
    appPacket.set(badData)
    let encrypted = encrypt(appPacket)

    sendOnMockSocket(encrypted)
}

// ==================================================================
// ==================================================================
// ==================================================================
// =================== SERVER SIDE HANDSHAKE CODE ===================
// ============================ (sorta) =============================

function validateM1NoServSigKey(t, message) {
    t.ok((message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    let m1 = new Uint8Array(message)

    t.equal( m1.length, 42, 'Bad packet length')

    let protocol = String.fromCharCode(...m1.slice(0,4))
    t.equal(protocol, 'SCv2', 'Bad protocol indicator')
    t.equal(m1[4], 1, 'Invalid packet type')
    t.equal(m1[5], 0, 'Unexpected server sig key included')
    t.arrayEqual(m1.slice(6, 10), [1, 0, 0, 0], 'M1: Expected time to be set: ' +util.ab2hex(m1.buffer))

    cEpoch = util.currentTimeMs()

    let publicEphemeral = m1.slice(10)
    t.arrayEqual(publicEphemeral, clientEphKeyPair.publicKey, 'Unexpected public ephemeral key from client')

    sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    m1Hash = nacl.hash(m1)
}

function validateM1WithServSigKey(t, message) {
    t.ok((message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    let m1 = new Uint8Array(message)

    t.equal( m1.length, 74, 'Bad packet length')

    let protocol = String.fromCharCode(...m1.slice(0, 4))
    t.equal(protocol, 'SCv2', 'Bad protocol indicator')
    t.equal(m1[4], 1, 'Invalid packet type')
    t.equal(m1[5], 1, 'Expected server sig key included')
    t.arrayEqual(m1.slice(6, 10), [1, 0, 0, 0], 'M1: Expected time to be set: ' +util.ab2hex(m1.buffer))

    cEpoch = util.currentTimeMs()

    let publicEphemeral = m1.slice(10, 42)
    t.arrayEqual( publicEphemeral, clientEphKeyPair.publicKey, 'Unexpected public ephemeral key from client')

    let serverSigKey = m1.slice(42, 74)
    t.arrayEqual( serverSigKey, serverSigKeyPair.publicKey, 'Expected server sig key from client')

    sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    m1Hash = nacl.hash(m1)
}

function validateM1BadServSigKey(message) {
    if (!(message instanceof ArrayBuffer)) {
        outcome(false, '  Expected ArrayBuffer from Salt Channel')
        return
    }
    let bytes = new Uint8Array(message)

    if (bytes.length !== 74) {
        outcome(false, '  Bad packet length, expected 42, was ' + bytes.length)
        return
    }

    let protocol = String.fromCharCode(...bytes.slice(0, 4))

    if (protocol !== 'SCv2') {
        outcome(false, '  Bad protocol indicator: ' + protocol)
        return
    }

    if (bytes[4] !== 1) {
        outcome(false, '  Invalid packet type, expected 1, was ' + bytes[4])
        return
    }

    if(bytes[5] !== 1) {
        outcome(false, '  Unexpected server sig key included, expected 1, was ' + bytes[5])
        return
    }

    if (!(bytes[6] === 1 && bytes[7] === 0 &&
        bytes[8] === 0 && bytes[9] === 0)) {
        outcome(false, '  M1: Expected time to be set')
        return
    }

    cEpoch = util.currentTimeMs()

    let publicEphemeral = new Uint8Array(bytes.buffer, 10, 32)

    if (!util.uint8ArrayEquals(publicEphemeral, clientEphKeyPair.publicKey)) {
        outcome(false, '  Unexpected public ephemeral key from client')
        return
    }

    let serverSigKey = new Uint8Array(bytes.buffer, 42, 32)
    if (!util.uint8ArrayEquals(serverSigKey, new Uint8Array(32))) {
        outcome(false, '  Unexpected server sig key from client')
        return
    }

    sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    m1Hash = nacl.hash(bytes)

    sendM2NoSuchServer()
}

function sendM2() {
    let m2 = new Uint8Array(38)

    m2[0] = 2

    // Time is supported
    m2[2] = 1

    for(let i = 0; i < 32; i++) {
        m2[6+i] = serverEphKeyPair.publicKey[i]
    }

    m2Hash = nacl.hash(m2)

    sEpoch = util.currentTimeMs()

    return m2;

    //sendOnMockSocket(m2)

    //sendM3()
}

function sendM2NoSuchServer() {
    let m2 = new Uint8Array(38)

    m2[0] = 2
    m2[1] = 129 // NoSuchServer & LastFlag
    // Time is supported
    m2[2] = 1

    sendOnMockSocket(m2)
}

function sendBadM2() {
    let m2 = new Uint8Array(38)

    m2.set(badData)

    for(let i = 0; i < 32; i++) {
        m2[6+i] = serverEphKeyPair.publicKey[i]
    }

    m2Hash = nacl.hash(m2)

    sEpoch = util.currentTimeMs()

    sendOnMockSocket(m2)
}

function sendBadEphM2(m1) {
    let publicEphemeral = new Uint8Array(m1, 10, 32)
    sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    let m2 = new Uint8Array(38)
    m2[0] = 2
    m2[2] = 1
    m2.set(serverEphKeyPair.publicKey, 6)
    m2[6] = 0

    m2Hash = nacl.hash(m2)

    sEpoch = util.currentTimeMs()

    sendOnMockSocket(m2)

    sendM3()
}

function sendOnMockSocket(data) {
    mockSocket.onmessage({data: data.buffer})
}

function sendM3() {
    let m3 = new Uint8Array(102)

    m3[0] = 3

    for (let i = 0; i < 32; i++) {
        m3[6+i] = serverSigKeyPair.publicKey[i]
    }

    let concat = getConcat(sigBytes1)

    let signature = nacl.sign.detached(concat, serverSigKeyPair.secretKey)

    for (let i = 0; i < 64; i++) {
        m3[38+i] = signature[i]
    }

    let time = new Int32Array([util.currentTimeMs() - sEpoch])
    time = new Uint8Array(time.buffer)

    m3[2] = time[0]
    m3[3] = time[1]
    m3[4] = time[2]
    m3[5] = time[3]

    mockSocket.send = validateM4

    let encrypted = encrypt(m3)
    return encrypted
    //sendOnMockSocket(encrypted)
}

function sendBadM3() {
    let m2 = new Uint8Array(38)
    m2[0] = 2
    m2[2] = 1
    for(let i = 0; i < 32; i++) {
        m2[6+i] = serverEphKeyPair.publicKey[i]
    }

    sendOnMockSocket(m2)

    let m3 = new Uint8Array(102)
    m3.set(badData)

    let encrypted = encrypt(m3)
    sendOnMockSocket(encrypted)
}

function validateM4(t, message) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')

    let encryptedMessage = new Uint8Array(message)
    let m4 = decrypt(encryptedMessage)

    t.ok(!util.isString(m4), m4)

    t.equal(m4[0], 4, 'M4: Bad packet type, expected 4, was ' + m4[0])

    t.equal(m4[1], 0, 'M4: Bad packet header, expected 0, was ' + m4[1])

    t.ok(!(m4[2] === 0 && m4[3] === 0 && m4[4] === 0 && m4[5] === 0), 'M4: Expected time to be set')

    let time = new Uint8Array(4)
    time[0] = m4[2]
    time[1] = m4[3]
    time[2] = m4[4]
    time[3] = m4[5]

    time = (new Int32Array(time.buffer))[0]

    t.ok(!(util.currentTimeMs() - cEpoch > time + threshold ), 'M4: Delayed packet')

    let clientSigKey = new Uint8Array(32)
    for (let i = 0; i < 32; i++) {
        clientSigKey[i] = m4[6+i]
    }

    t.arrayEqual(clientSigKey, clientSigKeyPair.publicKey, 'Client signing key does not match expected')

    let signature = new Uint8Array(64)
    for (let i = 0; i < 64; i++) {
        signature[i] = m4[38+i]
    }

    let concat = getConcat(sigBytes2)

    let success = nacl.sign.detached.verify(concat, signature, clientSigKey)

    t.ok(success, 'Could not verify signature')
}

// ==================================================================
// ==================================================================
// ==================================================================
// ========================== CRYPTO STUFF ==========================
// ==================================================================

function decrypt(message) {
    if (message[0] === 6 && message[1] === 0) {

    } else if (message[0] === 6 && message[1] === 128) {
        lastFlag = true
    } else {
        return '  EncryptedMessage: Bad packet header, was  ' +
                + message[0] + ' ' + message[1]
    }

    let bytes = new Uint8Array(message.byteLength - 2)
    let msg = new Uint8Array(message)

    for (let i = 0; i < message.byteLength - 2; i++) {
        bytes[i] = msg[i+2]
    }

    let clear = nacl.secretbox.open(bytes, dNonce, sessionKey)
    dNonce = increaseNonce2(dNonce)

    if (clear === false) {
        return '  EncryptedMessage: Failed to decrypt'
    }

    let copy = new Uint8Array(clear.length)
    for (let i = 0; i < copy.length; i++) {
        copy[i] = clear[i]
    }
    return copy
}

function encrypt(clearBytes, last = false) {
    let body = nacl.secretbox(clearBytes, eNonce, sessionKey)
    eNonce = increaseNonce2(eNonce)

    let encryptedMessage = new Uint8Array(body.length + 2)
    encryptedMessage[0] = 6
    encryptedMessage[1] = last ? 128 : 0

    for (let i = 0; i < body.length; i++) {
        encryptedMessage[2+i] = body[i]
    }

    return encryptedMessage
}

function getConcat(sigBytes) {
    let concat = new Uint8Array(2*nacl.hash.hashLength + 8)
    for (let i = 0; i < 8; i++) {
        concat[i] = sigBytes[i]
    }
    for (let i = 0; i < nacl.hash.hashLength; i++) {
        concat[8+i] = m1Hash[i]
        concat[8+i+nacl.hash.hashLength] = m2Hash[i]
    }

    return concat
}

function increaseNonce(nonce) {
    if (!(nonce instanceof Uint8Array)) {
        throw new Error('Expected Uint8Array. \n\t' +
                    'Input: ' + nonce)
    }
    if (!(nonce.length === nacl.secretbox.nonceLength)) {
        throw new Error('Unexpected nonce length. \n\t' +
                    'Length: ' + nonce.length)
    }
    nonce[0] += 1 // nonces are little endian
    for (let i = 0; i < 7; i++) {
        if (nonce[i] === 0) {
            nonce[i+1] += 1
        } else {
            break
        }
    }
    return nonce
}


function increaseNonce2(nonce) {
    nonce = increaseNonce(nonce)
    nonce = increaseNonce(nonce)
    return nonce
}

// ==================================================================
// ==================================================================
// ==================================================================

function validateAppPacket(t, message) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')

    let encryptedMessage = new Uint8Array(message)
    let appPacket = decrypt(encryptedMessage)

    t.equal(appPacket.length, 7, 'Expected AppPacket.length');

    t.equal(appPacket[0], 5, 'Expected AppPacket type');
    t.equal(appPacket[1], 0, 'Expected zero byte')

    let time = new Uint8Array(4)
    time[0] = appPacket[2]
    time[1] = appPacket[3]
    time[2] = appPacket[4]
    time[3] = appPacket[5]

    time = (new Int32Array(time.buffer))[0]

    t.ok(!(util.currentTimeMs() - cEpoch > time + threshold), 'AppPacket delayed')

    t.equal(appPacket[6], 0, 'Unexpected data')
}

function validateMultiAppPacket(t, message) {
     t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    let encryptedMessage = new Uint8Array(message)
    let multiAppPacket = decrypt(encryptedMessage)

    t.equal(multiAppPacket.length, 14, 'Expected MultiAppPacket.length 14, was ' + multiAppPacket.length)
    t.equal(multiAppPacket[0], 11, 'Expected MultiAppPacket type, was ' + multiAppPacket[0])
    t.equal(multiAppPacket[1], 0, 'Expected zero byte, was ' + multiAppPacket[1])

    let time = multiAppPacket.slice(2,6)
    time = (new Int32Array(time.buffer))[0]

    t.ok(!(util.currentTimeMs() - cEpoch > time + threshold), 'AppPacket delayed')

    t.arrayEqual(multiAppPacket.slice(6, 8), [2, 0], 'Unexpected count, expected 2 0, was ' +
                multiAppPacket[6] + ' ' + multiAppPacket[7])
    t.arrayEqual(multiAppPacket.slice(8, 10), [1, 0], 'Unexpected length, expected 1 0, was ' +
            multiAppPacket[8] + ' ' + multiAppPacket[9])

    t.equal(multiAppPacket[10], 0, 'Unexpected data, expected 0, was ' + multiAppPacket[10])

    t.arrayEqual(multiAppPacket.slice(11, 13), [1, 0], 'Unexpected length, expected 1 0, was ' +
            multiAppPacket[11] + ' ' + multiAppPacket[12])

    t.equal(multiAppPacket[13], 1, 'Unexpected data, expected 1, was ' + multiAppPacket[13])
}

function validateBigMultiAppPacket(t, message) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    let encryptedMessage = new Uint8Array(message)
    let multiAppPacket = decrypt(encryptedMessage)

    t.equal(multiAppPacket.length, bigPayload.length + 13, 'Expected MultiAppPacket.length ' + (bigPayload.length + 13) + ', was ' + multiAppPacket.length)

    t.arrayEqual(multiAppPacket.slice(6, 8), [2, 0], 'Unexpected count, expected 2 0, was ' +
                multiAppPacket[6] + ' ' + multiAppPacket[7])
    t.arrayEqual(multiAppPacket.slice(8, 10), [1, 0], 'Unexpected length, expected 1 0, was ' +
            multiAppPacket[8] + ' ' + multiAppPacket[9])

    t.equal(multiAppPacket[10], 0, 'Unexpected data, expected 0, was ' + multiAppPacket[10])

    let packetLength = new Uint8Array(2)
    let view = new DataView(packetLength.buffer);
    view.setUint16(0, bigPayload.length, true);

    t.arrayEqual( multiAppPacket.slice(11, 13), packetLength, 'Unexpected length, expected ' + packetLength[0] + ' ' + packetLength[1] + ', was ' +
            multiAppPacket[11] + ' ' + multiAppPacket[12])

    let payload = multiAppPacket.slice(13)

    t.arrayEqual( payload, bigPayload, 'Unexpected data, expected ' + util.ab2hex(bigPayload.buffer) + ', was ' + util.ab2hex(payload.buffer))
}

function validateAppPacketWithLastFlag(message) {
    if (!(message instanceof ArrayBuffer)) {
        outcome(false, '  Expected ArrayBuffer from Salt Channel')
        return
    }
    let encryptedMessage = new Uint8Array(message)
    let appPacket = decrypt(encryptedMessage)

    if (appPacket.length !== 7) {
        outcome(false, '  Expected AppPacket.length 7, was ' + appPacket.length)
        return
    }
    if (appPacket[0] !== 5) {
        outcome(false, ' Expected AppPacket type, was ' + appPacket[0])
        return
    }
    if (appPacket[1] !== 0) {
        outcome(false, '  Expected zero byte, was ' + appPacket[1])
        return
    }

    let time = new Uint8Array(4)
    time[0] = appPacket[2]
    time[1] = appPacket[3]
    time[2] = appPacket[4]
    time[3] = appPacket[5]

    time = (new Int32Array(time.buffer))[0]

    if (util.currentTimeMs() - cEpoch > time + threshold ) {
        outcome(false, '  AppPacket delayed')
        return
    }

    if (appPacket[6] !== 0) {
        outcome(false, '  Unexpected data, expected 0, was ' + appPacket[6])
        return
    }

    if (lastFlag) {
        outcome(true)
    } else {
        outcome(false, '  Expected lastFlag to have been set')
    }
}

async function  standardHandshake(t){
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    sc.setOnError(function(err) {
        t.fail('Got error: '+err)
    })
    sc.setOnClose(doNothing)

    let serverPromise = testServerSide(t, testInterface, validateM1NoServSigKey)

    await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined);

    t.equal(sc.getState(), 'ready', 'State is OPEN')

    await serverPromise;

    return [sc, testInterface]
}

function outcome(success, msg) {
    if (success) {
        passCount++
        //console.log(testCount + '. ' + currentTest + ' PASSED')
    } else {
        console.log(testCount + '. ' + currentTest + ' FAILED! \n' + msg)
    }
}
