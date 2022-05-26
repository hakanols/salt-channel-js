import saltChannelSession from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import getTimeChecker from '../src/time/typical-time-checker.js';
import test from './tap-esm.js'

const clientSecret =
    util.hex2ab('fd2956eb37782aabddc97eaf3b9e1b075f4976770db56c11e866e8763fa073d8' +
                '9cace2ed6af2e108bbabc69c0bb7f3e62a4c0bf59ac2296811a09e480bf7b0f7')
const clientSigKeyPair = nacl.sign.keyPair.fromSecretKey(clientSecret)
const clientEphKeyPair = {
    publicKey: util.hex2ab('159205ede53fe5334eaf26f15f80710453b6600e6df5c96bfb85dd593c86cf4f'),
    secretKey: util.hex2ab('e9f639ffd6cc1c1edd5ba28e0aecbbe15ad88478dbfcebc09ad80300880a3fa2')
}

const serverSecret =
    util.hex2ab('7a772fa9014b423300076a2ff646463952f141e2aa8d98263c690c0d72eed52d' +
                '07e28d4ee32bfdc4b07d41c92193c0c25ee6b3094c6296f373413b373d36168b')
const serverSigKeyPair = nacl.sign.keyPair.fromSecretKey(serverSecret)
const serverEphKeyPair = {
    publicKey: util.hex2ab('354200647ecfbcb1d5feeb7b2f59127fe1278ab4a632b505691f9a2f6a465065'),
    secretKey: util.hex2ab('942d5f9bb23b8380ce9a86ae52600ec675b922b64b1b294c8f94c44255a26fe0')
}

const SIG_STR_1 = 'SC-SIG01'
const SIG_STR_2 = 'SC-SIG02'
const sigBytes1 = [...SIG_STR_1].map(letter=>letter.charCodeAt(0))
const sigBytes2 = [...SIG_STR_2].map(letter=>letter.charCodeAt(0))

const bigPayload = util.hex2ab('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' +
    'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbcccccccccccccccccccccccccccccccccccccccc' +
    'ddddddddddddddddddddddddddddddddddddddddeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee' +
    'ffffffffffffffffffffffffffffffffffffffff0000000000000000000000000000000000000000' +
    '11111111111111111111111111111111111111112222222222222222222222222222222222222222' +
    '33333333333333333333333333333333333333334444444444444444444444444444444444444444' +
    '55555555555555555555555555555555555555556666666666666666666666666666666666666666' +
    '77777777777777777777777777777777777777778888888888888888888888888888888888888888' +
    '9999999999999999999999999999999999999999ffffffffffffffffffffffffffffffffffffffff')

//////////////////////////////////////////////////////////////////////////////////////////////
    
let serverData;

let cEpoch
let sEpoch
let threshold

//////////////////////////////////////////////////////////////////////////////////////////////

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
    serverData = createServerData();

    let m1 = await testInterface.receive(1000)
    validateM1(t, m1)
    testInterface.send(createM2())
    testInterface.send(createM3())
    let m4 = await testInterface.receive(1000)
    validateM4(t, m4)
}

function createErrorWaiter(sc){
    let errorQueue = util.waitQueue();
    sc.setOnError(function(err) {
        errorQueue.push(err.message);
    })
    return async function(waitTime){
        return (await errorQueue.pull(waitTime))[0];
    }
}

function createServerData(){
    let eNonce = new Uint8Array(nacl.secretbox.nonceLength)
    let dNonce = new Uint8Array(nacl.secretbox.nonceLength)
    eNonce[0] = 2
    dNonce[0] = 1
    let sessionKey;

    return {
        eNonce: eNonce,
        dNonce: dNonce,
        sessionKey: sessionKey
    }
}

//////////////////////////////////////////////////////////////////////////////////////////////

test('minimal', async function (t) {
    await standardHandshake(t)
	t.end();
});

test('withServSigKey', async function (t) {
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    sc.setOnError(function(err) {
        t.fail('Got error: '+err)
    })
    sc.setOnClose(doNothing)

    let serverPromise = testServerSide(t, testInterface, function(t,m1){validateM1WithServSigKey(t,m1,clientEphKeyPair.publicKey,serverSigKeyPair.publicKey)})

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
    t.ok((message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    t.arrayEqual(new Uint8Array(message), new Uint8Array(1), 'Expected 1 zero byte, was ' + util.ab2hex(message));

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
    let [sc, testInterface] = await standardHandshake(t)

    let multiAppPacket = getMultiAppPacket()
    let encrypted = encrypt(multiAppPacket)
    testInterface.send(encrypted)

    let multiApp1 = await sc.receive(1000)
    let multiApp2 = await sc.receive(1000)

    t.ok((multiApp1 instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    t.arrayEqual(new Uint8Array(multiApp1), new Uint8Array([0]), 'Unexpected data')

    t.ok((multiApp2 instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    t.arrayEqual(new Uint8Array(multiApp2), new Uint8Array([1]), 'Unexpected data')

	t.end();
});

test('receiveBadEncryption', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);
    let errorWaiter = createErrorWaiter(sc);

    let appPacket1 = new Uint8Array(7)
    appPacket1[0] = 5

    let time = new Int32Array([util.currentTimeMs() - sEpoch])
    time = new Uint8Array(time.buffer)

    appPacket1.set(time, 2)

    let encrypted1 = encrypt(appPacket1)

    encrypted1[5] = 0
    encrypted1[6] = 0
    encrypted1[7] = 0

    testInterface.send(encrypted1)

    let receivedError1 = await errorWaiter(1000) 
    const errorMsg1 = 'EncryptedMessage: Could not decrypt message'   
    t.equal(receivedError1, errorMsg1, "Expect error")

    console.log('receiveAfterError')
    let appPacket2 = getAppPacket()
    let encrypted2 = encrypt(appPacket2)
    testInterface.send(encrypted2)

    let receivedError2 = await errorWaiter(1000) 
    const errorMsg2 = 'Received message when salt channel was not ready' 
    t.equal(receivedError2, errorMsg2, "Expect error")

	t.end();
});

test('receiveDelayed', async function (t) {
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let timeChecker = getTimeChecker(util.currentTimeMs, 10)
    let sc = saltChannelSession(mockSocketInterface, undefined, timeChecker)
    let errorWaiter = createErrorWaiter(sc);

    sc.setOnClose(doNothing)

    let serverPromise = testServerSide(t, testInterface, validateM1NoServSigKey)

    await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined);

    t.equal(sc.getState(), 'ready', 'State is OPEN')

    await serverPromise;

    threshold = 20

    let appPacket = getAppPacket()
    appPacket[2] = 2    // Time
    appPacket[3] = 0
    appPacket[4] = 0
    appPacket[5] = 0
    let encrypted = encrypt(appPacket)
    testInterface.send(encrypted)

    let receivedError1 = await errorWaiter(1000) 
    const errorMsg1 = '(Multi)AppPacket: Detected a delayed packet'
    t.equal(receivedError1, errorMsg1, "Expect error")

    console.log('handShakeAfterError')
    serverData = createServerData();

    const errorMsg2 = 'Handshake: Invalid internal state: closed'
    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair)
    }, errorMsg2)
    let receivedError2 = await errorWaiter(1000)
    t.equal(receivedError2, errorMsg2, "Expect error")
    
	t.end();
});

test('receiveLastFlag', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);

    let appPacket = getAppPacket()
    let encrypted = encrypt(appPacket, true)
    testInterface.send(encrypted)

    let message = await sc.receive(1000)
    t.ok((message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    t.arrayEqual(new Uint8Array(message), new Uint8Array(1), 'Expected 1 zero byte, was ' + util.ab2hex(message));

    console.log('stateAfterReceivedLastFlag')
    t.equal(sc.getState(), 'closed', 'State not closed')
	t.end();
});

test('sendLastFlag', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);

    sc.send(true, new Uint8Array(1));

    let message = await testInterface.receive(1000)
    validateAppPacketWithLastFlag(t, message)

	console.log('stateAfterSentLastFlag')
    t.equal(sc.getState(), 'closed', 'State not closed')
	t.end();
});

test('withBadServSigKey', async function (t) {
    let m2 = new Uint8Array(38)
    m2[0] = 2
    m2[1] = 129 // NoSuchServer & LastFlag
    // Time is supported
    m2[2] = 1
    const expectedError = 'M2: NoSuchServer exception'
    await testBadM2(t, m2,  new Uint8Array(32), expectedError)
    t.end();
});

test('receiveBadHeaderEnc1', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);
    let errorWaiter = createErrorWaiter(sc);
    const expectedError = 'EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was 1 0' 
    const badData = new Uint8Array([1, 0])
    testInterface.send(createBadHeaderEnc(badData))
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")
	t.end();
});

test('receiveBadHeaderEnc2', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);
    let errorWaiter = createErrorWaiter(sc);
    const expectedError = 'EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was 6 2'
    const badData = new Uint8Array([6, 2])
    testInterface.send(createBadHeaderEnc(badData))
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")
	t.end();
});

test('receiveBadHeaderApp1', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);
    let errorWaiter = createErrorWaiter(sc);
    const expectedError = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 0 0'
    const badData = new Uint8Array([0, 0])
    testInterface.send(createBadHeaderApp(badData))
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")
	t.end();
});

test('receiveBadHeaderApp2', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);
    let errorWaiter = createErrorWaiter(sc);
    const expectedError = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 5 1'
    const badData = new Uint8Array([5, 1])
    testInterface.send(createBadHeaderApp(badData))
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")
	t.end();
});

test('receiveBadHeaderApp3', async function (t) {
    let [sc, testInterface] = await standardHandshake(t);
    let errorWaiter = createErrorWaiter(sc);
    const expectedError = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 11 1'
    const badData = new Uint8Array([11, 1])
    testInterface.send(createBadHeaderApp(badData))
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")
	t.end();
});

test('receiveBadHeaderM21', async function (t) {
    const expectedError = 'M2: Bad packet header. Expected 2 0 or 2 129, was 3 0'
    const badData = new Uint8Array([3, 0])
    const m2 = createBadM2(badData)
    await testBadM2(t, m2, undefined, expectedError)
	t.end();
});

test('receiveBadHeaderM22', async function (t) {
    const expectedError = 'M2: Bad packet header. Expected 2 0 or 2 129, was 2 50'
    const badData = new Uint8Array([2, 50])
    const m2 = createBadM2(badData)
    await testBadM2(t, m2, undefined, expectedError)
	t.end();
});

test('receiveBadTimeM2', async function (t) {
    const expectedError = 'M2: Invalid time value 20'
    const badData = new Uint8Array([2, 0, 20])
    const m2 = createBadM2(badData)
    await testBadM2(t, m2, undefined, expectedError)
	t.end();
});

test('receiveBadHeaderM31', async function (t) {
    const expectedError = 'M3: Bad packet header. Expected 3 0, was 0 0'
    const badData = new Uint8Array([0, 0])
    const [m2, m3] = createBadM3(badData)
    await testBadM3(t, m2, m3, undefined, expectedError)
	t.end();
});

test('receiveBadHeaderM32', async function (t) {
    const expectedError = 'M3: Bad packet header. Expected 3 0, was 3 1'
    const badData = new Uint8Array([3, 1])
    const [m2, m3] = createBadM3(badData)
    await testBadM3(t, m2, m3, undefined, expectedError)
	t.end();
});

test('receiveBadHeaderM33', async function (t) {
    const expectedError = 'M3: ServerSigKey does not match expected'
    const badData = new Uint8Array([3, 0, 20, 0, 0, 0, 12, 23, 34, 56])
    const [m2, m3] = createBadM3(badData)
    await testBadM3(t, m2, m3, serverSigKeyPair.publicKey, expectedError)
	t.end();
});

test('receiveBadHeaderM34', async function (t) {
    const expectedError = 'M3: Could not verify signature'
    const badData = new Uint8Array([3, 0, 20, 0, 0, 0, 12, 23, 34, 56])
    const [m2, m3] = createBadM3(badData)
    await testBadM3(t, m2, m3, undefined, expectedError)
	t.end();
});

test('receiveBadPubEph', async function (t) {
    const expectedError = 'EncryptedMessage: Could not decrypt message'

    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    let errorWaiter = createErrorWaiter(sc);
    sc.setOnClose(doNothing)

    let serverPromise = async function(){
        serverData = createServerData();
        let m1 = await testInterface.receive(1000)
        // Skip validating of m1
        testInterface.send(createBadEphM2(m1))
        testInterface.send(createM3())
    }()

    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined)
    }, expectedError)
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")

    await serverPromise
	t.end();
});

function doNothing() {
    // Do nothing
}

function getAppPacket() {
    let appPacket = new Uint8Array(7)
    appPacket[0] = 5

    let time = new Int32Array([util.currentTimeMs() - sEpoch])
    time = new Uint8Array(time.buffer)

    appPacket.set(time, 2)

    return appPacket
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

function createBadHeaderEnc(badData) {
    let appPacket = getAppPacket()
    let encrypted = encrypt(appPacket)
    encrypted.set(badData)
    return encrypted
}

function createBadHeaderApp(badData) {
    let appPacket = getAppPacket()
    appPacket.set(badData)
    let encrypted = encrypt(appPacket)
    return encrypted
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

    serverData.sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    serverData.m1Hash = nacl.hash(m1)
}

function validateM1WithServSigKey(t, message, expectedEphKey, expectedServKey) {
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
    t.arrayEqual( publicEphemeral, expectedEphKey, 'Unexpected public ephemeral key from client')

    let serverSigKey = m1.slice(42, 74)
    t.arrayEqual( serverSigKey, expectedServKey, 'Expected server sig key from client')

    serverData.sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    serverData.m1Hash = nacl.hash(m1)
}

function createM2() {
    let m2 = new Uint8Array(38)

    m2[0] = 2

    // Time is supported
    m2[2] = 1

    for(let i = 0; i < 32; i++) {
        m2[6+i] = serverEphKeyPair.publicKey[i]
    }

    serverData.m2Hash = nacl.hash(m2)

    sEpoch = util.currentTimeMs()

    return m2;
}

function createBadM2(badData) {
    let m2 = new Uint8Array(38)

    m2.set(badData)

    for(let i = 0; i < 32; i++) {
        m2[6+i] = serverEphKeyPair.publicKey[i]
    }

    serverData.m2Hash = nacl.hash(m2)

    sEpoch = util.currentTimeMs()

    return m2
}

function createBadEphM2(m1) {
    let publicEphemeral = new Uint8Array(m1, 10, 32)
    serverData.sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    let m2 = new Uint8Array(38)
    m2[0] = 2
    m2[2] = 1
    m2.set(serverEphKeyPair.publicKey, 6)
    m2[6] = 0
    serverData.m1Hash = nacl.hash(new Uint8Array(m1))
    serverData.m2Hash = nacl.hash(m2)

    sEpoch = util.currentTimeMs()

    return m2
}

function createM3() {
    let m3 = new Uint8Array(102)

    m3[0] = 3

    for (let i = 0; i < 32; i++) {
        m3[6+i] = serverSigKeyPair.publicKey[i]
    }

    let concat = new Uint8Array([...sigBytes1, ...serverData.m1Hash, ...serverData.m2Hash])

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

    let encrypted = encrypt(m3)
    return encrypted
}

function createBadM3(badData) {
    serverData = createServerData();
    serverData.sessionKey = new Uint8Array([
        223, 248,  72,  68, 244,  41, 255,  27,
         32, 180, 231, 197,   4, 130, 135,  46,
        253,  65, 203, 210, 125, 183, 210, 233,
         62, 156, 211,  97,  17, 254, 141, 237
    ])

    let m2 = new Uint8Array(38)
    m2[0] = 2
    m2[2] = 1
    for(let i = 0; i < 32; i++) {
        m2[6+i] = serverEphKeyPair.publicKey[i]
    }

    let m3 = new Uint8Array(102)
    m3.set(badData)
    let encrypted = encrypt(m3)

    return [m2, encrypted]
}

function validateM4(t, message) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')

    let encryptedMessage = new Uint8Array(message)
    let m4 = decrypt(encryptedMessage).data

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

    let concat = new Uint8Array([...sigBytes2, ...serverData.m1Hash, ...serverData.m2Hash])

    let success = nacl.sign.detached.verify(concat, signature, clientSigKey)

    t.ok(success, 'Could not verify signature')
}

// ==================================================================
// ==================================================================
// ==================================================================
// ========================== CRYPTO STUFF ==========================
// ==================================================================

function decrypt(message) {
    let lastFlag
    if (message[0] === 6 && message[1] === 0) {
        lastFlag = false
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

    let clear = nacl.secretbox.open(bytes, serverData.dNonce, serverData.sessionKey)
    serverData.dNonce = increaseNonce2(serverData.dNonce)

    if (clear === false) {
        return '  EncryptedMessage: Failed to decrypt'
    }

    let copy = new Uint8Array(clear.length)
    for (let i = 0; i < copy.length; i++) {
        copy[i] = clear[i]
    }
    return {
        data: copy,
        last: lastFlag
    }
}

function encrypt(clearBytes, last = false) {
    let body = nacl.secretbox(clearBytes, serverData.eNonce, serverData.sessionKey)
    serverData.eNonce = increaseNonce2(serverData.eNonce)

    let encryptedMessage = new Uint8Array(body.length + 2)
    encryptedMessage[0] = 6
    encryptedMessage[1] = last ? 128 : 0

    for (let i = 0; i < body.length; i++) {
        encryptedMessage[2+i] = body[i]
    }

    return encryptedMessage
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
    let appPacket = decrypt(encryptedMessage).data

    t.equal(appPacket.length, 7, 'Expected message length');

    t.equal(appPacket[0], 5, 'Expected AppPacket type');
    t.equal(appPacket[1], 0, 'Expected zero byte')

    let time = appPacket.slice(2,6)
    time = (new Int32Array(time.buffer))[0]

    t.ok(!(util.currentTimeMs() - cEpoch > time + threshold), 'AppPacket delayed')

    t.equal(appPacket[6], 0, 'Unexpected data')
}

function validateMultiAppPacket(t, message) {
     t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    let encryptedMessage = new Uint8Array(message)
    let multiAppPacket = decrypt(encryptedMessage).data

    t.equal(multiAppPacket.length, 14, 'Expected message length')
    t.equal(multiAppPacket[0], 11, 'Expected MultiAppPacket type, was ' + multiAppPacket[0])
    t.equal(multiAppPacket[1], 0, 'Expected zero byte, was ' + multiAppPacket[1])

    let time = multiAppPacket.slice(2,6)
    time = (new Int32Array(time.buffer))[0]

    t.ok(!(util.currentTimeMs() - cEpoch > time + threshold), 'AppPacket delayed')

    t.arrayEqual(multiAppPacket.slice(6, 8), [2, 0], 'Unexpected count')
    t.arrayEqual(multiAppPacket.slice(8, 10), [1, 0], 'Unexpected length')

    t.equal(multiAppPacket[10], 0, 'Unexpected data, expected 0, was ' + multiAppPacket[10])

    t.arrayEqual(multiAppPacket.slice(11, 13), [1, 0], 'Unexpected length, expected 1 0, was ' +
            multiAppPacket[11] + ' ' + multiAppPacket[12])

    t.equal(multiAppPacket[13], 1, 'Unexpected data, expected 1, was ' + multiAppPacket[13])
}

function validateBigMultiAppPacket(t, message) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    let encryptedMessage = new Uint8Array(message)
    let multiAppPacket = decrypt(encryptedMessage).data

    t.equal(multiAppPacket.length, bigPayload.length + 13, 'Expected message length')

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

function validateAppPacketWithLastFlag(t, message) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    let encryptedMessage = new Uint8Array(message)

    let {data, last} = decrypt(encryptedMessage)

    t.equal(data.length, 7, 'Expected message length')
    t.equal(data[0], 5, 'Expected MultiAppPacket type')
    t.equal(data[1], 0, 'Expected zero byte')

    let time = data.slice(2,6)
    time = (new Int32Array(time.buffer))[0]

    t.ok(!(util.currentTimeMs() - cEpoch > time + threshold), 'AppPacket delayed')
    t.arrayEqual(data[6], 0, 'Unexpected data')

    t.ok(last, 'Last message')
}

async function  standardHandshake(t){
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    sc.setOnError(function(err) {
        t.fail('Got error: '+err.message)
    })
    sc.setOnClose(doNothing)

    let serverPromise = testServerSide(t, testInterface, validateM1NoServSigKey)

    await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined);

    t.equal(sc.getState(), 'ready', 'State is OPEN')

    await serverPromise;

    return [sc, testInterface]
}

async function testBadM2(t, m2, sigKey, expectedError){
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    let errorWaiter = createErrorWaiter(sc);
    sc.setOnClose(doNothing)

    let serverPromise = async function(){
        serverData = createServerData();
        await testInterface.receive(1000)
        // Skip validating of m1
        testInterface.send(m2)
    }()

    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair, sigKey)
    }, expectedError)
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")

    await serverPromise
}

async function testBadM3(t, m2, m3, sigKey, expectedError){
    let [mockSocketInterface, testInterface] = createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)
    let errorWaiter = createErrorWaiter(sc);
    sc.setOnClose(doNothing)

    let serverPromise = async function(){
        serverData = createServerData();
        await testInterface.receive(1000)
        // Skip validating of m1
        testInterface.send(m2)
        testInterface.send(m3)
    }()

    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair, sigKey)
    }, expectedError)
    let receivedError = await errorWaiter(1000)
    t.equal(receivedError, expectedError, "Expect error")

    await serverPromise
}