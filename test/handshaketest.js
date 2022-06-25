import saltChannelSession from '../src/saltchannel.js';
import * as util from '../lib/util.js';
import nacl from '../lib/nacl-fast-es.js';
import getTimeChecker from '../src/time/typical-time-checker.js';
import test from './tap-esm.js'
import * as misc from './misc.js'

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

const PacketTypeM1  = 1
const PacketTypeM2  = 2
const PacketTypeM3  = 3
const PacketTypeM4  = 4
const PacketTypeApp = 5
const PacketTypeEncrypted = 6
const PacketTypeMultiApp = 11

//////////////////////////////////////////////////////////////////////////////////////////////

test('minimal', async function (t) {
    await standardHandshake(t)
	t.end();
});

test('withServSigKey', async function (t) {
    let [mockSocketInterface, testInterface] = misc.createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)

    let serverPromise = testServerSide(t, testInterface, clientEphKeyPair.publicKey, serverSigKeyPair.publicKey)

    let channel = await sc.handshake(clientSigKeyPair, clientEphKeyPair, serverSigKeyPair.publicKey);

    t.equal(channel.getState(), 'ready', 'State is OPEN')

    await serverPromise;

	t.end();
});

test('sendAppPacket1', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    channel.send(false, new Uint8Array([0]).buffer)
    let app1 = await testInterface.receive(1000)
    validateAppPacket(t, testInterface.serverData, app1, new Uint8Array([0]), false)

	t.end();
});

test('sendAppPacket2', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    let data = [new Uint8Array([0])]
    channel.send(false, data)
    let app2 = await testInterface.receive(1000)
    validateAppPacket(t, testInterface.serverData, app2, [0], false)

	t.end();
});

test('receiveAppPacket', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    let appPacket = createAppPacket(testInterface.serverData, [0])
    let encrypted = encrypt(testInterface.serverData, appPacket)
    testInterface.send(encrypted)

    let event = await channel.receive(1000)
    t.ok((event.message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    t.arrayEqual(new Uint8Array(event.message), new Uint8Array(1), 'Unexpected data')
    t.notOk(event.close,'Expected open');

	t.end();
});

test('sendMultiAppPacket1', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    let data = [new Uint8Array([0]).buffer, new Uint8Array([1])]
    channel.send(false, data)
    let multiApp = await testInterface.receive(1000)
    validateMultiAppPacket(t, testInterface.serverData, multiApp, data, false)
	t.end();
});

test('sendMultiAppPacket2', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    let data = [new Uint8Array([0]), new Uint8Array([1]).buffer]
    channel.send(false, data)
    let multiApp = await testInterface.receive(1000)
    validateMultiAppPacket(t, testInterface.serverData, multiApp, data, false)
	t.end();
});

test('testSendBigMultiAppPacket', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    let data = [new Uint8Array([0]), bigPayload]
    channel.send(false, data)
    let multiApp = await testInterface.receive(1000)
    validateMultiAppPacket(t, testInterface.serverData, multiApp, data, false)
	t.end();
});

test('receiveMultiAppPacket', async function (t) {
    let [channel, testInterface] = await standardHandshake(t)

    let multiAppPacket = createMultiAppPacket(testInterface.serverData, [[0], [1]])
    let encrypted = encrypt(testInterface.serverData, multiAppPacket)
    testInterface.send(encrypted)

    let event1 = await channel.receive(1000)
    let event2 = await channel.receive(1000)

    t.ok((event1.message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    t.arrayEqual(new Uint8Array(event1.message), new Uint8Array([0]), 'Unexpected data')
    t.notOk(event1.close,'Expected open');

    t.ok((event2.message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')
    t.arrayEqual(new Uint8Array(event2.message), new Uint8Array([1]), 'Unexpected data')
    t.notOk(event2.close,'Expected open');

	t.end();
});

test('receiveBadEncryption', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);

    let appPacket1 = new Uint8Array(7)
    appPacket1[0] = 5

    let time = new Int32Array([util.currentTimeMs() - testInterface.serverData.sEpoch])
    time = new Uint8Array(time.buffer)

    appPacket1.set(time, 2)

    let encrypted1 = encrypt(testInterface.serverData, appPacket1)

    encrypted1[5] = 0
    encrypted1[6] = 0
    encrypted1[7] = 0

    testInterface.send(encrypted1)

    
    const errorMsg1 = 'EncryptedMessage: Could not decrypt message'   
    t.throws(async function(){
        await channel.receive(1000)
    }, errorMsg1)

    console.log('## receiveAfterError')
    let appPacket2 = createAppPacket(testInterface.serverData, [0])
    let encrypted2 = encrypt(testInterface.serverData, appPacket2)
    testInterface.send(encrypted2)

    const errorMsg2 = 'Received message when salt channel was not ready' 
    t.throws(async function(){
        await channel.receive(1000)
    }, errorMsg2)

	t.end();
});

test('receiveDelayed', async function (t) {
    let [mockSocketInterface, testInterface] = misc.createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let timeChecker = getTimeChecker(util.currentTimeMs, 10)
    let sc = saltChannelSession(mockSocketInterface, undefined, timeChecker)

    const threshold = 20
    let serverPromise = testServerSide(t, testInterface, clientEphKeyPair.publicKey, undefined, threshold)

    let channel = await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined);

    t.equal(channel.getState(), 'ready', 'State is OPEN')

    await serverPromise;

    let appPacket = createAppPacket(testInterface.serverData, [0])
    appPacket[2] = 2    // Time
    appPacket[3] = 0
    appPacket[4] = 0
    appPacket[5] = 0
    let encrypted = encrypt(testInterface.serverData, appPacket)
    testInterface.send(encrypted)

    const errorMsg1 = '(Multi)AppPacket: Detected a delayed packet'
    t.throws(async function(){
        await channel.receive(1000)
    }, errorMsg1)

    console.log('## handShakeAfterError')
    testInterface.serverData = createServerData();

    const errorMsg2 = 'Handshake: Invalid internal state: closed'
    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair)
    }, errorMsg2)
    
	t.end();
});

test('receiveLastFlag', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);

    let appPacket = createAppPacket(testInterface.serverData, [0])
    let encrypted = encrypt(testInterface.serverData, appPacket, true)
    testInterface.send(encrypted)

    let event = await channel.receive(1000)
    t.ok((event.message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    t.arrayEqual(new Uint8Array(event.message), new Uint8Array(1), 'Expected 1 zero byte, was ' + util.ab2hex(event.message));
    t.ok(event.close,'Expected closed');

    console.log('## stateAfterReceivedLastFlag')
    t.equal(channel.getState(), 'closed', 'State not closed')
	t.end();
});

test('sendLastFlag', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);

    let data = new Uint8Array(1)
    channel.send(true, data);

    let message = await testInterface.receive(1000)
    validateAppPacket(t, testInterface.serverData, message, data, true)

	console.log('## stateAfterSentLastFlag')
    t.equal(channel.getState(), 'closed', 'State not closed')
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
    let [channel, testInterface] = await standardHandshake(t);
    const expectedError = 'EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was 1 0' 
    const badData = new Uint8Array([1, 0])
    testInterface.send(createBadHeaderEnc(testInterface.serverData, badData))
    t.throws(async function(){
        await channel.receive(1000)
    }, expectedError)
	t.end();
});

test('receiveBadHeaderEnc2', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);
    const expectedError = 'EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was 6 2'
    const badData = new Uint8Array([6, 2])
    testInterface.send(createBadHeaderEnc(testInterface.serverData, badData))
    t.throws(async function(){
        await channel.receive(1000)
    }, expectedError)
	t.end();
});

test('receiveBadHeaderApp1', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);
    const expectedError = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 0 0'
    const badData = new Uint8Array([0, 0])
    testInterface.send(createBadHeaderApp(testInterface.serverData, badData))
    t.throws(async function(){
        await channel.receive(1000)
    }, expectedError)
	t.end();
});

test('receiveBadHeaderApp2', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);
    const expectedError = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 5 1'
    const badData = new Uint8Array([5, 1])
    testInterface.send(createBadHeaderApp(testInterface.serverData, badData))
    t.throws(async function(){
        await channel.receive(1000)
    }, expectedError)
	t.end();
});

test('receiveBadHeaderApp3', async function (t) {
    let [channel, testInterface] = await standardHandshake(t);
    const expectedError = '(Multi)AppPacket: Bad packet header. Expected 5 0 or 11 0, was 11 1'
    const badData = new Uint8Array([11, 1])
    testInterface.send(createBadHeaderApp(testInterface.serverData, badData))
    t.throws(async function(){
        await channel.receive(1000)
    }, expectedError)
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
    await testBadM3(t, badData, undefined, expectedError)
	t.end();
});

test('receiveBadHeaderM32', async function (t) {
    const expectedError = 'M3: Bad packet header. Expected 3 0, was 3 1'
    const badData = new Uint8Array([3, 1])
    await testBadM3(t, badData, undefined, expectedError)
	t.end();
});

test('receiveBadHeaderM33', async function (t) {
    const expectedError = 'M3: ServerSigKey does not match expected'
    const badData = new Uint8Array([3, 0, 20, 0, 0, 0, 12, 23, 34, 56])
    await testBadM3(t, badData, serverSigKeyPair.publicKey, expectedError)
	t.end();
});

test('receiveBadHeaderM34', async function (t) {
    const expectedError = 'M3: Could not verify signature'
    const badData = new Uint8Array([3, 0, 20, 0, 0, 0, 12, 23, 34, 56])
    await testBadM3(t, badData, undefined, expectedError)
	t.end();
});

test('receiveBadPubEph', async function (t) {
    const expectedError = 'EncryptedMessage: Could not decrypt message'

    let [mockSocketInterface, testInterface] = misc.createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)

    let serverPromise = async function(){
        testInterface.serverData = createServerData();
        let m1 = await testInterface.receive(1000)
        // Skip validating of m1
        testInterface.send(createBadEphM2(testInterface.serverData, m1))
        testInterface.send(createM3(testInterface.serverData))
    }()

    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined)
    }, expectedError)

    await serverPromise
	t.end();
});

// ==================================================================
// ==================================================================
// ==================================================================
// =================== SERVER SIDE HANDSHAKE CODE ===================
// ============================ (sorta) =============================

function doNothing() {
    // Do nothing
}

function numberTo8Array(number){
    let array = new Int16Array([number])
    return new Uint8Array(array.buffer)
}

function createM2(serverData) { 
    let header = new Uint8Array([PacketTypeM2, 0])
    let time = new Int32Array([1, 0, 0, 0]) // Time is supported

    let m2 = new Uint8Array([
        ...header, 
        ...time,
        ...serverEphKeyPair.publicKey])

    serverData.m2Hash = nacl.hash(m2)
    serverData.sEpoch = util.currentTimeMs()

    return m2;
}

function createBadM2(badData) {
    let header = new Uint8Array([PacketTypeM2, 0])
    let time = new Int32Array([1, 0, 0, 0]) // Time is supported

    let m2 = new Uint8Array([
        ...header, 
        ...time,
        ...serverEphKeyPair.publicKey])

    m2.set(badData)

    return m2
}

function createBadEphM2(serverData, m1) {
    let publicEphemeral = new Uint8Array(m1, 10, 32)
    serverData.sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    let header = new Uint8Array([PacketTypeM2, 0])
    let time = new Int32Array([1, 0, 0, 0]) // Time is supported
    
    let m2 = new Uint8Array([
        ...header, 
        ...time,
        ...serverEphKeyPair.publicKey])

    m2[6] = 0
    serverData.m1Hash = nacl.hash(new Uint8Array(m1))
    serverData.m2Hash = nacl.hash(m2)

    serverData.sEpoch = util.currentTimeMs()

    return m2
}

function createM3(serverData) {

    let header = new Uint8Array([PacketTypeM3, 0])

    let time = new Int32Array([util.currentTimeMs() - serverData.sEpoch])
    time = new Uint8Array(time.buffer)

    let concat = new Uint8Array([...sigBytes1, ...serverData.m1Hash, ...serverData.m2Hash])
    let signature = nacl.sign.detached(concat, serverSigKeyPair.secretKey)

    let m3 = new Uint8Array([
        ...header, 
        ...time,
        ...serverSigKeyPair.publicKey,
        ...signature])

    let encrypted = encrypt(serverData, m3)
    return encrypted
}

function createAppPacket(serverData, message) {
    let header = new Uint8Array([PacketTypeApp, 0])
    let time = new Int32Array([util.currentTimeMs() - serverData.sEpoch])
    time = new Uint8Array(time.buffer)

    let packet= new Uint8Array([
        ...header, 
        ...time,
        ...message])

    return packet
}

function createMultiAppPacketBody(messages) {
    let packet = numberTo8Array(messages.length)
    for (const message of messages){
        let size = numberTo8Array(message.length)
        packet= new Uint8Array([
            ...packet, 
            ...size,
            ...message])
    };
    return packet
}

function createMultiAppPacket(serverData, messages) {
    let header = new Uint8Array([PacketTypeMultiApp, 0])
    let time = new Int32Array([util.currentTimeMs() - serverData.sEpoch])
    time = new Uint8Array(time.buffer)
    let body = createMultiAppPacketBody(messages)

    let packet= new Uint8Array([
        ...header, 
        ...time,
        ...body])

    return packet
}

function createBadHeaderEnc(serverData, badData) {
    let appPacket = createAppPacket(serverData, [0])
    let encrypted = encrypt(serverData, appPacket)
    encrypted.set(badData)
    return encrypted
}

function createBadHeaderApp(serverData, badData) {
    let appPacket = createAppPacket(serverData, [0])
    appPacket.set(badData)
    let encrypted = encrypt(serverData, appPacket)
    return encrypted
}

function createBadM3(serverData, badData) {
    let m3 = new Uint8Array(102)
    m3.set(badData)
    let encrypted = encrypt(serverData, m3)

    return encrypted
}

// ==================================================================
// ==================================================================
// ==================================================================
// ========================== CRYPTO STUFF ==========================
// ==================================================================

function decrypt(serverData, message) {
    let lastFlag
    if (message[0] === PacketTypeEncrypted && message[1] === 0) {
        lastFlag = false
    } else if (message[0] === PacketTypeEncrypted && message[1] === 128) {
        lastFlag = true
    } else {
        throw new Error('EncryptedMessage: Bad packet header, was  ' +
                + message[0] + ' ' + message[1])
    }

    let bytes = message.slice(2)

    let clear = nacl.secretbox.open(bytes, serverData.dNonce, serverData.sessionKey)
    serverData.dNonce = increaseNonce2(serverData.dNonce)

    if (clear === false) {
        throw new Error('EncryptedMessage: Failed to decrypt')
    }

    let copy = new Uint8Array(clear)

    return {
        data: copy,
        last: lastFlag
    }
}

function encrypt(serverData, clearBytes, last = false) {
    let body = nacl.secretbox(clearBytes, serverData.eNonce, serverData.sessionKey)
    serverData.eNonce = increaseNonce2(serverData.eNonce)

    let headerByte1= PacketTypeEncrypted
    let headerByte2 = last ? 128 : 0
    let encryptedMessage = new Uint8Array([headerByte1, headerByte2, ...body])

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


function validateM1(t, serverData, message, expectedEphKey, expectedServKey) {
    t.ok((message instanceof ArrayBuffer),'Expected ArrayBuffer from Salt Channel');
    let m1 = new Uint8Array(message)

    let expectedLength = 42 + ((expectedServKey === undefined) ? 0 : 32)
    t.equal( m1.length, expectedLength, 'M1: Check packet length')

    let protocol = String.fromCharCode(...m1.slice(0, 4))
    t.equal(protocol, 'SCv2', 'M1: Check: Bad protocol indicator')

    let expectedHeader = [PacketTypeM1, (expectedServKey === undefined) ? 0 : 1]
    t.arrayEqual(m1.slice(4, 6), expectedHeader, 'M1: Check header')
    t.arrayEqual(m1.slice(6, 10), [1, 0, 0, 0], 'M1: Check time to be set: ' +util.ab2hex(m1.slice(6, 10)))

    serverData.cEpoch = util.currentTimeMs()

    let publicEphemeral = m1.slice(10, 42)
    t.arrayEqual( publicEphemeral, expectedEphKey, 'M1: Check public ephemeral key from client')

    if (expectedServKey !== undefined){
        let serverSigKey = m1.slice(42, 74)
        t.arrayEqual( serverSigKey, expectedServKey, 'M1: Check server sig key from client')
    }

    serverData.sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

    serverData.m1Hash = nacl.hash(m1)
}

function validateM4(t, serverData, message, threshold) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')

    let encryptedMessage = new Uint8Array(message)
    let m4 = decrypt(serverData, encryptedMessage).data

    t.arrayEqual(m4.slice(0, 2), [PacketTypeM4, 0], 'M4: Check header')

    let time = m4.slice(2,6)
    t.notArrayEqual(time, [0, 0, 0, 0], 'M4: Check time to be set: ' +util.ab2hex(time))
    time = (new Int32Array(time.buffer))[0]
    if (threshold !== undefined) {
        t.ok((util.currentTimeMs() - serverData.cEpoch < time + threshold ), 'M4: Delayed packet')
    }

    let clientSigKey = m4.slice(6,38)

    t.arrayEqual(clientSigKey, clientSigKeyPair.publicKey, 'M4: Client signing key does not match expected')

    let signature = m4.slice(38,102)

    let concat = new Uint8Array([...sigBytes2, ...serverData.m1Hash, ...serverData.m2Hash])

    let success = nacl.sign.detached.verify(concat, signature, clientSigKey)

    t.ok(success, 'M4: Could not verify signature')
}

function validateAppPacket(t, serverData, message, expectedData, lastFlag) {
    t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')

    let encryptedMessage = new Uint8Array(message)
    let {data, last} = decrypt(serverData, encryptedMessage)

    t.equal(last, lastFlag, 'AppPacket: Check last flag')
    t.equal(data.length, 6 + expectedData.length, 'AppPacket: Check message length');

    t.arrayEqual(data.slice(0, 2), [PacketTypeApp, 0], 'AppPacket: Expected header')
    t.notArrayEqual(data.slice(2,6), [0, 0, 0, 0], 'AppPacket: Check time to be set: ' +util.ab2hex(data.slice(2,6)))

    t.arrayEqual(data.slice(6), expectedData, 'AppPacket: Unexpected data')
}

function validateMultiAppPacket(t, serverData, message, expectedData, lastFlag) {
     t.ok((message instanceof ArrayBuffer), 'Expected ArrayBuffer from Salt Channel')

    let encryptedMessage = new Uint8Array(message)
    let {data, last} = decrypt(serverData, encryptedMessage)
    let expectedBytes = createMultiAppPacketBody(expectedData)

    t.equal(last, lastFlag, 'AppPacket: Check last flag')
    t.equal(data.length, 6 + expectedBytes.length, 'AppPacket: Check message length')

    t.arrayEqual(data.slice(0, 2), [PacketTypeMultiApp, 0], 'AppPacket: Check header')
    t.notArrayEqual(data.slice(2,6), [0, 0, 0, 0], 'AppPacket: Check time to be set: ' +util.ab2hex(data.slice(2,6)))

    t.arrayEqual(data.slice(6), expectedBytes, 'AppPacket: Unexpected data')
}

// ==================================================================
// ==================================================================
// ==================================================================

async function testServerSide(t, testInterface, clientEphPub, serverSigPub, threshold){        
    testInterface.serverData = createServerData();

    let m1 = await testInterface.receive(1000)
    validateM1(t, testInterface.serverData, m1, clientEphPub, serverSigPub)
    testInterface.send(createM2(testInterface.serverData))
    testInterface.send(createM3(testInterface.serverData))
    let m4 = await testInterface.receive(1000)
    validateM4(t, testInterface.serverData, m4, threshold)
}

function createServerData(){
    let eNonce = new Uint8Array(nacl.secretbox.nonceLength)
    let dNonce = new Uint8Array(nacl.secretbox.nonceLength)
    eNonce[0] = 2
    dNonce[0] = 1

    return {
        eNonce: eNonce,
        dNonce: dNonce,
        sessionKey: undefined,
        m1Hash: undefined,
        m2Hash: undefined,
        cEpoch: undefined,
        sEpoch: undefined
    }
}

async function standardHandshake(t){
    let [mockSocketInterface, testInterface] = misc.createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)

    let serverPromise = testServerSide(t, testInterface, clientEphKeyPair.publicKey)

    let channel = await sc.handshake(clientSigKeyPair, clientEphKeyPair, undefined);

    t.equal(channel.getState(), 'ready', 'State is OPEN')

    await serverPromise;

    return [channel, testInterface]
}

async function testBadM2(t, m2, sigKey, expectedError){
    let [mockSocketInterface, testInterface] = misc.createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)

    let serverPromise = async function(){
        await testInterface.receive(1000)
        // Skip validating of m1
        testInterface.send(m2)
    }()

    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair, sigKey)
    }, expectedError)

    await serverPromise
}

async function testBadM3(t, badData, sigKey, expectedError){
    let [mockSocketInterface, testInterface] = misc.createMockSocket()
    testInterface.setState(mockSocketInterface.OPEN)

    let sc = saltChannelSession(mockSocketInterface, undefined, undefined)

    let serverPromise = async function(){
        let serverData = createServerData()

        let m1 = await testInterface.receive(1000)
        serverData.m1Hash = nacl.hash(new Uint8Array(m1))
        let publicEphemeral = new Uint8Array(m1, 10, 32)
        serverData.sessionKey = nacl.box.before(publicEphemeral, serverEphKeyPair.secretKey)

        const m2 = createM2(serverData)
        testInterface.send(m2)
        const m3 = createBadM3( serverData, badData)
        testInterface.send(m3)
    }()

    t.throws(async function(){
        await sc.handshake(clientSigKeyPair, clientEphKeyPair, sigKey)
    }, expectedError)

    await serverPromise
}