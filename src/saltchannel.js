import * as util from './../lib/util.js';
import nacl from './../lib/nacl-fast-es.js';
import getTimeKeeper from './time/typical-time-keeper.js';
import getTimeChecker from './time/typical-time-checker.js';
import getNullTimeChecker from './time/null-time-checker.js';

/**
 * JavaScript implementation of Salt Channel v2
 *
 */
export default function(ws, timeKeeper, timeChecker) {
	'use-strict'

	const SIG_STR_1 = 'SC-SIG01'
	const SIG_STR_2 = 'SC-SIG02'
	const VERSION_STR = 'SCv2'

	const STATE_INIT = 'init'
	const STATE_A1A2 = 'a1a2'
	const STATE_HAND = 'handshake'
	const STATE_READY = 'ready'
	const STATE_LAST = 'last'
	const STATE_ERR = 'error'
	const STATE_CLOSED = 'closed'
	const STATE_WAITING = 'waiting'

	const ADDR_TYPE_ANY = 0
	const ADDR_TYPE_PUB = 1

	const WS_CONNECTING = 0
	const WS_OPEN = 1
	const WS_CLOSING = 2
	const WS_CLOSED = 3

	const SIG_STR1_BYTES = new Uint8Array([ SIG_STR_1.charCodeAt(0)
							, SIG_STR_1.charCodeAt(1)
							, SIG_STR_1.charCodeAt(2)
							, SIG_STR_1.charCodeAt(3)
							, SIG_STR_1.charCodeAt(4)
							, SIG_STR_1.charCodeAt(5)
							, SIG_STR_1.charCodeAt(6)
							, SIG_STR_1.charCodeAt(7) ])

	const SIG_STR2_BYTES = new Uint8Array([ SIG_STR_2.charCodeAt(0)
							, SIG_STR_2.charCodeAt(1)
							, SIG_STR_2.charCodeAt(2)
							, SIG_STR_2.charCodeAt(3)
							, SIG_STR_2.charCodeAt(4)
							, SIG_STR_2.charCodeAt(5)
							, SIG_STR_2.charCodeAt(6)
							, SIG_STR_2.charCodeAt(7) ])

	const VERSION = new Uint8Array([ VERSION_STR.charCodeAt(0)
							, VERSION_STR.charCodeAt(1)
							, VERSION_STR.charCodeAt(2)
							, VERSION_STR.charCodeAt(3) ])



	let eNonce
	let dNonce
	let m1Hash
	let m2Hash
	let sessionKey
	let hostPub
	let signKeyPair
	let ephemeralKeyPair
	let readQueue = util.waitQueue();

	timeKeeper = (timeKeeper) ? timeKeeper : getTimeKeeper(util.currentTimeMs)
	timeChecker = (timeChecker) ? timeChecker : getTimeChecker(util.currentTimeMs)
	let saltState

	// Set by calling corresponding set-function
	let onerror
	let onclose

	init()

	function close() {
		eNonce = undefined
		dNonce = undefined
		m1Hash = undefined
		m2Hash = undefined
		sessionKey = undefined
		hostPub = undefined
		signKeyPair = undefined
		ephemeralKeyPair = undefined

		let state = saltState
		saltState = STATE_CLOSED

		timeKeeper.reset()
		timeChecker.reset()

		ws.close()

		if (typeof onclose === 'function') {
			onclose(state)
		} else {
			console.error('saltchannel.onClose not set')
			console.error(state)
		}
	}

	function init() {
		eNonce = new Uint8Array(nacl.secretbox.nonceLength)
		dNonce = new Uint8Array(nacl.secretbox.nonceLength)
		eNonce[0] = 1
		dNonce[0] = 2

		saltState = STATE_INIT
	}

	async function receive(waitTime){
		return (await readQueue.pull(waitTime))[0];
	}

	// =========== A1A2 MESSAGE EXCHANGE ================
	async function a1a2(adressType, adress) {
		if (saltState !== STATE_INIT) {
			throw new Error('A1A2: Invalid internal state: ' + saltState)
        }
		saltState = STATE_A1A2

		let a1a2ReadQueue = util.waitQueue();
		ws.onmessage = function(event){
			a1a2ReadQueue.push(new Uint8Array(event.data));
		}
		async function a1a2Receive(waitTime){
			return (await a1a2ReadQueue.pull(waitTime))[0];
		}

		let a1 = createA1(adressType, adress)
        ws.send(a1)
		let a2 = await a1a2Receive(1000)
		let prots = handleA2(a2)
		return prots
    }

    function createA1(adressType = ADDR_TYPE_ANY, adress) {
    	switch (adressType) {
    		case ADDR_TYPE_ANY:
    			return getA1Any()

    		case ADDR_TYPE_PUB:
    			return getA1Pub(adress)

    		default:
    			throw new RangeError('A1A2: Unsupported adress type: ' + adressType)
    	}
    }

    function getA1Any() {
    	let a1 = new Uint8Array(5)
    	a1[0] = 8
    	return a1
    }

    function getA1Pub(adress) {
    	if (adress instanceof ArrayBuffer) {
    		adress = new Uint8Array(adress)
    	} else if (!(adress instanceof Uint8Array)) {
    		throw new TypeError('A1A2: Expected adress to be ArrayBuffer or Uint8Array')
    	}
		let a1 = new Uint8Array(5 + adress.length)
        a1[0] = 8
        a1[2] = ADDR_TYPE_PUB
        setUint16(a1, adress.length, 3)
        a1.set(adress, 5)
        return a1
    }

    function handleA2(message) {
    	if (saltState !== STATE_A1A2) {
    		errorAndThrow('A2: Invalid internal state: ' + saltState)
    		return
    	}
        let a2 = new Uint8Array(message)

        if (validHeader(a2, 9, 129)) {
        	errorAndThrow('A2: NoSuchServer exception')
        	return
        }
        if (!validHeader(a2, 9, 128)) {
        	errorAndThrow('A2: Bad packet header. Expected 9 128, was ' +
        		a2[0] + ' ' + a2[1])
        	return
        }
        let offset = 2
        let count = a2[offset++]

        if (count < 1 || count > 127) {
            errorAndThrow('A2: Count must be in range [1, 127], was: ' + count)
            return
        }

        if (a2.length !== count*20 + 3) {
            errorAndThrow('A2: Expected packet length ' + (count*20 + 3) +
            	' was ' + a2.length)
            return
        }

        let prots = []
        for (let i = 0; i < count; i++) {
        	let p1 = ''
        	let p2 = ''

        	for (let j = 0; j < 10; j++) {
        		if (!validPStringChar(a2[offset])) {
        			errorAndThrow('A2: Invalid char in p1 "' +
        				String.fromCharCode(a2[offset]) + '"')
        			return
        		}
        		if (!validPStringChar(a2[offset + 10])) {
        			errorAndThrow('A2: Invalid char in p2 "' +
        				String.fromCharCode(a2[offset + 10]) + '"')
        			return
        		}
        		p1 += String.fromCharCode(a2[offset])
        		p2 += String.fromCharCode(a2[offset + 10])
        		offset++
        	}

            prots[i] = {p1: p1, p2: p2}
        }

        saltState = STATE_LAST

        close() // ToDo Should this be here?

		return prots
    }

    function validPStringChar(byteValue) {
    	// '-' to '9' in ASCII
    	if (byteValue >= 45 && byteValue <= 57) {
    		return true
    	}
    	// 'A' to 'Z' in ASCII
    	if (byteValue >= 65 && byteValue <= 90) {
    		return true
    	}
    	// '_' in ASCII
    	if (byteValue === 95) {
    		return true
    	}
    	// 'a' to 'z' in ASCII
    	if (byteValue >= 97 && byteValue <= 122) {
    		return true
    	}

    	return false
    }

    // =================================================

	// =============== HANDSHAKE BEGIN =================

	async function handshake(sigKeyPair, ephKeyPair, hostSigPub) {
		verifySigKeyPair(sigKeyPair)
		verifyEphKeyPair(ephKeyPair)
		verifyHostSigPub(hostSigPub)
		if (saltState !== STATE_INIT) {
			errorAndThrow('Handshake: Invalid internal state: ' + saltState)
		}
		signKeyPair = sigKeyPair
		ephemeralKeyPair = ephKeyPair
		hostPub = hostSigPub
		saltState = STATE_HAND

		let handshakeReadQueue = util.waitQueue();
		ws.onmessage = function(event){
			handshakeReadQueue.push(new Uint8Array(event.data));
		}
		async function handshakeReceive(waitTime){
			return (await handshakeReadQueue.pull(waitTime))[0];
		}

		sendM1()
		let m2 = await handshakeReceive(1000)
		handleM2(m2)
		let m3 = await handshakeReceive(1000)
		handleM3(m3)
		sendM4()
		

		ws.onmessage = function(evt) {
			onmsg(evt.data)
		}
		saltState = STATE_READY

		return {
			send: send,
			receive: receive,
			getState: getState,
			setOnError: setOnerror,
			setOnClose: setOnclose
		}
	}

	function errorAndThrow(msg){
		error(msg)
		throw new Error(msg)
	}

	function verifySigKeyPair(keyPair) {
		let pub = keyPair.publicKey
		let sec = keyPair.secretKey
		if (!pub || !sec) {
			throw new TypeError('sigKeyPair must have publicKey and secretKey properties')
		}
		if (!(pub instanceof Uint8Array) ||
			!(sec instanceof Uint8Array)) {
			throw new TypeError('sigKeyPair.publicKey & sigKeyPair.secretKey must be Uint8Array')
		}
		if (pub.length !== nacl.sign.publicKeyLength ||
			sec.length !== nacl.sign.secretKeyLength) {
			throw new TypeError('sigKeyPair.publicKey & sigKeyPair.secretKey must be 32 and 64 bytes')
		}
	}
	function verifyEphKeyPair(keyPair) {
		let pub = keyPair.publicKey
		let sec = keyPair.secretKey
		if (!pub || !sec) {
			throw new TypeError('ephKeyPair must have publicKey and secretKey properties')
		}
		if (!(pub instanceof Uint8Array) ||
			!(sec instanceof Uint8Array)) {
			throw new TypeError('ephKeyPair.publicKey & ephKeyPair.secretKey must be Uint8Array')
		}
		if (pub.length !== nacl.box.publicKeyLength ||
			sec.length !== nacl.box.secretKeyLength) {
			throw new TypeError('ephKeyPair.publicKey & ephKeyPair.secretKey must be 32 and 64 bytes')
		}
	}
	function verifyHostSigPub(key) {
		if (key) {
			if (!(key instanceof Uint8Array)) {
				throw new TypeError('hostSigPub must be Uint8Array')
			}
			if (key.length !== nacl.sign.publicKeyLength) {
				throw new TypeError('hostSigPub must be 32 bytes')
			}
		}
	}

	function sendM1() {
		let m1Len = (hostPub) ? 74 : 42
		let m1 = new Uint8Array(m1Len)

		m1.set(VERSION)

		// Header
		m1[4] = 1	// Packet type 1
		m1[5] = (hostPub) ? 1 : 0

		// Time
		setInt32(m1, timeKeeper.getTime(), 6)

		// ClientEncKey
		m1.set(ephemeralKeyPair.publicKey, 10)

		// ServerSigKey
		if (hostPub) {
			m1.set(hostPub, 42)
		}
		m1Hash = nacl.hash(m1)

		sendOnWs(m1.buffer)
	}

	function handleM2(m2) {
		if (saltState !== STATE_HAND) {
    		errorAndThrow('M2: Invalid internal state: ' + saltState)
    	}

		// Header
		if (validHeader(m2, 2, 0)) {

		} else if (validHeader(m2, 2, 129)) {
			errorAndThrow('M2: NoSuchServer exception')
		} else {
			errorAndThrow('M2: Bad packet header. Expected 2 0 or 2 129, was '
				+ m2[0] + ' ' + m2[1])
		}

		// Time
		let time = getInt32(m2, 2)
		if (time === 0) {
			timeChecker = getNullTimeChecker()
		} else if (time !== 1){
			errorAndThrow('M2: Invalid time value ' + time)
		}

		let serverPub = getUints(m2, 32, 6)

		sessionKey = nacl.box.before(serverPub, ephemeralKeyPair.secretKey)

		m2Hash = nacl.hash(m2)
	}

	function handleM3(data) {
		if (saltState !== STATE_HAND) {
    		errorAndThrow('M3: Invalid internal state: ' + saltState)
    	}

		let m3 = decrypt(data)

		if (!m3) {
			errorAndThrow('EncryptedMessage: Could not decrypt message')
		}
		// Header
		if (!validHeader(m3, 3, 0)) {
			errorAndThrow('M3: Bad packet header. Expected 3 0, was ' +
				m3[0] + ' ' + m3[1])
		}

		// Time
		let time = getInt32(m3, 2)
		if (timeChecker.delayed(time)) {
			errorAndThrow('M3: Detected delayed packet')
		}

		let serverPub = getUints(m3, 32, 6)

		if (hostPub) {
			if (!util.uint8ArrayEquals(serverPub, hostPub)) {
				errorAndThrow('M3: ServerSigKey does not match expected')
			}
		}

		let signature = new Uint8Array(64)
		for (let i = 0; i < 64; i++) {
			signature[i] = m3[38+i]
		}

		// Construct the message that was signed
		let concat = new Uint8Array(2*nacl.hash.hashLength + 8)
		concat.set(SIG_STR1_BYTES)
		concat.set(m1Hash, 8)
		concat.set(m2Hash, 8 + nacl.hash.hashLength)

		let success = nacl.sign.detached.verify(concat, signature, serverPub)

		if (!success) {
			errorAndThrow('M3: Could not verify signature')
		}
	}

	function sendM4() {
		// Create m4
		let m4 = new Uint8Array(102)

		// Header
		m4[0] = 4

		m4.set(signKeyPair.publicKey, 6)

		let concat = new Uint8Array(2*nacl.hash.hashLength + 8)
		concat.set(SIG_STR2_BYTES)
		concat.set(m1Hash, 8)
		concat.set(m2Hash, 8 + nacl.hash.hashLength)
		// We only send the signature, NOT the message
		let signature = nacl.sign.detached(concat, signKeyPair.secretKey)

		m4.set(signature, 38)

		setInt32(m4, timeKeeper.getTime(), 2)

		let encrypted = encrypt(false, m4)

		sendOnWs(encrypted.buffer)
	}

	// =================================================

	// ================ SET FUNCTIONS ==================
    function setOnerror(callback) {
    	onerror = callback
    }

	function setOnclose(callback) {
		onclose = callback
	}
	// =================================================

	function getState() {
		switch (ws.readyState) {
			case WS_OPEN:
				return saltState
			case WS_CLOSED:
			case WS_CLOSING:
				return STATE_CLOSED
			case WS_CONNECTING:
				return STATE_WAITING
		}
	}

	function error(msg) {
		saltState = STATE_ERR
		if (typeof onerror === 'function') {
			onerror(new Error(msg))
		} else {
			console.error('saltchannel.onerror not set')
			console.error(new Error(msg))
		}

		close()
	}

	function onmsg(data) {
		if (saltState !== STATE_READY) {
			error('Received message when salt channel was not ready')
			return
		}

		let bytes = new Uint8Array(data)

		let clear = decrypt(bytes)

		if (!clear) {
			return
		}

		let time = getInt32(clear, 2)
		if (timeChecker.delayed(time)) {
			error('(Multi)AppPacket: Detected a delayed packet')
			return
		}

		if (validHeader(clear, 5, 0)) {
			handleAppPacket(clear)
		} else if (validHeader(clear, 11, 0)) {
			handleMultiAppPacket(clear)
		} else {
			error('(Multi)AppPacket: Bad packet header. ' +
			'Expected 5 0 or 11 0, was ' + clear[0] + ' ' + clear[1])
			return
		}
		if (saltState === STATE_LAST) {
			close()
		}
	}

	function handleMultiAppPacket(multiAppPacket) {
		let count = getUint16(multiAppPacket, 6)

		if (count === 0) {
			error('MultiAppPacket: Zero application messages')
			return
		}

		let offset = 2 + 4 + 2
		for (let i = 0; i < count; i++) {
			let length = getUint16(multiAppPacket, offset)
			offset += 2

			let data = getUints(multiAppPacket, length, offset)
			offset += length

			readQueue.push(data.buffer);
		}
	}

	function handleAppPacket(appPacket) {

		let data = getUints(appPacket, appPacket.length - 6, 6)
		readQueue.push(data.buffer);
	}

	function sendOnWs(message) {
		if (message instanceof ArrayBuffer) {
			ws.send(message)
		} else {
			throw new TypeError('Must only send ArrayBuffer on WebSocket')
		}
	}

	function decrypt(message) {
		if (validHeader(message, 6, 0)) {
			// Regular message
		} else if (validHeader(message, 6, 128)) {
			// Last message
			saltState = STATE_LAST;
		} else {
			error('EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was '
				+ message[0] + ' ' + message[1])
			return null
		}

		let bytes = new Uint8Array(message.byteLength - 2)
		let msg = new Uint8Array(message)

		for (let i = 0; i < message.byteLength - 2; i++) {
			bytes[i] = msg[i+2]
		}

		let clear = nacl.secretbox.open(bytes, dNonce, sessionKey)
		dNonce = increaseNonce2(dNonce)

		if (!clear) {
			error('EncryptedMessage: Could not decrypt message')
			return null
		}
		// clear.length < clear.buffer.byteLength
		clear = new Uint8Array(clear)
		// clear.length == clear.buffer.byteLength

		return clear
	}

	function validHeader(uints, first, second, offset = 0) {
		if (uints[offset] !== first | uints[offset + 1] !== second) {
			return false
		}
		return true
	}

	function getUints(from, length, offset = 0) {
		let uints = new Uint8Array(length)

		for (let i = 0; i < length; i++) {
			uints[i] = from[offset++]
		}

		return uints
	}

	function getInt32(uints, offset) {
		let int32 = new Uint8Array(4)
		int32[0] = uints[offset++]
		int32[1] = uints[offset++]
		int32[2] = uints[offset++]
		int32[3] = uints[offset++]

		return (new Int32Array(int32.buffer))[0]
	}

	function setInt32(uints, data, offset) {
		let view = new DataView(uints.buffer);
		view.setUint32(offset, data, true);
	}

	function getUint16(uints, offset) {
		let uint16 = new Uint8Array(2)
		uint16[0] = uints[offset++]
		uint16[1] = uints[offset]

		return (new Uint16Array(uint16.buffer))[0]
	}

	function setUint16(uints, data, offset) {
		let view = new DataView(uints.buffer);
		view.setUint16(offset, data, true);
	}

	function send(last, arg) {
		if (saltState !== STATE_READY) {
			errorAndThrow('Invalid state: ' + saltState)
		}
		if (last) {
			saltState = STATE_LAST
		}

		if (arguments.length === 2) {
			if (util.isArray(arg)) {
				if (arg.length === 1) {
					sendAppPacket(last, arg[0])
				} else {
					sendMultiAppPacket(last, arg)
				}
			} else {
				sendAppPacket(last, arg)
			}
		} else {
			// turn arguments into an array
			let arr = []
			for (let i = 1; i < arguments.length; i++) {
				arr[i-1] = arguments[i]
			}
			sendMultiAppPacket(last, arr)
		}

		if (saltState === STATE_LAST) {
			close()
		}
	}

	function sendAppPacket(last, data) {
		if (data instanceof ArrayBuffer) {
			data = new Uint8Array(data)
		} else if (!(data instanceof Uint8Array)) {
			throw new TypeError('Expected data to be ArrayBuffer or Uint8Array')
		}

		let appPacket = new Uint8Array(data.length + 6)

		appPacket[0] = 5
		appPacket.set(data, 6)

		setInt32(appPacket, timeKeeper.getTime(), 2)

		let encrypted = encrypt(last, appPacket)
		sendOnWs(encrypted.buffer)
	}

	function sendMultiAppPacket(last, arr) {
		if (arr.length > 65535) {
			throw new RangeError('Too many application messages')
		}
		let size = 2 + 4 + 2
		for (let i = 0; i < arr.length; i++) {
			if (arr[i] instanceof ArrayBuffer) {
				arr[i] = new Uint8Array(arr[i])
			} else if (!(arr[i] instanceof Uint8Array)) {
				throw new TypeError('Expected data to be ArrayBuffer or Uint8Array')
			}
			if (arr[i].length > 65535) {
				throw new RangeError('Application message ' + i + ' too large')
			}
			size += 2 + arr[i].length
		}

		let multiAppPacket = new Uint8Array(size)
		multiAppPacket[0] = 11

		let offset = 6
		setUint16(multiAppPacket, arr.length, offset)

		offset = 8
		for (let i = 0; i < arr.length; i++) {
			writeMessage(multiAppPacket, arr[i], offset)
			offset += arr[i].length + 2
		}

		setInt32(multiAppPacket, timeKeeper.getTime(), 2)

		let encrypted = encrypt(last, multiAppPacket)
		sendOnWs(encrypted.buffer)
	}

	function writeMessage(multiAppPacket, uints, offset) {
		setUint16(multiAppPacket, uints.length, offset)
		offset += 2
		multiAppPacket.set(uints, offset)
	}

	function encrypt(last, clearBytes) {
		let body = nacl.secretbox(clearBytes, eNonce, sessionKey)
		eNonce = increaseNonce2(eNonce)

		let encryptedMessage = new Uint8Array(body.length + 2)
		encryptedMessage[0] = 6
		encryptedMessage[1] = last ? 128 : 0
		encryptedMessage.set(body, 2)

		return encryptedMessage
	}

	function increaseNonce(nonce) {
		if (!(nonce instanceof Uint8Array)) {
			errorAndThrow('Expected Uint8Array. \n\t' +
						'Input: ' + nonce)
		}
		if (!(nonce.length === nacl.secretbox.nonceLength)) {
			errorAndThrow('Unexpected nonce length. \n\t' +
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

	return {
		a1a2: a1a2,
		handshake: handshake,
		setOnError: setOnerror,
		setOnClose: setOnclose
	}
}
