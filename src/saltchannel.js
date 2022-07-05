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
	const SIG_STR1_BYTES = [...SIG_STR_1].map(letter=>letter.charCodeAt(0))
	const SIG_STR2_BYTES = [...SIG_STR_2].map(letter=>letter.charCodeAt(0))
	const VERSION = [...VERSION_STR].map(letter=>letter.charCodeAt(0))

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

	const PacketTypeM1  = 1
	const PacketTypeM2  = 2
	const PacketTypeM3  = 3
	const PacketTypeM4  = 4
	const PacketTypeApp = 5
	const PacketTypeA1  = 8
	const PacketTypeA2  = 9
	const PacketTypeEncrypted = 6
	const PacketTypeMultiApp = 11

	const WS_CONNECTING = 0
	const WS_OPEN = 1
	const WS_CLOSING = 2
	const WS_CLOSED = 3

	let eNonce
	let dNonce
	let sessionKey
	let receiveQueue = util.waitQueue();
	let messageQueue = [];
	let closeTrigger = util.triggWaiter()

	timeKeeper = (timeKeeper) ? timeKeeper : getTimeKeeper(util.currentTimeMs)
	timeChecker = (timeChecker) ? timeChecker : getTimeChecker(util.currentTimeMs)
	let saltState

	init()

	function close() {
		eNonce = undefined
		dNonce = undefined
		sessionKey = undefined

		saltState = STATE_CLOSED

		timeKeeper.reset()
		timeChecker.reset()

		closeTrigger.trigg()
		ws.close()
	}

	function init() {
		eNonce = new Uint8Array(nacl.secretbox.nonceLength)
		dNonce = new Uint8Array(nacl.secretbox.nonceLength)
		eNonce[0] = 1
		dNonce[0] = 2

		saltState = STATE_INIT

		ws.onmessage = function(event){
			receiveQueue.push(new Uint8Array(event.data));
		}
	}

	async function receiveData(waitTime){
		return (await receiveQueue.pull(waitTime))[0];
	}

	async function receive(waitTime){
		let message = messageQueue.shift();
		if (message == undefined){
			let data = await Promise.race([
				receiveData(waitTime), 
				closeTrigger.waiter(waitTime+1000)
			])
			if (data != null){
				handleMessage(data)
				message = messageQueue.shift()
			}
		}
		return {
			message: message.buffer,
			close: saltState == STATE_CLOSED
		}
	}

	// =========== A1A2 MESSAGE EXCHANGE ================
	async function a1a2(adress) {
		if (saltState !== STATE_INIT) {
			throw new Error('A1A2: Invalid internal state: ' + saltState)
        }
		saltState = STATE_A1A2

		let a1 = createA1(adress)
        sendOnWs(a1)
		let a2 = await receiveData(1000)
		let prots = handleA2(a2)
		return prots
    }

    function createA1(address) {
		let header = new Uint8Array([PacketTypeA1, 0])
		let type = (address == null ? ADDR_TYPE_ANY : ADDR_TYPE_PUB)
		if (address == null) {
			address = new Uint8Array([])
		}
		let count = new Uint8Array( (new Int16Array([address.length])).buffer)

		let packet = new Uint8Array([
			...header, 
			type,
			...count,
			...address])

    	return packet
    }

    function handleA2(a2) {
    	if (saltState !== STATE_A1A2) {
    		closeAndThrow('A2: Invalid internal state: ' + saltState)
    	}

        if (a2[0] != PacketTypeA2) {
			closeAndThrow('A2: Bad packet header. Message type was: '+a2[0])
        }
		if (a2[1] != 128) {
			if (a2[1] == 129) {
				closeAndThrow('A2: NoSuchServer exception')
			}
			else {
				closeAndThrow('A2: Bad packet header. Message info was: '+a2[1])
			}	
        }

        let count = a2[2]

        if (count < 1 || count > 127) {
            closeAndThrow('A2: Count must be in range [1, 127], was: ' + count)
        }

        if (a2.length !== count*20 + 3) {
            closeAndThrow('A2: Expected packet length ' + (count*20 + 3) +
            	' was ' + a2.length)
        }

        let prots = []
        for (let i = 0; i < count; i++) {
        	let p1 = a2.slice(i*20+3,i*20+13)
        	let p2 = a2.slice(i*20+13,i*20+23)

			for (let byte of p1){
				if (!validPStringChar(byte)) {
					closeAndThrow('A2: Invalid char in p1 "' + byte + '"')
				}
			}
			for (let byte of p2){
				if (!validPStringChar(byte)) {
					closeAndThrow('A2: Invalid char in p2 "' + byte + '"')
				}
			}

            prots[i] = {
				p1: String.fromCharCode(...p1),
				p2: String.fromCharCode(...p2)
			}
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
			closeAndThrow('Handshake: Invalid internal state: ' + saltState)
		}
		saltState = STATE_HAND

		let m1 = createM1(ephKeyPair.publicKey, hostSigPub)
		sendOnWs(m1)
		let m2 = await receiveData(1000)
		let serverPub = handleM2(m2)

		sessionKey = nacl.box.before(serverPub, ephKeyPair.secretKey)
		let m1Hash = nacl.hash(m1)
		let m2Hash = nacl.hash(m2)

		let m3 = await receiveData(1000)
		handleM3(m3, hostSigPub, m1Hash, m2Hash)
		let m4 = createM4(sigKeyPair, m1Hash, m2Hash)
		sendOnWs(m4)
		
		saltState = STATE_READY

		return {
			send: send,
			receive: receive,
			getState: getState
		}
	}

	function closeAndThrow(msg){
		saltState = STATE_ERR
		close()
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

	function createM1(ephPublicKey, hostPub) {
		let m1Len = (hostPub) ? 74 : 42
		let m1 = new Uint8Array(m1Len)

		m1.set(VERSION)

		// Header
		m1[4] = 1	// Packet type 1
		m1[5] = (hostPub) ? 1 : 0

		// Time
		setInt32(m1, timeKeeper.getTime(), 6)

		// ClientEncKey
		m1.set(ephPublicKey, 10)

		// ServerSigKey
		if (hostPub) {
			m1.set(hostPub, 42)
		}

		return m1
	}

	function handleM2(m2) {
		if (saltState !== STATE_HAND) {
    		closeAndThrow('M2: Invalid internal state: ' + saltState)
    	}

		// Header
		if (validHeader(m2, 2, 0)) {

		} else if (validHeader(m2, 2, 129)) {
			closeAndThrow('M2: NoSuchServer exception')
		} else {
			closeAndThrow('M2: Bad packet header. Expected 2 0 or 2 129, was '
				+ m2[0] + ' ' + m2[1])
		}

		// Time
		let time = getInt32(m2, 2)
		if (time === 0) {
			timeChecker = getNullTimeChecker()
		} else if (time !== 1){
			closeAndThrow('M2: Invalid time value ' + time)
		}

		let serverPub = getUints(m2, 32, 6)
		return serverPub
	}

	function handleM3(data, hostPub, m1Hash, m2Hash) {
		if (saltState !== STATE_HAND) {
    		closeAndThrow('M3: Invalid internal state: ' + saltState)
    	}

		let m3 = decrypt(data)
		if (!m3) {
			closeAndThrow('EncryptedMessage: Could not decrypt message')
		}
		// Header
		if (!validHeader(m3, 3, 0)) {
			closeAndThrow('M3: Bad packet header. Expected 3 0, was ' +
				m3[0] + ' ' + m3[1])
		}

		// Time
		let time = getInt32(m3, 2)
		if (timeChecker.delayed(time)) {
			closeAndThrow('M3: Detected delayed packet')
		}

		let serverPub = m3.slice(6, 38)
		if (hostPub) {
			if (!util.uint8ArrayEquals(serverPub, hostPub)) {
				closeAndThrow('M3: ServerSigKey does not match expected')
			}
		}

		
		let fingerprint = new Uint8Array([...SIG_STR1_BYTES, ...m1Hash, ...m2Hash])
		let signature = m3.slice(38, 102)
		let success = nacl.sign.detached.verify(fingerprint, signature, serverPub)
		if (!success) {
			closeAndThrow('M3: Could not verify signature')
		}
	}

	function createM4(signKeyPair, m1Hash, m2Hash) {
		// Create m4
		let m4 = new Uint8Array(102)

		// Header
		m4[0] = 4

		m4.set(signKeyPair.publicKey, 6)

		let fingerprint = new Uint8Array([...SIG_STR2_BYTES, ...m1Hash, ...m2Hash])
		let signature = nacl.sign.detached(fingerprint, signKeyPair.secretKey)

		m4.set(signature, 38)

		setInt32(m4, timeKeeper.getTime(), 2)

		let encrypted = encrypt(false, m4)

		return encrypted
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

	function handleMessage(bytes) {
		if (saltState !== STATE_READY) {
			closeAndThrow('Received message when salt channel was not ready')
		}

		let clear = decrypt(bytes)
		if (!clear) {
			return
		}

		let time = getInt32(clear, 2)
		if (timeChecker.delayed(time)) {
			closeAndThrow('(Multi)AppPacket: Detected a delayed packet')
		}

		if (validHeader(clear, 5, 0)) {
			handleAppPacket(clear)
		} else if (validHeader(clear, 11, 0)) {
			handleMultiAppPacket(clear)
		} else {
			closeAndThrow('(Multi)AppPacket: Bad packet header. ' +
			'Expected 5 0 or 11 0, was ' + clear[0] + ' ' + clear[1])
		}
		if (saltState === STATE_LAST) {
			close()
		}
	}

	function handleMultiAppPacket(multiAppPacket) {
		let count = getUint16(multiAppPacket, 6)

		if (count === 0) {
			closeAndThrow('MultiAppPacket: Zero application messages')
		}

		let offset = 2 + 4 + 2
		for (let i = 0; i < count; i++) {
			let length = getUint16(multiAppPacket, offset)
			offset += 2

			let data = getUints(multiAppPacket, length, offset)
			offset += length

			messageQueue.push(data);
		}
	}

	function handleAppPacket(appPacket) {

		let data = getUints(appPacket, appPacket.length - 6, 6)
		messageQueue.push(data);
	}

	function sendOnWs(message) {
		if (message instanceof Uint8Array) {
			ws.send(message.buffer)
		} else {
			throw new TypeError('Must only send Uint8Array on WebSocket')
		}
	}

	function decrypt(message) {
		if (validHeader(message, 6, 0)) {
			// Regular message
		} else if (validHeader(message, 6, 128)) {
			// Last message
			saltState = STATE_LAST;
		} else {
			closeAndThrow('EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was '
				+ message[0] + ' ' + message[1])
		}

		let bytes = new Uint8Array(message.byteLength - 2)
		let msg = new Uint8Array(message)

		for (let i = 0; i < message.byteLength - 2; i++) {
			bytes[i] = msg[i+2]
		}

		let clear = nacl.secretbox.open(bytes, dNonce, sessionKey)
		dNonce = increaseNonce2(dNonce)

		if (!clear) {
			closeAndThrow('EncryptedMessage: Could not decrypt message')
		}
		clear = new Uint8Array(clear)

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
			closeAndThrow('Invalid state: ' + saltState)
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
		sendOnWs(encrypted)
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
		sendOnWs(encrypted)
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
			closeAndThrow('Expected Uint8Array. \n\t' +
						'Input: ' + nonce)
		}
		if (!(nonce.length === nacl.secretbox.nonceLength)) {
			closeAndThrow('Unexpected nonce length. \n\t' +
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
		handshake: handshake
	}
}