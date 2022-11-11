import * as util from './../lib/util.js';
import nacl from './../lib/nacl-fast-es.js';

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

/**
 * JavaScript implementation of Salt Channel v2
 *
 */
 export function null_time_checker() {
	return {
		delayed: function() {
			return false
		},
		start: function() {},
		reset: function() {}
	}
}

export function null_time_keeper() {
	return {
		getTime: function() {
			return 0
		},
		reset: function() {}
	}
}

export function typical_time_checker(getCurrentTime, threshold = 5000) {

	let epoch

	function delayed(time) {
		if (!epoch) {
			start()
		}
		let expectedTime = getCurrentTime() - epoch
		return expectedTime > time + threshold
	}

	function start() {
		epoch = getCurrentTime()
	}

	function reset() {
		epoch = undefined
	}

	return {
		delayed: delayed,
		start: start,
		reset: reset
	}
}

export function typical_time_keeper(getCurrentTime) {

	let epoch
	function getTime() {
		if (epoch === undefined) {
			epoch = getCurrentTime()
			return 1
		}

		let t = getCurrentTime() - epoch
		if (t > 2147483647 || t < 0) {
			t = 2147483647
		}
		return t
	}

	function reset() {
		epoch = undefined
	}
	return {
		getTime: getTime,
		reset: reset
	}
}

export function asyncSocket(webSocket){
	let receiveQueue = util.waitQueue();
	const TIMEOUT_EVENT = 0
	const CLOSE_EVENT = 1
	const DATA_EVENT = 2

	function close() {
		webSocket.close()
	}

	function send(message) {
		if (message instanceof Uint8Array) {
			webSocket.send(message.buffer)
		} else {
			throw new TypeError('Must only send Uint8Array on WebSocket')
		}
	}

	async function receive(waitTime){
		let event = await receiveQueue.pull(waitTime);
		if (event[0] == null){
			return {type: TIMEOUT_EVENT}
		}
		else {
			return event[0]
		}
	}
	
	async function excpectData(waitTime){
		let event = await receive(waitTime)
		if (event.type == DATA_EVENT){
			return event.data
		}
		else if (event.type == TIMEOUT_EVENT){
			throw new Error("Timout waiting for data")
		}
		else {
			throw new Error("Other event then data was received: "+ event.type)
		}
	}
	
	webSocket.onmessage = function(event){
		receiveQueue.push( { 
			type: DATA_EVENT,
			data: new Uint8Array(event.data)
		});
	}
	webSocket.onclose = function(){
		receiveQueue.push( { 
				type: CLOSE_EVENT
		});
	}
	// ToDo add onerror
	// ToDo add onopen

	return {
		close: close,
		send: send,
		receive: receive,
		excpectData: excpectData,
		TIMEOUT_EVENT: TIMEOUT_EVENT,
		CLOSE_EVENT: CLOSE_EVENT,
		DATA_EVENT: DATA_EVENT
	}
}


function decrypt(message, storage) {
	let last = false
	if (validHeader(message, PacketTypeEncrypted, 0)) {
		// Regular message
	} else if (validHeader(message, PacketTypeEncrypted, 128)) {
		last = true
	} else {
		throw new Error('EncryptedMessage: Bad packet header. Expected 6 0 or 6 128, was '
			+ message[0] + ' ' + message[1])
	}

	let bytes = message.slice(2)
	let clear = nacl.secretbox.open(bytes, storage.theirNonce, storage.sessionKey)

	if (!clear) {
		throw new Error('EncryptedMessage: Could not decrypt message')
	}
	
	storage.theirNonce = increaseNonce2(storage.theirNonce)
	return {
		message: new Uint8Array(clear),
		last: last
	}
}

function validHeader(uints, first, second, offset = 0) {
	if (uints[offset] !== first | uints[offset + 1] !== second) {
		return false
	}
	return true
}

function getInt32(bytes) {
	return (new Int32Array(bytes.buffer))[0]
}

function setInt32(number) {
	let array = new Int32Array([number])
	return new Uint8Array(array.buffer)
}

function getUint16(bytes) {
	return (new Uint16Array(bytes.buffer))[0]
}

function setUint16(number) {
	let array = new Int16Array([number])
	return new Uint8Array(array.buffer)
}

function extactMessages(args){
	if (args.length === 2) {
		if (util.isArray(args[1])) {
			return args[1]
		} else {
			return [args[1]]
		}
	}
	else {
		return args.slice(1)
	}
}

function validateAndFix(messages){
	let results = []
	for (let message of messages) {
		let result = message
		if (message instanceof ArrayBuffer) {
			result = new Uint8Array(message)
		}
		else if (!(message instanceof Uint8Array)) {
			throw new TypeError('Expected data to be ArrayBuffer or Uint8Array')
		}

		if (result.length > 65535) {
			throw new RangeError('Application message ' + i + ' too large')
		}
		results.push(result)
	}
	return results
}

function sendAppPacket(last, message, storage, timeKeeper) {
	let time = setInt32(timeKeeper.getTime())

	let appPacket = new Uint8Array([
		PacketTypeApp,
		0,
		...time,
		...message
	])

	return encrypt(last, appPacket, storage)
}

function sendMultiAppPacket(last, messages, storage, timeKeeper) {
	if (messages.length > 65535) {
		throw new RangeError('Too many application messages')
	}

	let time = setInt32(timeKeeper.getTime())
	let count = setUint16(messages.length)

	let multiAppPacket = new Uint8Array([
		PacketTypeMultiApp,
		0,
		...time,
		...count
	])

	for (const message of messages){
		let size = setUint16(message.length)
		multiAppPacket = new Uint8Array([
			...multiAppPacket,
			...size,
			...message])
	};

	return encrypt(last, multiAppPacket, storage)
}

function encrypt(last, clearBytes, storage) {
	let body = nacl.secretbox(clearBytes, storage.myNonce, storage.sessionKey)
	storage.myNonce = increaseNonce2(storage.myNonce)

	let encryptedMessage = new Uint8Array([
		PacketTypeEncrypted,
		last ? 128 : 0,
		...body
	])

	return encryptedMessage
}

function createNonce(startValue){
	let nonce = new Uint8Array(nacl.secretbox.nonceLength)
	nonce[0] = startValue
	return nonce
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

function handleM1(m1){
	if (6 >= m1.length){
		throw new Error('M1 Length: To short massage. Length is '+ m1.length)
	} 
	if(!util.bufferEquals(m1.slice(0, 4), VERSION)){
		throw new Error('M1 Version: ' +m1.slice(0, 4) + ' Expected: ' + VERSION)
	}
	if (m1[4] != PacketTypeM1){
		throw new Error('M1 Header: ' + m1[4] + ' Expected: ' + PacketTypeM1)
	}
	if (!(m1[5] in [0, 1] )){
		throw new Error('M1 Header: ' + m1[5] + ' Expected: 0 or 1')
	}
	let expectedServKey = (m1[5] == 1)
	let expectedLength = 42 + (expectedServKey ? 0 : 32)
	if( m1.length == expectedLength){
		throw new Error('M1: Check packet length:' + m1.length)
	}

	let time = getInt32(m1.slice(6, 10))
	// ToDo check time

	return {
		publicEphemeral: m1.slice(10, 42),
		serverSigKey: expectedServKey ? null : m1.slice(42, 74) 
	}
}

function createM2(ephPublicKey, timeKeeper) { 
	let header = new Uint8Array([PacketTypeM2, 0])
	let time = setInt32(timeKeeper.getTime())
	let m2 = new Uint8Array([
		...header, 
		...time,
		...ephPublicKey])

	return m2;
}

function createM3(sigKeyPair, storage, m1Hash, m2Hash, timeKeeper) {
	let header = new Uint8Array([PacketTypeM3, 0])
	let time = setInt32(timeKeeper.getTime())
	let concat = new Uint8Array([...SIG_STR1_BYTES, ...m1Hash, ...m2Hash])
	let signature = nacl.sign.detached(concat, sigKeyPair.secretKey)
	let m3 = new Uint8Array([
		...header, 
		...time,
		...sigKeyPair.publicKey,
		...signature])

		let encrypted = encrypt(false, m3, storage)
		return encrypted
}

function handleM4(encryptedM4, storage, m1Hash, m2Hash, timeChecker) {

	let m4 = decrypt(new Uint8Array(encryptedM4), storage).message

	if(!util.bufferEquals(m4.slice(0, 2), [PacketTypeM4, 0])){
		throw new Error('M4: Check header: ' +m4.slice(0, 2) + ' Expected: ' + [PacketTypeM4, 0])
	}

	let time = getInt32(m4.slice(2,6))
	if (timeChecker.delayed(time)){
		throw new Error('M4: Check time to be set: ' +util.ab2hex(time))
	}

	let clientSigKey = m4.slice(6,38)
	let signature = m4.slice(38,102)
	let concat = new Uint8Array([...SIG_STR2_BYTES, ...m1Hash, ...m2Hash])
	let success = nacl.sign.detached.verify(concat, signature, clientSigKey)
	if (!success){
		throw new Error('M4: Could not verify signature')
	} 
	return clientSigKey
}

function padProtocol(prot){
	const totLength = 10
	const padChar = '-'.charCodeAt(0)
	if (prot.length > 10){
		throw new Error('Protocol indecator is to long '+prot.length)
	}
	return prot.concat(Array(totLength-prot.length).fill(padChar));
}

function checkProtocol(prot, message){
	return util.bufferEquals( prot,  message.slice(0, prot.length))
}

// =========== A1A2 MESSAGE EXCHANGE ================

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
	if (a2[0] != PacketTypeA2) {
		throw new Error('A2: Bad packet header. Message type was: '+a2[0])
	}
	if (a2[1] != 128) {
		if (a2[1] == 129) {
			throw new Error('A2: NoSuchServer exception')
		}
		else {
			throw new Error('A2: Unsupported adress type: '+a2[1])
		}	
	}
	let count = a2[2]
	if (count < 1 || count > 127) {
		throw new Error('A2: Count must be in range [1, 127], was: ' + count)
	}
	if (a2.length !== count*20 + 3) {
		throw new Error('A2: Expected packet length ' + (count*20 + 3) +
			' was ' + a2.length)
	}
	let prots = []
	for (let i = 0; i < count; i++) {
		let p1 = a2.slice(i*20+3,i*20+13)
		let p2 = a2.slice(i*20+13,i*20+23)
		for (let byte of p1){
			if (!validPStringChar(byte)) {
				throw new Error('A2: Invalid char in p1 "' + byte + '"')
			}
		}
		for (let byte of p2){
			if (!validPStringChar(byte)) {
				throw new Error('A2: Invalid char in p2 "' + byte + '"')
			}
		}
		prots[i] = {
			p1: String.fromCharCode(...p1),
			p2: String.fromCharCode(...p2)
		}
	}
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

function serverA1A2(protocols, message){
	if (util.bufferEquals(message.slice(2, 5), [0, 0, 0])){
		const LastFlag = 128
		const defaultExtra = [...'----------'].map(letter=>letter.charCodeAt(0))
	
		let a2 = new Uint8Array([
			PacketTypeA2,
			LastFlag,
			protocols.length,
		])
		for (let i = 0; i < protocols.length; i++) {
			a2 = new Uint8Array([
				...a2,
				...padProtocol(protocols[i]),
				...defaultExtra
			])
		}
		return a2
	}
	else {
		throw new Error('A1 with key request is not suported. Message: '+ message)
	}
}

function handleMessage(bytes, storage, timeChecker) {
	let clear = decrypt(bytes, storage)
	if (!clear) {
		throw new Error('Could not decrypt')
	}
	let rawMessage = clear.message;

	let time = getInt32(rawMessage.slice(2, 6))
	if (timeChecker.delayed(time)) {
		throw new Error('(Multi)AppPacket: Detected a delayed packet')
	}

	let messages
	if (validHeader(rawMessage, PacketTypeApp, 0)) {
		messages = handleAppPacket(rawMessage)
	} else if (validHeader(rawMessage, PacketTypeMultiApp, 0)) {
		messages = handleMultiAppPacket(rawMessage)
	} else {
		throw new Error('(Multi)AppPacket: Bad packet header. ' +
		'Expected 5 0 or 11 0, was ' + rawMessage[0] + ' ' + rawMessage[1])
	}
	return {
		messages: messages,
		last: clear.last
	}
}

function handleMultiAppPacket(multiAppPacket) {
	let count = getUint16(multiAppPacket.slice(6, 8))

	if (count === 0) {
		throw new Error('MultiAppPacket: Zero application messages')
	}

	let buffer = multiAppPacket.slice(8)
	let messages = []
	for (let i = 0; i < count; i++) {
		if (buffer.length < 2) {
			throw new Error('MultiAppPacket: Message missing length field')
		}
		let length = getUint16(buffer.slice(0, 2))
		if (buffer.length < 2+length) {
			throw new Error('MultiAppPacket: Incomplete message')
		}
		let data = buffer.slice(2, 2+length)
		messages.push(data);

		buffer = buffer.slice(2+length)
	}
	return messages
}

function handleAppPacket(appPacket) {
	return [appPacket.slice(6)]
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

function createM1(ephPublicKey, hostPub, timeKeeper) {

	let time = setInt32(timeKeeper.getTime())
	if (hostPub === undefined){
		hostPub = new Uint8Array()
	}
	let m1 = new Uint8Array([
		...VERSION,
		PacketTypeM1,
		(hostPub.length !== 0) ? 1 : 0,
		...time,
		...ephPublicKey,
		...hostPub
	])

	return m1
}

function handleM2(m2, timeChecker) {
	// Header
	if (validHeader(m2, PacketTypeM2, 0)) {

	} else if (validHeader(m2, 2, 129)) {
		throw new Error('M2: NoSuchServer exception')
	} else {
		throw new Error('M2: Bad packet header. Expected 2 0 or 2 129, was '
			+ m2[0] + ' ' + m2[1])
	}

	// Time
	let time = getInt32(m2.slice(2, 6))
	if (timeChecker.delayed(time)) {
		throw new Error('M2: Detected delayed packet')
	}

	let serverPub = m2.slice(6, 38)
	return serverPub
}

function handleM3(rawM3, storage, m1Hash, m2Hash, timeChecker) {
	let m3 = decrypt(rawM3, storage).message
	if (!m3) {
		throw new Error('EncryptedMessage: Could not decrypt message')
	}
	// Header
	if (!validHeader(m3, PacketTypeM3, 0)) {
		throw new Error('M3: Bad packet header. Expected 3 0, was ' +
			m3[0] + ' ' + m3[1])
	}

	// Time
	let time = getInt32(m3.slice(2, 6))
	if (timeChecker.delayed(time)) {
		throw new Error('M3: Detected delayed packet')
	}

	let serverPub = m3.slice(6, 38)

	let fingerprint = new Uint8Array([...SIG_STR1_BYTES, ...m1Hash, ...m2Hash])
	let signature = m3.slice(38, 102)
	let success = nacl.sign.detached.verify(fingerprint, signature, serverPub)
	if (!success) {
		throw new Error('M3: Could not verify signature')
	}

	return serverPub
}

function createM4(storage, signKeyPair, m1Hash, m2Hash, timeKeeper) {

	let time = setInt32(timeKeeper.getTime())
	let fingerprint = new Uint8Array([...SIG_STR2_BYTES, ...m1Hash, ...m2Hash])
	let signature = nacl.sign.detached(fingerprint, signKeyPair.secretKey)

	let m4 = new Uint8Array([
		PacketTypeM4,
		0,
		...time,
		...signKeyPair.publicKey,
		...signature
	])

	let encrypted = encrypt(false, m4, storage)
	return encrypted
}

export function client (webSocket, timeKeeper, timeChecker) {
	timeKeeper = (timeKeeper === undefined) ? typical_time_keeper(util.currentTimeMs) : timeKeeper;
	timeChecker = (timeChecker === undefined) ? typical_time_checker(util.currentTimeMs) : timeChecker;
	let saltState = STATE_INIT
	let messageQueue = [];
	const socket = asyncSocket(webSocket)
	let storage = {
		myNonce: createNonce(1),
		theirNonce: createNonce(2),
		sessionKey: null
	}

	function close() {
		saltState = STATE_CLOSED
		timeKeeper.reset()
		timeChecker.reset()
		socket.close()
	}

	async function receive(waitTime){
		try{
			let message = messageQueue.shift();
			if (message == undefined){
				if (saltState !== STATE_READY) {
					throw new Error('Invalid state: ' + saltState)
				}
				const event = await socket.receive(waitTime);
				if (event.type == socket.DATA_EVENT){
					let data = handleMessage(event.data, storage, timeChecker)
					if (data.last){
						saltState = STATE_LAST
					}
					messageQueue.push( ...data.messages )
					message = messageQueue.shift()
				}
			}
			if (messageQueue.length == 0 && saltState == STATE_LAST){
				close()
			}
			return {
				message: message.buffer, // ToDo What if message is undefined
				close: saltState == STATE_CLOSED
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	function send(last){
		try{
			if (saltState !== STATE_READY) {
				throw new Error('Invalid state: ' + saltState)
			}
			if (last) {
				saltState = STATE_LAST
			}

			let messages = extactMessages(Array.from(arguments))
			messages = validateAndFix(messages)
			if (messages.length === 1) {
				socket.send( sendAppPacket(last, messages[0], storage, timeKeeper))
			} else {
				socket.send( sendMultiAppPacket(last, messages, storage, timeKeeper))
			}

			if (last) {
				close()
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	function getState() {
		switch (webSocket.readyState) {
			case WS_OPEN:
				return saltState
			case WS_CLOSED:
			case WS_CLOSING:
				return STATE_CLOSED
			case WS_CONNECTING:
				return STATE_WAITING
		}
	}

	function closeAndThrow(err){
		close()
		saltState = STATE_ERR
		throw err
	}

	async function a1a2(adress) {
		try{
			if (saltState !== STATE_INIT) {
				throw new Error('A1A2: Invalid internal state: ' + saltState)
			}
			saltState = STATE_A1A2
			let a1 = createA1(adress)
			socket.send(a1)
			let a2 = await socket.excpectData(1000)
			saltState = STATE_INIT	
			return handleA2(a2)	
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	async function handshake(sigKeyPair, ephKeyPair, hostSigPub) {
		try{			
			if (saltState !== STATE_INIT) {
				throw new Error('Handshake: Invalid internal state: ' + saltState)
			}
			saltState = STATE_HAND

			verifySigKeyPair(sigKeyPair)
			verifyEphKeyPair(ephKeyPair)
			verifyHostSigPub(hostSigPub)

			let m1 = createM1(ephKeyPair.publicKey, hostSigPub, timeKeeper)
			socket.send(m1)
			let m2 = await socket.excpectData(1000)
			let serverPub = handleM2(m2, timeChecker)

			let m1Hash = nacl.hash(m1)
			let m2Hash = nacl.hash(m2)
			storage.sessionKey = nacl.box.before(serverPub, ephKeyPair.secretKey)

			let m3 = await socket.excpectData(1000)
			let serverSigPub = handleM3(m3, storage, m1Hash, m2Hash, timeChecker)
			if (hostSigPub !== undefined && !util.uint8ArrayEquals(serverSigPub, hostSigPub)) {
				throw new Error('Handshake: ServerSigKey does not match expected')
			}
			let m4 = createM4(storage, sigKeyPair, m1Hash, m2Hash, timeKeeper)
			socket.send(m4)
			
			saltState = STATE_READY
			return {
				close: close,
				send: send,
				receive: receive,
				getState: getState,
				serverSigPub: serverSigPub
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	return {
		a1a2: a1a2,
		handshake: handshake
	}
}

export function server(webSocket, timeKeeper, timeChecker) {
	timeKeeper = (timeKeeper === undefined) ? typical_time_keeper(util.currentTimeMs) : timeKeeper;
	timeChecker = (timeChecker === undefined) ? typical_time_checker(util.currentTimeMs) : timeChecker;
	let saltState = STATE_INIT
	let messageQueue = [];
	const socket = asyncSocket(webSocket)
	let storage = {
		myNonce: createNonce(2),
		theirNonce: createNonce(1),
		sessionKey: null
	}

	function close() {
		saltState = STATE_CLOSED
		timeKeeper.reset()
		timeChecker.reset()
		socket.close()
	}

	async function receive(waitTime){
		try{
			let message = messageQueue.shift();
			if (message == undefined){
				if (saltState !== STATE_READY) {
					throw new Error('Invalid state: ' + saltState)
				}
				const event = await socket.receive(waitTime);
				if (event.type == socket.DATA_EVENT){
					let data = handleMessage(event.data, storage, timeChecker)
					if (data.last){
						saltState = STATE_LAST
					}
					messageQueue.push( ...data.messages )
					message = messageQueue.shift()
				}
			}
			if (messageQueue.length == 0 && saltState == STATE_LAST){
				close()
			}
			return {
				message: message.buffer, // ToDo What if message is undefined
				close: saltState == STATE_CLOSED
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	function send(last){
		try{
			if (saltState !== STATE_READY) {
				throw new Error('Invalid state: ' + saltState)
			}
			if (last) {
				saltState = STATE_LAST
			}

			let messages = extactMessages(Array.from(arguments))
			messages = validateAndFix(messages)
			if (messages.length === 1) {
				socket.send( sendAppPacket(last, messages[0], storage, timeKeeper))
			} else {
				socket.send( sendMultiAppPacket(last, messages, storage, timeKeeper))
			}

			if (last) {
				close()
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	function getState() {
		switch (webSocket.readyState) {
			case WS_OPEN:
				return saltState
			case WS_CLOSED:
			case WS_CLOSING:
				return STATE_CLOSED
			case WS_CONNECTING:
				return STATE_WAITING
		}
	}

	function closeAndThrow(err){
		close()
		saltState = STATE_ERR
		throw err
	}

	async function runA1A2(protocols, waitTime) {
		try{
			if (saltState !== STATE_INIT) {
				throw new Error('Handshake: Invalid internal state: ' + saltState)
			}
			saltState = STATE_A1A2

			let message = await socket.excpectData(waitTime)
			if(message == null){ // No message
				return
			}
			else if (util.bufferEquals(message.slice(0, 2), [PacketTypeA1, 0])){ // Is A1
				socket.send( serverA1A2(protocols, message) )
				saltState = STATE_INIT
				return {
					protocol: "A1",
					message: ""
				}
			}
			else {
				for (let i = 0; i < protocols.length; i++) {
					let protocol = protocols[i]
					if (checkProtocol(protocol, message)){
						saltState = STATE_INIT
						return {
							protocol: protocol,
							message: message
						}
					}
				}
				throw new Error('Unknown protocol '+ message)
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	async function handshake(m1, sigKeyPair, ephKeyPair) {
		try {
			verifySigKeyPair(sigKeyPair)
			verifyEphKeyPair(ephKeyPair)
			if (saltState !== STATE_INIT) {
				throw new Error('Handshake: Invalid internal state: ' + saltState)
			}
			saltState = STATE_HAND
			let m1Return = handleM1(m1)
			if (!(m1Return.serverSigKey != null && !util.bufferEquals(m1Return.serverSigKey, sigKeyPair.publicKey))) {
				throw new Error('Handshake: Client try to to connect to missing singKeyPair')
			}
			let m2 = createM2(ephKeyPair.publicKey, timeKeeper)

			let m1Hash = nacl.hash(m1)
			let m2Hash = nacl.hash(m2)
			storage.sessionKey = nacl.box.before(m1Return.publicEphemeral, ephKeyPair.secretKey)

			let m3 = createM3(sigKeyPair, storage, m1Hash, m2Hash, timeKeeper)
			socket.send(m2)
			socket.send(m3)
			let m4 = await socket.excpectData(1000)
			let clientSigPub = handleM4(m4, storage, m1Hash, m2Hash, timeChecker)
			
			saltState = STATE_READY
			return {
				close: close,
				send: send,
				receive: receive,
				getState: getState,
				clientSigPub: clientSigPub
			}
		}
		catch (err){
			closeAndThrow(err)
		}
	}

	return {
		runA1A2: runA1A2,
		handshake: handshake
	}
}