import * as util from '../lib/util.js';

export function createMockSocket(){

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


export function createErrorWaiter(sc){
    let errorQueue = util.waitQueue();
    sc.setOnError(function(err) {
        errorQueue.push(err.message);
    })
    return async function(waitTime){
        return (await errorQueue.pull(waitTime))[0];
    }
}