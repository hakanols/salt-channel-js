# salt-channel-js
A JavaScript implementation of a Salt Channel client. Client-side code that connects on top of WebSocket

## Dependencies
Salt Channel is based on [TweetNaCl](http://tweetnacl.cr.yp.to/) and SaltChannel.js uses [TweetNaCl-es6.js](https://github.com/hakanols/tweetnacl-es6) which has no dependencies.

## Usage
Download the source code and include using import.

    import saltchannel from 'path/to/saltchannel.js';

## Testing
To run test in Node.js:

    $ npm run test
    $ npm run browser

To run test in browser:
* [browser test](https://hakanols.github.io/salt-channel-js/test/runJs.html?file=runAll.js)
