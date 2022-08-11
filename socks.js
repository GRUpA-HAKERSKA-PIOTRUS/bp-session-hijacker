'use strict';
var net = require('net'),
    util = require('util'),
    DNS = require('dns'),
    log = function() {},
    info = function() {},
    errorLog = console.error.bind(console),
    SOCKS_VERSION5 = 5,
    SOCKS_VERSION4 = 4,
    USERPASS, AUTHENTICATION = {
        NOAUTH: 0x00,
        GSSAPI: 0x01,
        USERPASS: 0x02,
        NONE: 0xFF
    },
    REQUEST_CMD = {
        CONNECT: 0x01,
        BIND: 0x02,
        UDP_ASSOCIATE: 0x03
    },
    ATYP = {
        IP_V4: 0x01,
        DNS: 0x03,
        IP_V6: 0x04
    },
    Address = {
        read: function(buffer, offset) {
            if (buffer[offset] == ATYP.IP_V4) {
                return util.format('%s.%s.%s.%s', buffer[offset + 1], buffer[offset + 2], buffer[offset + 3], buffer[offset + 4])
            } else if (buffer[offset] == ATYP.DNS) {
                return buffer.toString('utf8', offset + 2, offset + 2 + buffer[offset + 1])
            } else if (buffer[offset] == ATYP.IP_V6) {
                return buffer.slice(buffer[offset + 1], buffer[offset + 1 + 16])
            }
        },
        sizeOf: function(buffer, offset) {
            if (buffer[offset] == ATYP.IP_V4) {
                return 4
            } else if (buffer[offset] == ATYP.DNS) {
                return buffer[offset + 1]
            } else if (buffer[offset] == ATYP.IP_V6) {
                return 16
            }
        }
    },
    Port = {
        read: function(buffer, offset) {
            if (buffer[offset] == ATYP.IP_V4) {
                return buffer.readUInt16BE(8)
            } else if (buffer[offset] == ATYP.DNS) {
                return buffer.readUInt16BE(5 + buffer[offset + 1])
            } else if (buffer[offset] == ATYP.IP_V6) {
                return buffer.readUInt16BE(20)
            }
        },
    };

function createSocksServer(cb, userpass) {
    USERPASS = userpass;
    var socksServer = net.createServer();
    socksServer.on('listening', function() {
        var address = socksServer.address();
        console.log('listening %s:%d', address.address, address.port)
    });
    socksServer.on('connection', function(socket) {
        info('CONNECTED %s:%d', socket.remoteAddress, socket.remotePort);
        initSocksConnection.bind(socket)(cb)
    });
    return socksServer
}

function initSocksConnection(on_accept) {
    this.on('error', function(e) {
        errorLog('%j', e)
    });
    this.handshake = handshake.bind(this);
    this.on_accept = on_accept;
    this.once('data', this.handshake)
}

function handshake(chunk) {
    if (chunk[0] == SOCKS_VERSION5) {
        this.socksVersion = SOCKS_VERSION5;
        this.handshake5 = handshake5.bind(this);
        this.handshake5(chunk)
    } else if (chunk[0] == SOCKS_VERSION4) {
        this.socksVersion = SOCKS_VERSION4;
        this.handshake4 = handshake4.bind(this);
        this.handshake4(chunk)
    } else {
        errorLog('handshake: wrong socks version: %d', chunk[0]);
        this.end()
    }
}

function handshake5(chunk) {
    var method_count = 0;
    if (chunk[0] != SOCKS_VERSION5) {
        errorLog('socks5 handshake: wrong socks version: %d', chunk[0]);
        this.end();
        return
    }
    method_count = chunk[1];
    this.auth_methods = [];
    for (var i = 2; i < method_count + 2; i++) {
        this.auth_methods.push(chunk[i])
    }
    log('Supported auth methods: %j', this.auth_methods);
    var resp = new Buffer(2);
    resp[0] = 0x05;
    if (USERPASS) {
        if (this.auth_methods.indexOf(AUTHENTICATION.USERPASS) > -1) {
            log('Handing off to handleAuthRequest');
            this.handleAuthRequest = handleAuthRequest.bind(this);
            this.once('data', this.handleAuthRequest);
            resp[1] = AUTHENTICATION.USERPASS;
            this.write(resp)
        } else {
            errorLog('Unsuported authentication method -- disconnecting');
            resp[1] = 0xFF;
            this.end(resp)
        }
    } else if (this.auth_methods.indexOf(AUTHENTICATION.NOAUTH) > -1) {
        log('Handing off to handleConnRequest');
        this.handleConnRequest = handleConnRequest.bind(this);
        this.once('data', this.handleConnRequest);
        resp[1] = AUTHENTICATION.NOAUTH;
        this.write(resp)
    } else {
        errorLog('Unsuported authentication method -- disconnecting');
        resp[1] = 0xFF;
        this.end(resp)
    }
}

function handshake4(chunk) {
    var cmd = chunk[1],
        address, port, uid;
    if (chunk[0] !== SOCKS_VERSION4) {
        this.end(new Buffer([0x00, 0x5b]));
        errorLog('socks4 handleConnRequest: wrong socks version: %d', chunk[0]);
        return
    }
    port = chunk.readUInt16BE(2);
    if ((chunk[4] == 0 && chunk[5] == chunk[6] == 0) && (chunk[7] != 0)) {
        var it = 0;
        uid = '';
        for (it = 0; it < 1024; it++) {
            uid += chunk[8 + it];
            if (chunk[8 + it] == 0x00) break
        }
        address = '';
        if (chunk[8 + it] == 0x00) {
            for (it++; it < 2048; it++) {
                address += chunk[8 + it];
                if (chunk[8 + it] == 0x00) break
            }
        }
        if (chunk[8 + it] == 0x00) {
            DNS.lookup(address, function(err, ip, family) {
                if (err) {
                    errorLog(err + ',socks4a dns lookup failed');
                    this.end(new Buffer([0x00, 0x5b]));
                    return
                } else {
                    this.socksAddress = ip;
                    this.socksPort = port;
                    this.socksUid = uid;
                    log('socks4a Request: type: %d -- to: %s:%d:%s', cmd, address, port, uid);
                    if (cmd == REQUEST_CMD.CONNECT) {
                        this.request = chunk;
                        this.on_accept(this, port, ip, proxyReady4.bind(this))
                    } else {
                        this.end(new Buffer([0x00, 0x5b]));
                        return
                    }
                }
            })
        } else {
            this.end(new Buffer([0x00, 0x5b]));
            return
        }
    } else {
        address = util.format('%s.%s.%s.%s', chunk[4], chunk[5], chunk[6], chunk[7]);
        uid = '';
        for (it = 0; it < 1024; it++) {
            uid += chunk[8 + it];
            if (chunk[8 + it] == 0x00) break
        }
        this.socksAddress = address;
        this.socksPort = port;
        this.socksUid = uid;
        log('socks4 Request: type: %d -- to: %s:%d:%s', cmd, address, port, uid);
        if (cmd == REQUEST_CMD.CONNECT) {
            this.request = chunk;
            this.on_accept(this, port, address, proxyReady4.bind(this))
        } else {
            this.end(new Buffer([0x00, 0x5b]));
            return
        }
    }
}

function handleAuthRequest(chunk) {
    var username, password;
    if (chunk[0] !== 1) {
        this.end(new Buffer([0x01, 0x01]));
        errorLog('socks5 handleAuthRequest: wrong socks version: %d', chunk[0]);
        return
    }
    try {
        var na = [],
            pa = [],
            ni, pi;
        for (ni = 2; ni < (2 + chunk[1]); ni++) na.push(chunk[ni]);
        username = new Buffer(na).toString('utf8');
        for (pi = ni + 1; pi < (ni + 1 + chunk[ni]); pi++) pa.push(chunk[pi]);
        password = new Buffer(pa).toString('utf8')
    } catch (e) {
        this.end(new Buffer([0x01, 0x01]));
        errorLog('socks5 handleAuthRequest: username/password ' + e);
        return
    }
    if (USERPASS && USERPASS.username === username && USERPASS.password === password) {
        log('Handing off to handleConnRequest');
        this.handleConnRequest = handleConnRequest.bind(this);
        this.once('data', this.handleConnRequest);
        this.write(new Buffer([0x01, 0x00]))
    } else {
        this.end(new Buffer([0x01, 0x01]));
        errorLog('socks5 handleConnRequest: wrong socks version: %d', chunk[0]);
        return
    }
}

function handleConnRequest(chunk) {
    var cmd = chunk[1],
        address, port, offset = 3;
    if (chunk[0] !== SOCKS_VERSION5) {
        this.end(new Buffer([0x05, 0x01]));
        errorLog('socks5 handleConnRequest: wrong socks version: %d', chunk[0]);
        return
    }
    try {
        address = Address.read(chunk, 3);
        port = Port.read(chunk, 3)
    } catch (e) {
        errorLog('socks5 handleConnRequest: Address.read ' + e);
        return
    }
    log('socks5 Request: type: %d -- to: %s:%d', chunk[1], address, port);
    if (cmd == REQUEST_CMD.CONNECT) {
        this.request = chunk;
        this.on_accept(this, port, address, proxyReady5.bind(this))
    } else {
        this.end(new Buffer([0x05, 0x01]));
        return
    }
}

function proxyReady5() {
    log('Indicating to the client that the proxy is ready');
    var resp = new Buffer(this.request.length);
    this.request.copy(resp);
    resp[0] = SOCKS_VERSION5;
    resp[1] = 0x00;
    resp[2] = 0x00;
    this.write(resp);
    log('socks5 Connected to: %s:%d', Address.read(resp, 3), resp.readUInt16BE(resp.length - 2))
}

function proxyReady4() {
    log('Indicating to the client that the proxy is ready');
    var resp = new Buffer(8);
    resp[0] = 0x00;
    resp[1] = 0x5a;
    resp.writeUInt16BE(this.socksPort, 2);
    var ips = this.socksAddress.split('.');
    resp.writeUInt8(parseInt(ips[0]), 4);
    resp.writeUInt8(parseInt(ips[1]), 5);
    resp.writeUInt8(parseInt(ips[2]), 6);
    resp.writeUInt8(parseInt(ips[3]), 7);
    this.write(resp);
    log('socks4 Connected to: %s:%d:%s', this.socksAddress, this.socksPort, this.socksUid)
}
module.exports = {
    createServer: createSocksServer
};