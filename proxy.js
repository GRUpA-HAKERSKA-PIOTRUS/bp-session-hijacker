var net = require('net'),
  socks = require('./socks.js'),
  info = console.log.bind(console)
var bpsocket
var clientsckt
var handshake
var serverrr
var porttt
var servera = net
  .createServer(function (d) {
    while (true) {
      switch (e[f++]) {
        case '0':
          b.connect(porttt, serverrr, function () {})
          continue
        case '1':
          b.on('data', function (b) {
            if (c == 0) {
              bpsocket.write(b)
            }
            d.write(b)
          })
          continue
        case '2':
          setTimeout(function () {
            c = 1
          }, 300)
          continue
        case '3':
          d.on('data', function (d) {
            if (c == 0 && d[2] == 47) {
              d = handshake
            }
            b.write(d)
          })
          continue
        case '4':
          clientsckt = b
          continue
        case '5':
          var b = new net.Socket()
          continue
        case '6':
          var c = 0
          continue
      }
      break
    }
  })
  .listen(100)
var HOST = '127.0.0.1',
  PORT = '8082',
  server = socks.createServer(
    function (b, j, i, k) {
      while (true) {
        switch (g[h++]) {
          case '0':
            a.on(
              'close',
              function (e) {
                try {
                  if (f && d) {
                    console.log('The proxy %s:%d closed', f, d)
                  } else {
                    console.error('Connect to %s:%d failed', i, j)
                  }
                  b.end()
                } catch (a) {}
              }.bind(this)
            )
            continue
          case '1':
            var a = net.createConnection(
              {
                port: j,
                host: i,
                localAddress: process.argv[2] || undefined,
              },
              k
            )
            continue
          case '2':
            a.on('error', function (b) {})
            continue
          case '3':
            var f, d
            continue
          case '4':
            b.on(
              'close',
              function (d) {
                try {
                  if (this.proxy !== undefined) {
                    a.removeAllListeners('data')
                    a.end()
                  }
                } catch (a) {}
              }.bind(this)
            )
            continue
          case '5':
            a.on(
              'connect',
              function () {
                while (true) {
                  switch (g[h++]) {
                    case '0':
                      porttt = a.remotePort
                      continue
                    case '1':
                      f = a.localAddress
                      continue
                    case '2':
                      info(
                        '%s:%d <== %s:%d ==> %s:%d',
                        b.remoteAddress,
                        b.remotePort,
                        a.localAddress,
                        a.localPort,
                        a.remoteAddress,
                        a.remotePort
                      )
                      continue
                    case '3':
                      d = a.localPort
                      continue
                    case '4':
                      serverrr = a.remoteAddress
                      continue
                  }
                  break
                }
              }.bind(this)
            )
            continue
          case '6':
            b.on('data', function (d) {
              try {
                bpsocket = b
                if (d[2] == 47) {
                  console.log('MAMY TO')
                  handshake = d
                }
                if (
                  d.toString().search('PrList') != -1 ||
                  d.toString().toLowerCase().search('epack') != -1 ||
                  d.toString().toLowerCase().search('cpack') != -1 ||
                  d.toString().toLowerCase().search('auth') != -1
                ) {
                  clientsckt.write(d)
                }
              } catch (a) {}
            })
            continue
          case '7':
            a.on('data', function (c) {
              try {
              } catch (c) {}
            })
            continue
          case '8':
            b.on('error', function (b) {})
            continue
        }
        break
      }
    },
    process.argv[3] &&
      process.argv[4] && {
        username: process.argv[3],
        password: process.argv[4],
      }
  )
server.on('error', function (c) {
  console.error('SERVER ERROR: %j', c)
  if (c.code == 'EADDRINUSE') {
    console.log('Address in use, retrying in 10 seconds...')
    setTimeout(function () {
      console.log('Reconnecting to %s:%s', HOST, PORT)
      server.close()
      server.listen(PORT, HOST)
    }, 10000)
  }
})
server.listen(PORT, HOST)
