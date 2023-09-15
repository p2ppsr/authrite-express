const bsv = require('babbage-bsv')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const cryptononce = require('cryptononce')
const authriteUtils = require('authrite-utils')
const AUTHRITE_VERSION = '0.1'

const getAuthResponseHeaders = require('./utils/getAuthResponseHeaders')
const validateAuthHeaders = require('./utils/validateAuthHeaders')

/**
 * Provides server-side access to Authrite protected sockets
 */
class AuthSock {
  constructor (http, options) {
    // Initialize necessary server properties
    this.socket = require('socket.io')(http, options)
    this.broadcast = this.socket.broadcast
    this.serverPrivateKey = options.serverPrivateKey
    this.serverNonce = cryptononce.createNonce(this.serverPrivateKey)

    /**
     * Configure web sockets initial connection middleware
     */
    this.socket.use((socket, next) => {
      this.setAuthenticationMiddleware(socket, next)
    })
  }

  /**
   * Retrieves the unique identifier for the socket connection
   * @returns {string} - The socket ID
   */
  get id () {
    return this.socket.id
  }

  /**
   * Retrieves the list of rooms that the socket is currently in
   * @returns {Set<string>} - A set containing the names of the rooms
   */
  get rooms () {
    return this.socket.rooms
  }

  /**
   * Retrieves information about the initial handshake when the socket connection was established
   * @returns {Object} - Handshake information including headers, address, secure, etc.
   */
  get handshake () {
    return this.socket.handshake
  }

  setAuthenticationMiddleware (socket, next) {
    try {
      if (socket.request.headers['x-authrite'] === AUTHRITE_VERSION) {
        // Get initial request params
        this.clientPublicKey = socket.request.headers['x-authrite-identity-key']
        this.clientNonce = socket.request.headers['x-authrite-nonce']
        const message = this.clientNonce + this.serverNonce

        // Get response headers for authentication
        // TODO: consider if an error is thrown, what should be the response.
        // Connection terminated?
        const headers = getAuthResponseHeaders({
          authrite: AUTHRITE_VERSION,
          messageType: 'initialResponse',
          serverPrivateKey: this.serverPrivateKey,
          clientPublicKey: this.clientPublicKey,
          clientNonce: this.clientNonce,
          serverNonce: this.serverNonce,
          messageToSign: message,
          certificates: [],
          requestedCertificates: socket.request.headers['x-authrite-requested-certificates']
        })
        // Send the initial request response to the client
        socket.emit('validationResponse', headers)
        next()
      } else {
        next(new Error('invalid'))
      }
    } catch (error) {
      console.error(error)
    }
  }

  /**
   * Registers a middleware function to intercept events on the socket
   * @param {Socket} socket - The socket object to apply the middleware to
   * @param {function} next - The callback function to call after the middleware completes
   */
  use (socket, next) {
  // TODO: Test this function
    this.setAuthenticationMiddleware(socket, next)
    this.socket.use(socket, next)
  }

  /**
   * Joins the socket to a specified room
   * @param {string} room - The name of the room to join
   */
  join (room) {
    this.socket.join(room)
  }

  /**
   * Leaves a specified room
   * @param {string} room - The name of the room to leave
   */
  leave (room) {
    this.socket.leave(room)
  }

  /**
   * Sends a message to all clients in a specified room
   * @param {string} room - The name of the room to send the message to
   * @returns {Socket} - A reference to the socket
   */
  to (room) {
    return this.socket.to(room)
  }

  /**
   * Disconnects the socket from the server
   */
  disconnect () {
    this.socket.disconnect()
  }

  /**
   * Emits a message to the client
   * @param {*} event
   * @param {*} data
   */
  emit (event, data) {
    try {
      // Get auth headers to send to client
      const headers = getAuthResponseHeaders({
        authrite: AUTHRITE_VERSION,
        messageType: 'response',
        serverPrivateKey: this.serverPrivateKey,
        clientPublicKey: this.clientPublicKey,
        clientNonce: this.clientNonce,
        serverNonce: cryptononce.createNonce(this.serverPrivateKey),
        messageToSign: JSON.stringify(data),
        certificates: [],
        requestedCertificates: [] // TODO Add support
      })

      // Send the initial data + auth headers
      this.socket.emit(event, {
        headers,
        data
      })
    } catch (error) {
      console.error(error)
      // TODO: Figure out optimal socket server-side error handling
    }
  }

  /**
   * Custom configured web sockets on method
   * @param {*} event
   * @param {function} callback
   */
  on (event, callback) {
    // Keep track of the current instance
    const authSockInstance = this
    if (typeof callback === 'function') {
      // Construct a callback which wraps the custom callback
      const modifiedCallback = (socket) => {
        // Keep track of the original socket on function
        const originalOn = socket.on
        const originalEmit = socket.emit

        // Define a new socket on function for any inner on event callbacks defined
        socket.on = function (event, innerCallback) {
          // Define a custom wrapped callback to authenticate headers provided
          const wrappedInnerCallback = (body) => {
            // Call the helper auth function
            authSockInstance.authenticateRequest({
              messageToSign: JSON.stringify(body.data),
              authHeaders: body.headers
            })
            // Invoke the expected inner callback function
            innerCallback(body.data)
          }
          // Invoke the wrapped callback
          originalOn.call(this, event, wrappedInnerCallback)
        }

        // Define a new wrapped socket.emit function
        socket.emit = function (event, ...args) {
          // Modify the data or perform any custom actions here
          const headers = getAuthResponseHeaders({
            authrite: AUTHRITE_VERSION,
            messageType: 'response',
            serverPrivateKey: authSockInstance.serverPrivateKey,
            clientPublicKey: authSockInstance.clientPublicKey,
            clientNonce: authSockInstance.clientNonce,
            serverNonce: cryptononce.createNonce(authSockInstance.serverPrivateKey),
            messageToSign: JSON.stringify(...args),
            certificates: [],
            requestedCertificates: [] // TODO Add support
          })
          // Invoke the wrapped callback
          originalEmit.call(this, event, {
            ...args,
            headers
          })
        }
        // Call the original callback function with the modified socket
        callback(socket)
      }

      this.socket.on(event, modifiedCallback)
    } else {
      this.socket.on(event, callback)
    }
  }

  authenticateRequest ({ messageToSign, authHeaders }) {
    try {
      // Validate request headers
      const verified = validateAuthHeaders(messageToSign, authHeaders, this.serverPrivateKey)
      if (!verified) {
        // TODO: Define standard for sending error notifications...?
        this.socket.emit('serverResponse', {
          status: 'error',
          code: 'ERR_AUTHRITE_INVALID_SIGNATURE',
          description: 'The server was unable to verify this Authrite request\'s message signature.'
        })
      } else {
        // Update the client nonce to be the last request nonce used
        // This allows future requests to the client to succeed
        this.clientNonce = authHeaders['x-authrite-nonce']
        console.log('Client message verified!')
      }
    } catch (error) {
      console.error(error)
      // TODO: Figure out optimal socket server-side error handling
    }
  }
}

/**
 * Authrite express middleware for providing mutual authentication with a client
 * @param {object} config Configures the middleware with initial parameters
 * @param {String} config.serverPrivateKey The server's private key used for derivations
 * @param {Object} config.requestedCertificates The RequestedCertificateSet that the server will send to client. An object with `certifiers` and `types`, as per the Authrite specification.
 * @param {String} config.baseUrl The base url of the express server
 * @param {String} config.initialRequestPath The initial route path used to request the server's information and identity key
 * @returns {function} Which can be used as authentication middleware in an express server
 */
const middleware = (config = {}) => {
  if (!config.baseUrl || typeof config.baseUrl !== 'string') {
    const e = new Error(
      'Authrite middleware requires a valid baseUrl string in its configuration object'
    )
    e.code = 'ERR_NO_BASEURL'
    throw e
  }
  if (
    !config.baseUrl.startsWith('http://') &&
    !config.baseUrl.startsWith('https://')
  ) {
    const e = new Error(
      'Authrite middleware requires the baseUrl to start with http:// or https://'
    )
    e.code = 'ERR_MALFORMED_BASEURL'
    throw e
  }
  if (!config.initialRequestPath) {
    config.initialRequestPath = '/authrite/initialRequest'
  }
  if (!config.serverPrivateKey || typeof config.serverPrivateKey !== 'string') {
    const e = new Error(
      'Authrite middleware requires a valid serverPrivateKey string in its configuration object'
    )
    e.code = 'ERR_NO_PRIVKEY'
    throw e
  }
  if (config.serverPrivateKey.length !== 64) {
    const e = new Error(
      'Authrite middleware requires the serverPrivateKey to be 64 hex digits'
    )
    e.code = 'ERR_BAD_PRIVKEY'
    throw e
  }
  if (!config.requestedCertificates) {
    config.requestedCertificates = {
      certifiers: [],
      types: {}
    }
  }
  if (typeof config.requestedCertificates !== 'object') {
    const e = new Error(
      'Authrite middleware requires that requestedCertificates be provided as an object with keys "certifiers" and "types"'
    )
    e.code = 'ERR_INVALID_REQUESTED_CERTS'
    throw e
  }
  if (!Array.isArray(config.requestedCertificates.certifiers)) {
    const e = new Error(
      'Authrite middleware requires that requestedCertificates.certifiers be an array of trusted certifier public keys'
    )
    e.code = 'ERR_INVALID_REQUESTED_CERT_CERTIFIERS'
    throw e
  }
  if (typeof config.requestedCertificates.types !== 'object') {
    const e = new Error(
      'Authrite middleware requires that requestedCertificates.types be an object whose keys are trusted certificate type IDs and whose values are arrays of fields to request from certificate holders who present a certificate of the given type'
    )
    e.code = 'ERR_INVALID_REQUESTED_CERT_TYPES'
    throw e
  }
  return async (req, res, next) => {
    if (req.path === config.initialRequestPath) {
      if (req.method === 'OPTIONS') {
        return res.sendStatus(200)
      }
      if (req.method !== 'POST') {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_BAD_METHOD',
          description: 'Authrite initial requests must usee the HTTP POST method'
        })
      }
      if (typeof req.body !== 'object') {
        if (req.get('content-type') !== 'application/json') {
          return res.status(400).json({
            status: 'error',
            code: 'ERR_BAD_CONTENT_TYPE',
            description: 'Authrite initial requests must have a "Content-Type" header with value "application/json"'
          })
        } else {
          return res.status(400).json({
            status: 'error',
            code: 'ERR_BAD_REQUEST_BODY',
            description: 'The JSON request body cannot be parsed by the Authrite middleware. If a valid JSON body was provided, ensure that the server uses "body-parser" for JSON bodies before the Authrite middleware.'
          })
        }
      }
      if (!req.body.authrite) {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_MISSING_AUTHRITE_VERSION',
          description: 'The Authrite initial request body must contain an "authrite" property stipulating which version to use.'
        })
      }
      if (AUTHRITE_VERSION !== req.body.authrite) {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_AUTHRITE_VERSION_MISMATCH',
          description: `The client and server do not share a common Authrite version. This server is configured for version "${AUTHRITE_VERSION}", but the client requested version "${req.body.authrite}" instead.`,
          serverVersion: AUTHRITE_VERSION,
          clientVersion: req.body.authrite
        })
      }
      if (
        !req.body.authrite ||
        !req.body.identityKey ||
        !req.body.nonce
      ) {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_AUTHRITE_MISSING_INITIAL_REQUEST_PARAMS',
          description: 'The Authrite initial request is missing required fields from its JSON request body object. The required fields are: "authrite", "identityKey", and "nonce"'
        })
      }
      try {
        const serverNonce = cryptononce.createNonce(config.serverPrivateKey)
        const message = req.body.nonce + serverNonce

        // Get auth headers to send back to the client
        return res.status(200).json(getAuthResponseHeaders({
          authrite: AUTHRITE_VERSION,
          messageType: 'initialResponse',
          serverPrivateKey: config.serverPrivateKey,
          clientPublicKey: req.body.identityKey,
          clientNonce: req.body.nonce,
          serverNonce,
          messageToSign: message,
          certificates: [],
          requestedCertificates: config.requestedCertificates
        }))
      } catch (error) {
        console.error(error)
        return res.status(500).json({
          status: 'error',
          code: 'ERR_AUTHRITE_INIT_INTERNAL',
          description: 'An internal error occurred within the initial request handler of this server\'s Authrite middleware'
        })
      }
    }
    try {
      if (!req.headers['x-authrite']) {
        return res.status(401).json({
          status: 'error',
          code: 'ERR_MISSING_AUTHRITE_HEADER',
          description: 'This route is protected by Authrite. All requests to Authrite-protected routes must contain an "X-Authrite" HTTP header stipulating which Authrite version to use. Ensure that this header is present, and that your server\'s CORS configuration allows the Authrite headers.'
        })
      }
      if (
        !req.headers['x-authrite'] ||
        !req.headers['x-authrite-identity-key'] ||
        !req.headers['x-authrite-nonce'] ||
        !req.headers['x-authrite-yournonce'] ||
        !req.headers['x-authrite-signature'] ||
        !req.headers['x-authrite-certificates']
      ) {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_AUTHRITE_MISSING_HEADERS',
          description: 'This route is protected by Authrite. Ensure that the following Authrite HTTP headers are present, and that your server\'s CORS policy is configured to allow them: "X-Authrite", "X-Authrite-Identity-Key", "X-Authrite-Nonce", "X-Authrite-YourNonce", "X-Authrite-Signature", "X-Authrite-Certificates".'
        })
      }
      if (AUTHRITE_VERSION !== req.headers['x-authrite']) {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_AUTHRITE_VERSION_MISMATCH',
          description: `The client and server do not share a common Authrite version. This server is configured for version "${AUTHRITE_VERSION}", but the client requested version "${req.headers['x-authrite']}" instead.`,
          serverVersion: AUTHRITE_VERSION,
          clientVersion: req.headers['x-authrite']
        })
      }
      if (
        !cryptononce.verifyNonce(
          req.headers['x-authrite-yournonce'],
          config.serverPrivateKey)
      ) {
        return res.status(401).json({
          status: 'error',
          code: 'ERR_AUTHRITE_BAD_SERVER_NONCE',
          description: 'The server was unable to verify that the value given by the "X-Authrite-YourNonce" HTTP header was previously generated. Ensure the value of this header is a nonce returned from a previous Authrite initial response.'
        })
      }
      // Validate the client's request signature according to the specification
      const signingPublicKey = getPaymentAddress({
        senderPrivateKey: config.serverPrivateKey,
        recipientPublicKey: req.headers['x-authrite-identity-key'],
        invoiceNumber: `2-authrite message signature-${req.headers['x-authrite-nonce']} ${req.headers['x-authrite-yournonce']}`,
        returnType: 'publicKey'
      })
      // 2. Construct the message for verification
      let messageToVerify
      if (req.method === 'GET' || req.method === 'HEAD') {
        messageToVerify = config.baseUrl + req.originalUrl
      } else {
        messageToVerify = req.body
          ? JSON.stringify(req.body)
          : config.baseUrl + req.originalUrl
      }

      // 3. Verify the signature
      const signature = bsv.crypto.Signature.fromString(
        req.headers['x-authrite-signature']
      )
      const verified = bsv.crypto.ECDSA.verify(
        bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
        signature,
        bsv.PublicKey.fromString(signingPublicKey)
      )
      if (!verified) {
        return res.status(401).json({
          status: 'error',
          code: 'ERR_AUTHRITE_INVALID_SIGNATURE',
          description: 'The server was unable to verify this Authrite request\'s message signature.'
        })
      }

      const unsignedJson = res.json
      res.json = (json) => {
        try {
          // NOTE: It may not be necessary to use a "signed" nonce here, and it
          // may be more secure to use a pure - random nonce.
          const responseNonce = cryptononce.createNonce(config.serverPrivateKey)
          const derivedPrivateKey = getPaymentPrivateKey({
            recipientPrivateKey: config.serverPrivateKey,
            senderPublicKey: req.headers['x-authrite-identity-key'],
            invoiceNumber: '2-authrite message signature-' + req.headers['x-authrite-nonce'] + ' ' + responseNonce,
            returnType: 'hex'
          })
          const responseSignature = bsv.crypto.ECDSA.sign(
            bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(json))),
            bsv.PrivateKey.fromBuffer(Buffer.from(derivedPrivateKey, 'hex'))
          )
          res.set({
            'X-Authrite': AUTHRITE_VERSION,
            'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(config.serverPrivateKey).publicKey.toString(),
            'X-Authrite-Nonce': responseNonce,
            'X-Authrite-YourNonce': req.headers['x-authrite-nonce'],
            'X-Authrite-Certificates': '[]',
            'X-Authrite-Signature': responseSignature.toString()
          })
        } catch (error) {
          console.error(error)
        } finally {
          res.json = unsignedJson
          return res.json(json)
        }
      }

      let certificates
      try {
        certificates = JSON.parse(req.headers['x-authrite-certificates'])
      } catch (e) {
        return res.status(400).json({
          status: 'error',
          code: 'ERR_AUTHRITE_BAD_CERTS',
          description: 'The server was unable to parse the value of the "X-Authrite-Certificates HTTP header. Ensure the value is a properly-formatted JSON array of certificates.'
        })
      }
      for (const c in certificates) {
        const cert = certificates[c]
        if (cert.subject !== req.headers['x-authrite-identity-key']) {
          return res.status(401).json({
            status: 'error',
            code: 'ERR_INVALID_SUBJECT',
            description: `The subject of one of your certificates ("${cert.subject}") is not the same as the request sender ("${req.headers['x-authrite-identity-key']}").`,
            identityKey: req.headers['x-authrite-identity-key'],
            certificateSubject: cert.subject
          })
        }

        // Check valid signature
        try {
          authriteUtils.verifyCertificateSignature(cert)
        } catch (err) {
          if (err.code && err.code.startsWith('ERR_AUTHRITE')) {
            return res.status(401).json({
              status: 'error',
              code: err.code,
              description: err.message
            })
          } else {
            throw e
          }
        }

        // Check encrypted fields and decrypt them
        let decryptedFields = {}
        try {
          decryptedFields = await authriteUtils.decryptCertificateFields(
            cert,
            cert.keyring,
            config.serverPrivateKey
          )
        } catch (err) {
          return res.status(401).json({
            status: 'error',
            code: 'ERR_DECRYPTION_FAILED',
            description: 'Could not decrypt certificate fields'
          })
        }

        certificates[c] = {
          ...cert,
          decryptedFields
        }
      }
      // Compress evil uncompressed public keys
      let identityKey = req.headers['x-authrite-identity-key']
      if (identityKey.length > 66) {
        identityKey = new bsv.PublicKey(identityKey).toCompressed().toString()
      }
      req.authrite = {
        identityKey,
        certificates
      }
    } catch (error) {
      console.error(error)
      return res.status(500).json({
        status: 'error',
        code: 'ERR_AUTHRITE_MAIN_INTERNAL',
        description: 'An internal error occurred within the main request handler of this server\'s Authrite middleware'
      })
    }
    next()
  }
}

module.exports = { middleware, socket: (http, options) => { return new AuthSock(http, options) } }
