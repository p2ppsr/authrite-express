const bsv = require('bsv')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const createNonce = require('./utils/createNonce')
const verifyNonce = require('./utils/verifyNonce')
const AUTHRITE_VERSION = '0.1'

/**
 * Authrite express middleware for providing mutual authentication with a client
 * @param {object} config Configures the middleware with initial parameters
 * @param {String} config.serverPrivateKey The server's private key used for derivations
 * @param {String} config.baseUrl The base url of the express server
 * @param {String} config.initialRequestPath The initial route path used to request the server's information and identity key
 * @returns {function} Which can be used as authentication middleware in an express server
 */
const middleware = (config = {}) => (req, res, next) => {
  if (!config.initalRequestPath) {
    config.initalRequestPath = '/authrite/initialRequest'
  }
  if (req.path === config.initalRequestPath) {
    if (AUTHRITE_VERSION !== req.body.authrite) {
      return res.status(400).json({
        error: 'Authrite version incompatible'
      })
    }
    try {
      const serverNonce = createNonce(config.serverPrivateKey)
      const message = req.body.nonce + serverNonce
      const derivedPrivateKey = getPaymentPrivateKey({
        recipientPrivateKey: config.serverPrivateKey,
        senderPublicKey: req.body.identityKey,
        invoiceNumber: 'authrite message signature-' + req.body.nonce + ' ' + serverNonce,
        returnType: 'hex'
      })
      const signature = bsv.crypto.ECDSA.sign(
        bsv.crypto.Hash.sha256(Buffer.from(message)),
        bsv.PrivateKey.fromHex(derivedPrivateKey)
      )
      return res.status(200).json({
        authrite: '0.1',
        messageType: 'initialResponse',
        identityKey: bsv.PrivateKey.fromHex(config.serverPrivateKey).publicKey.toString(),
        nonce: serverNonce,
        certificates: [],
        requestedCertificates: [],
        signature: signature.toString()
      })
    } catch (error) {
      return res.status(400).json({
        error: `Server could not create initial response! ErrorMessage: ${error}`
      })
    }
  }
  try {
    if (AUTHRITE_VERSION !== req.headers['x-authrite']) {
      return res.status(400).json({
        error: 'Authrite version incompatible'
      })
    }
    if (!verifyNonce(req.headers['x-authrite-yournonce'], config.serverPrivateKey)) {
      return res.status(401).json({
        error: 'show sum\' R.E.S.P.E.C.T.'
      })
    }
    // Validate the client's request signature according to the specification
    const signingPublicKey = getPaymentAddress({
      senderPrivateKey: config.serverPrivateKey,
      recipientPublicKey: req.headers['x-authrite-identity-key'],
      invoiceNumber: `authrite message signature-${req.headers['x-authrite-nonce']} ${req.headers['x-authrite-yournonce']}`,
      returnType: 'publicKey'
    })
    // 2. Construct the message for verification
    const messageToVerify = req.body
      ? JSON.stringify(req.body)
      : config.baseUrl + req.originalUrl
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
        error: 'Signature verification failed!'
      })
    }
    req.authrite = {
      identityKey: req.headers['x-authrite-identity-key']
    }
  } catch (error) {
    return res.status(400).json({
      error: 'Server could not find Authrite headers in request from client!'
    })
  }
  const unsignedJson = res.json
  res.json = (json) => {
    const responseNonce = createNonce(config.serverPrivateKey)
    const derivedPrivateKey = getPaymentPrivateKey({
      recipientPrivateKey: config.serverPrivateKey,
      senderPublicKey: req.headers['x-authrite-identity-key'],
      invoiceNumber: 'authrite message signature-' + req.headers['x-authrite-nonce'] + ' ' + responseNonce,
      returnType: 'bsv'
    })
    const responseSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(json))),
      bsv.PrivateKey.fromBuffer(derivedPrivateKey.toBuffer())
    )
    res.set({
      'X-Authrite': AUTHRITE_VERSION,
      'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(config.serverPrivateKey).publicKey.toString(),
      'X-Authrite-Nonce': responseNonce,
      'X-Authrite-YourNonce': req.headers['x-authrite-nonce'],
      'X-Authrite-Certificates': '[]',
      'X-Authrite-Signature': responseSignature.toString()
    })
    res.json = unsignedJson
    return res.json(json)
  }
  next()
}
module.exports = { middleware }
