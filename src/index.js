const bsv = require('bsv')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const createNonce = require('./utils/createNonce')
const verifyNonce = require('./utils/verifyNonce')
const AUTHRITE_VERSION = '0.1'
const middleware = (config = {}) => (req, res, next) => {
  if (!config.initalRequestPath) {
    config.initalRequestPath = '/authrite/initialRequest'
  }
  if (req.path === config.initialRequestPath) {
    if (AUTHRITE_VERSION !== req.body.authrite) {
      return res.status(400).json({
        error: 'Authrite version incompatible'
      })
    }
    const serverNonce = createNonce(config.serverPrivateKey)
    const message = req.body.nonce + serverNonce
    const derivedPrivateKey = getPaymentPrivateKey({
      recipientPrivateKey: config.serverPrivateKey,
      senderPublicKey: req.body.identityKey,
      invoiceNumber: 'authrite message signature-' + req.body.nonce + ' ' + serverNonce,
      returnType: 'hex'
    })
    const signature = bsv.crypto.ECDSA.sign(bsv.crypto.Hash.sha256(Buffer.from(message)), bsv.PrivateKey.fromHex(derivedPrivateKey))
    return res.status(200).json({
      authrite: '0.1',
      messageType: 'initialResponse',
      identityKey: bsv.PrivateKey.fromHex(config.serverPrivateKey).publicKey.toString(),
      nonce: serverNonce,
      certificates: [],
      requestedCertificates: [],
      signature: signature.toString()
    })
  }
  if (AUTHRITE_VERSION !== req.headers['X-Authrite']) {
    return res.status(400).json({
      error: 'Authrite version incompatible'
    })
  }
  if (verifyNonce(req.headers['X-Authrite-YourNonce'], config.serverPrivateKey) === false) {
    return res.status(401).json({
      error: 'show sum\' R.E.S.P.E.C.T.'
    })
  }
  // When the server response comes back, validate the signature according to the specification
  const signingPublicKey = getPaymentAddress({
    senderPrivateKey: config.serverPrivateKey,
    recipientPublicKey: req.headers['X-Authrite-Indentity-Key'],
    invoiceNumber: 'authrite message signature-' + req.headers['X-Authrite-Nonce'] + ' ' + req.headers['X-Authrite-YourNonce'],
    returnType: 'publicKey'
  })
  // 2. Construct the message for verification
  const messageToVerify = req.body ? JSON.stringify(req.body) : req.url
  // 3. Verify the signature
  const signature = bsv.crypto.Signature.fromString(
    req.headers['X-Authrite-Signature']
  )
  const verified = bsv.crypto.ECDSA.verify(
    bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
    signature,
    bsv.PublicKey.fromString(signingPublicKey)
  )
  if (verified === false) {
    res.status(401).json({
      error: 'You didn\'t sign signatures'
    })
  }
  req.authrite = {
    identityKey: req.headers['X-Authrite-Identity-Key']
  }
  res.unsignedJson = res.json
  res.json = (json) => {
    const responseNonce = createNonce(config.serverPrivateKey)
    const derivedPrivateKey = getPaymentPrivateKey({
      recipientPrivateKey: config.senderPrivateKey,
      senderPublicKey: req.headers['X-Authrite-Identity-Key'],
      invoiceNumber: 'authrite message signature-' + req.headers['X-Authrite-Nonce'] + ' ' + responseNonce,
      returnType: 'hex'
    })
    const responseSignature = bsv.crypto.ECDSA.sign(
      bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(json))),
      bsv.PrivateKey.fromHex(derivedPrivateKey)
    )
    res.set({
      'X-Authrite': AUTHRITE_VERSION,
      'X-Authrite-Identity-Key': bsv.PrivateKey.fromHex(config.serverPrivateKey).publicKey.toString(),
      'X-Authrite-Nonce': responseNonce,
      'X-Authrite-YourNonce': req.headers['X-Authrite-Nonce'],
      'X-Authrite-Certificates': '[]',
      'X-Authrite-Signature': responseSignature.toString()
    })
    return res.unsignedJson(json)
  }

  next()
}
module.exports = { middleware }
