const bsv = require('bsv')
const crypto = require('crypto')
const { getPaymentAddress, getPaymentPrivateKey } = require('sendover')
const createNonce = require('./utils/createNonce')
const verifyNonce = require('./utils/verifyNonce')
const AUTHRITE_VERSION = '0.1'
const middleware = config => (req, res, next) => {
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
    invoiceNumber: 'authrite message signature-' + req.headers['X-Authrite-Nonce'] + ' ' + response.headers['X-Authrite-YourNonce'],
    returnType: 'publicKey'
  })
  // 2. Construct the message for verification
  const messageToVerify = req.body ? JSON.stringify(req.body):req.url
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
  next()
  const derivedPrivateKey = sendover.getPaymentPrivateKey({
    recipientPrivateKey: TEST_SERVER_PRIVATE_KEY,
    senderPublicKey: fetchConfig.headers['X-Authrite-Identity-Key'],
    invoiceNumber: 'authrite message signature-' + fetchConfig.headers['X-Authrite-Nonce'] + ' ' + serverNonce,
    returnType: 'hex'
  })
  const responseSignature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(Buffer.from(JSON.stringify(responseMessage))),
    bsv.PrivateKey.fromHex(derivedPrivateKey))
}
module.exports = { middleware }
