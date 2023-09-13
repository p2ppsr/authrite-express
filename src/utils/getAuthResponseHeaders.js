const bsv = require('babbage-bsv')
const { getPaymentPrivateKey } = require('sendover')

/**
 * Constructs the required server response headers for a given client
 * Supports initial request, and subsequent requests
 * @param {string} serverPrivateKey
 * @param {string} clientPublicKey
 * @param {string} clientNonce
 * @param {string} messageToSign
 * @param {boolean} initialRequest
 * @returns {object} - the required response headers for authentication
 */
const getAuthResponseHeaders = (serverPrivateKey, clientPublicKey, clientNonce, responseNonce, messageToSign = 'test', initialResponse = false) => {
  // Derive the signing private key
  const derivedPrivateKey = getPaymentPrivateKey({
    recipientPrivateKey: serverPrivateKey,
    senderPublicKey: clientPublicKey,
    invoiceNumber: '2-authrite message signature-' + clientNonce + ' ' + responseNonce,
    returnType: 'hex'
  })

  // Sign the message
  const responseSignature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(Buffer.from(messageToSign)),
    bsv.PrivateKey.fromBuffer(Buffer.from(derivedPrivateKey, 'hex'))
  )

  // Construct the auth headers to send to the client
  return {
    'x-authrite': '0.1',
    'x-message-type': initialResponse ? 'initialResponse' : 'response',
    'x-authrite-identity-key': new bsv.PrivateKey(serverPrivateKey).publicKey.toString('hex'),
    'x-authrite-nonce': responseNonce,
    'x-authrite-yournonce': clientNonce,
    'x-authrite-certificates': '[]', // ?
    'x-authrite-signature': responseSignature.toString()
  }
}
module.exports = getAuthResponseHeaders
