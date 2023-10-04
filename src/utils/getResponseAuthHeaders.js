const bsv = require('babbage-bsv')
const { getPaymentPrivateKey } = require('sendover')

/**
 * Constructs the required server response headers for a given client
 * Supports initial request, and subsequent requests
 * @param {object} obj - all params given in an object
 * @param {string} obj.authrite - the version of authrite being used
 * @param {string} obj.messageType - type of message to respond to
 * @param {string} obj.serverPrivateKey - server private key to use to derive the signing private key
 * @param {string} obj.clientPublicKey - public key of the sender
 * @param {string} obj.clientNonce - random data provided by the client
 * @param {string} obj.serverNonce - random data provided by the server
 * @param {string} obj.messageToSign - expected message to be signed
 * @param {Array} obj.certificates - provided certificates as requested by the client
 * @param {Array} obj.requestedCertificates - a structure indicating which certificates the client should provide
 * @returns {object} - the required response headers for authentication
 */
const getResponseAuthHeaders = ({
  authrite,
  messageType,
  serverPrivateKey,
  clientPublicKey,
  clientNonce,
  serverNonce,
  messageToSign = 'test',
  certificates = [],
  requestedCertificates
}) => {
  // Derive the signing private key
  const derivedPrivateKey = getPaymentPrivateKey({
    recipientPrivateKey: serverPrivateKey,
    senderPublicKey: clientPublicKey,
    invoiceNumber: `2-authrite message signature-${clientNonce} ${serverNonce}`,
    returnType: 'hex'
  })

  // Sign the message
  const responseSignature = bsv.crypto.ECDSA.sign(
    bsv.crypto.Hash.sha256(Buffer.from(messageToSign)),
    bsv.PrivateKey.fromBuffer(Buffer.from(derivedPrivateKey, 'hex'))
  )

  // Construct the auth headers to send to the client
  if (messageType === 'initialResponse') {
    return {
      authrite,
      messageType,
      identityKey: new bsv.PrivateKey(serverPrivateKey).publicKey.toString('hex'),
      nonce: serverNonce,
      certificates,
      requestedCertificates,
      signature: responseSignature.toString()
    }
  } else {
    return {
      'x-authrite': authrite,
      'x-authrite-identity-key': new bsv.PrivateKey(serverPrivateKey).publicKey.toString('hex'),
      'x-authrite-nonce': serverNonce,
      'x-authrite-yournonce': clientNonce,
      'x-authrite-certificates': JSON.stringify(certificates),
      'x-authrite-signature': responseSignature.toString()
    }
  }
}
module.exports = getResponseAuthHeaders
