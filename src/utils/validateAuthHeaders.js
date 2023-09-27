const bsv = require('babbage-bsv')
const { getPaymentAddress } = require('sendover')

/**
 *
 * @param {object} obj - all params given in an object
 * @param {string} obj.messageToSign - the message signed when the signature was created
 * @param {object} obj.authHeaders - provided by the client for authentication
 * @param {string} obj.serverPrivateKey - server private key to use to derive the signingPublicKey
 * @returns {boolean} - the validation result
 */
const validateAuthHeaders = ({ messageToSign, authHeaders, serverPrivateKey }) => {
  // Derive the corresponding public key to the signing key used
  const signingPublicKey = getPaymentAddress({
    senderPrivateKey: serverPrivateKey,
    recipientPublicKey: authHeaders['x-authrite-identity-key'],
    invoiceNumber: `2-authrite message signature-${authHeaders['x-authrite-nonce']} ${authHeaders['x-authrite-yournonce']}`,
    returnType: 'publicKey'
  })

  // Verify the signature
  const signature = bsv.crypto.Signature.fromString(
    authHeaders['x-authrite-signature']
  )
  const verified = bsv.crypto.ECDSA.verify(
    bsv.crypto.Hash.sha256(Buffer.from(messageToSign)),
    signature,
    bsv.PublicKey.fromString(signingPublicKey)
  )
  return verified
}
module.exports = validateAuthHeaders
