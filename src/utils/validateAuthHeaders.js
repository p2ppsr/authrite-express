const bsv = require('babbage-bsv')
const { getPaymentAddress } = require('sendover')

const validateAuthHeaders = (messageToVerify, headers, serverPrivateKey) => {
  // Derive the corresponding public key to the signing key used
  const signingPublicKey = getPaymentAddress({
    senderPrivateKey: serverPrivateKey,
    recipientPublicKey: headers['x-authrite-identity-key'],
    invoiceNumber: `2-authrite message signature-${headers['x-authrite-nonce']} ${headers['x-authrite-yournonce']}`,
    returnType: 'publicKey'
  })

  // Verify the signature
  const signature = bsv.crypto.Signature.fromString(
    headers['x-authrite-signature']
  )
  const verified = bsv.crypto.ECDSA.verify(
    bsv.crypto.Hash.sha256(Buffer.from(messageToVerify)),
    signature,
    bsv.PublicKey.fromString(signingPublicKey)
  )
  return verified
}
module.exports = validateAuthHeaders
