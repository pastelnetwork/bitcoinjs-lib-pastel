// {signature} {pubKey}

const bscript = require('../../script')
const typeforce = require('typeforce')

function isCompressedCanonicalPubKey (pubKey) {
  return bscript.isCanonicalPubKey(pubKey) && pubKey.length === 33
}

function check (script) {
  const chunks = bscript.decompile(script)

  return chunks.length === 2 &&
    bscript.isCanonicalSignature(chunks[0]) &&
    isCompressedCanonicalPubKey(chunks[1])
}
check.toJSON = function () { return 'witnessPubKeyHash input' }

function encodeStack (signature, pubKey) {
  typeforce({
    signature: bscript.isCanonicalSignature,
    pubKey: isCompressedCanonicalPubKey
  }, {
    signature,
    pubKey
  })

  return [signature, pubKey]
}

function decodeStack (stack) {
  typeforce(check, stack)

  return {
    signature: stack[0],
    pubKey: stack[1]
  }
}

module.exports = {
  check,
  decodeStack,
  encodeStack
}
