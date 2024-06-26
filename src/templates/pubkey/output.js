// {pubKey} OP_CHECKSIG

const bscript = require('../../script')
const typeforce = require('typeforce')
const OPS = require('bitcoin-ops')

function check (script) {
  const chunks = bscript.decompile(script)

  return chunks.length === 2 &&
    bscript.isCanonicalPubKey(chunks[0]) &&
    chunks[1] === OPS.OP_CHECKSIG
}
check.toJSON = function () { return 'pubKey output' }

function encode (pubKey) {
  typeforce(bscript.isCanonicalPubKey, pubKey)

  return bscript.compile([pubKey, OPS.OP_CHECKSIG])
}

function decode (buffer) {
  const chunks = bscript.decompile(buffer)
  typeforce(check, chunks)

  return chunks[0]
}

module.exports = {
  check,
  decode,
  encode
}
