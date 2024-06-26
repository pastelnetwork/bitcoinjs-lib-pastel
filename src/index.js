const script = require('./script')

const templates = require('./templates')
for (const key in templates) {
  script[key] = templates[key]
}

module.exports = {
  bufferutils: require('./bufferutils'), // TODO: remove in 4.0.0

  Block: require('./block'),
  ECPair: require('./ecpair'),
  ECSignature: require('./ecsignature'),
  HDNode: require('./hdnode'),
  Transaction: require('./transaction'),
  TransactionBuilder: require('./transaction_builder'),

  address: require('./address'),
  coins: require('./coins'),
  crypto: require('./crypto'),
  networks: require('./networks'),
  opcodes: require('bitcoin-ops'),
  script
}
