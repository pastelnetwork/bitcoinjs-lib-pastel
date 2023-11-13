const bitgo = require('.')

// Pastel is on version 4 right now
const txb = new bitgo.TransactionBuilder(bitgo.networks.psl, 4)

// add as many inputs as needed by txid of previous transaction and output-index
txb.addInput('0daaab90cb686f7104b400d9e5741c8ddada83626c7c510647e8ab09e694ba26', 0)
// txb.addInput('ec34c44d147cff9abd16a3814fd35d6adb64935717f593703446669c60366994', 2);

// add as many outputs as needed by rcpt address and amount to send to this address
txb.addOutput('PtphukRR2jPqVPjHUf7XxH6oXuMdQii8moY', 12499510)
// txb.addOutput('PtoU4cpM8eJxjnSRK3UKzaYZpur3YFzvaxT', 12499755);

// sign each input with corresponding private key for that input,
// here witnessValue is amount in the output of previous transaction - the one added above with addInput
// default value for hashType is 'Transaction.SIGHASH_ALL'
const privateKey = bitgo.ECPair.fromWIF('L37XeG5vzCkV1yRXS3RmjDnZDhmk9QMZ41ahyhwYdZn2bSEhm6M6', bitgo.networks.psl)
txb.sign(0, privateKey, undefined, undefined, 12499755)

// var privateKey = bitgo.ECPair.fromWIF('L3NXepoiinJTzJnjmyQne8KSk5hATqnFahNiKe6u5UX4Eg7VxCZb', bitgo.networks.psl);
// txb.sign(0, privateKey, undefined, undefined, 12500000);

const txhex = txb.build().toHex()
console.log(txhex)
