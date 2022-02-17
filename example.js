var bitgo = require(".");

var txb = new bitgo.TransactionBuilder(bitgo.networks.psl, 4);

txb.addInput('ec34c44d147cff9abd16a3814fd35d6adb64935717f593703446669c60366994', 2);
txb.addOutput('PtoU4cpM8eJxjnSRK3UKzaYZpur3YFzvaxT', 12499755);

var alice = bitgo.ECPair.fromWIF('L3NXepoiinJTzJnjmyQne8KSk5hATqnFahNiKe6u5UX4Eg7VxCZb', bitgo.networks.psl);
txb.sign(0, alice, undefined, undefined, 12500000);

var txhex = txb.build().toHex();
console.log(txhex);