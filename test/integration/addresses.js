/* global describe, it */

const assert = require('assert')
const bigi = require('bigi')
const bitcoin = require('../../')
const dhttp = require('dhttp/200')

// deterministic RNG for testing only
function rng () { return Buffer.from('zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz') }

describe('bitcoinjs-lib (addresses)', function () {
  it('can generate a random address', function () {
    const keyPair = bitcoin.ECPair.makeRandom({ rng })
    const address = keyPair.getAddress()

    assert.strictEqual(address, '1F5VhMHukdnUES9kfXqzPzMeF1GPHKiF64')
  })

  it('can generate an address from a SHA256 hash', function () {
    const hash = bitcoin.crypto.sha256('correct horse battery staple')
    const d = bigi.fromBuffer(hash)

    const keyPair = new bitcoin.ECPair(d)
    const address = keyPair.getAddress()

    assert.strictEqual(address, '1C7zdTfnkzmr13HfA2vNm5SJYRK6nEKyq8')
  })

  it('can import an address via WIF', function () {
    const keyPair = bitcoin.ECPair.fromWIF('Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct')
    const address = keyPair.getAddress()

    assert.strictEqual(address, '19AAjaTUbRjQCMuVczepkoPswiZRhjtg31')
  })

  it('can generate a 2-of-3 multisig P2SH address', function () {
    const pubKeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
      '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9'
    ].map(function (hex) { return Buffer.from(hex, 'hex') })

    const redeemScript = bitcoin.script.multisig.output.encode(2, pubKeys) // 2 of 3
    const scriptPubKey = bitcoin.script.scriptHash.output.encode(bitcoin.crypto.hash160(redeemScript))
    const address = bitcoin.address.fromOutputScript(scriptPubKey)

    assert.strictEqual(address, '36NUkt6FWUi3LAWBqWRdDmdTWbt91Yvfu7')
  })

  it('can generate a SegWit address', function () {
    const keyPair = bitcoin.ECPair.fromWIF('Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct')
    const pubKey = keyPair.getPublicKeyBuffer()

    const scriptPubKey = bitcoin.script.witnessPubKeyHash.output.encode(bitcoin.crypto.hash160(pubKey))
    const address = bitcoin.address.fromOutputScript(scriptPubKey)

    assert.strictEqual(address, 'bc1qt97wqg464zrhnx23upykca5annqvwkwujjglky')
  })

  it('can generate a SegWit address (via P2SH)', function () {
    const keyPair = bitcoin.ECPair.fromWIF('Kxr9tQED9H44gCmp6HAdmemAzU3n84H3dGkuWTKvE23JgHMW8gct')
    const pubKey = keyPair.getPublicKeyBuffer()

    const witnessScript = bitcoin.script.witnessPubKeyHash.output.encode(bitcoin.crypto.hash160(pubKey))
    const scriptPubKey = bitcoin.script.scriptHash.output.encode(bitcoin.crypto.hash160(witnessScript))
    const address = bitcoin.address.fromOutputScript(scriptPubKey)

    assert.strictEqual(address, '34AgLJhwXrvmkZS1o5TrcdeevMt22Nar53')
  })

  it('can generate a SegWit 3-of-4 multisig address', function () {
    const pubKeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9',
      '023e4740d0ba639e28963f3476157b7cf2fb7c6fdf4254f97099cf8670b505ea59',
      '03c6103b3b83e4a24a0e33a4df246ef11772f9992663db0c35759a5e2ebf68d8e9'
    ].map(function (hex) { return Buffer.from(hex, 'hex') })

    const witnessScript = bitcoin.script.multisig.output.encode(3, pubKeys) // 3 of 4
    const scriptPubKey = bitcoin.script.witnessScriptHash.output.encode(bitcoin.crypto.sha256(witnessScript))
    const address = bitcoin.address.fromOutputScript(scriptPubKey)

    assert.strictEqual(address, 'bc1q75f6dv4q8ug7zhujrsp5t0hzf33lllnr3fe7e2pra3v24mzl8rrqtp3qul')
  })

  it('can generate a SegWit 2-of-2 multisig address (via P2SH)', function () {
    const pubKeys = [
      '026477115981fe981a6918a6297d9803c4dc04f328f22041bedff886bbc2962e01',
      '02c96db2302d19b43d4c69368babace7854cc84eb9e061cde51cfa77ca4a22b8b9'
    ].map(function (hex) { return Buffer.from(hex, 'hex') })

    const witnessScript = bitcoin.script.multisig.output.encode(2, pubKeys) // 2 of 2
    const redeemScript = bitcoin.script.witnessScriptHash.output.encode(bitcoin.crypto.sha256(witnessScript))
    const scriptPubKey = bitcoin.script.scriptHash.output.encode(bitcoin.crypto.hash160(redeemScript))
    const address = bitcoin.address.fromOutputScript(scriptPubKey)

    assert.strictEqual(address, '3P4mrxQfmExfhxqjLnR2Ah4WES5EB1KBrN')
  })

  it('can support the retrieval of transactions for an address (via 3PBP)', function (done) {
    const keyPair = bitcoin.ECPair.makeRandom()
    const address = keyPair.getAddress()

    dhttp({
      method: 'GET',
      url: 'https://blockchain.info/rawaddr/' + address
    }, function (err, result) {
      if (err) return done(err)

      // random private keys [probably!] have no transactions
      assert.strictEqual(result.n_tx, 0)
      assert.strictEqual(result.total_received, 0)
      assert.strictEqual(result.total_sent, 0)
      done()
    })
  })

  // other networks
  it('can generate a Testnet address', function () {
    const testnet = bitcoin.networks.testnet
    const keyPair = bitcoin.ECPair.makeRandom({ network: testnet, rng })
    const wif = keyPair.toWIF()
    const address = keyPair.getAddress()

    assert.strictEqual(address, 'mubSzQNtZfDj1YdNP6pNDuZy6zs6GDn61L')
    assert.strictEqual(wif, 'cRgnQe9MUu1JznntrLaoQpB476M8PURvXVQB5R2eqms5tXnzNsrr')
  })

  it('can generate a Litecoin address', function () {
    const litecoin = bitcoin.networks.litecoin
    const keyPair = bitcoin.ECPair.makeRandom({ network: litecoin, rng })
    const wif = keyPair.toWIF()
    const address = keyPair.getAddress()

    assert.strictEqual(address, 'LZJSxZbjqJ2XVEquqfqHg1RQTDdfST5PTn')
    assert.strictEqual(wif, 'T7A4PUSgTDHecBxW1ZiYFrDNRih2o7M8Gf9xpoCgudPF9gDiNvuS')
  })
})
