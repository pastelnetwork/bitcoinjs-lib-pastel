/* global describe, it */

const assert = require('assert')
const bip39 = require('bip39')
const bitcoin = require('../../')

describe('bitcoinjs-lib (BIP32)', function () {
  it('can import a BIP32 testnet xpriv and export to WIF', function () {
    const xpriv = 'tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK'
    const node = bitcoin.HDNode.fromBase58(xpriv, bitcoin.networks.testnet)

    assert.equal(node.keyPair.toWIF(), 'cQfoY67cetFNunmBUX5wJiw3VNoYx3gG9U9CAofKE6BfiV1fSRw7')
  })

  it('can export a BIP32 xpriv, then import it', function () {
    const mnemonic = 'praise you muffin lion enable neck grocery crumble super myself license ghost'
    const seed = bip39.mnemonicToSeed(mnemonic)
    const node = bitcoin.HDNode.fromSeedBuffer(seed)
    const string = node.toBase58()
    const restored = bitcoin.HDNode.fromBase58(string)

    assert.equal(node.getAddress(), restored.getAddress()) // same public key
    assert.equal(node.keyPair.toWIF(), restored.keyPair.toWIF()) // same private key
  })

  it('can export a BIP32 xpub', function () {
    const mnemonic = 'praise you muffin lion enable neck grocery crumble super myself license ghost'
    const seed = bip39.mnemonicToSeed(mnemonic)
    const node = bitcoin.HDNode.fromSeedBuffer(seed)
    const string = node.neutered().toBase58()

    assert.equal(string, 'xpub661MyMwAqRbcGhVeaVfEBA25e3cP9DsJQZoE8iep5fZSxy3TnPBNBgWnMZx56oreNc48ZoTkQfatNJ9VWnQ7ZcLZcVStpaXLTeG8bGrzX3n')
  })

  it('can create a BIP32, bitcoin, account 0, external address', function () {
    const path = "m/0'/0/0"
    const root = bitcoin.HDNode.fromSeedHex('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd')

    const child1 = root.derivePath(path)

    // option 2, manually
    const child1b = root.deriveHardened(0)
      .derive(0)
      .derive(0)

    assert.equal(child1.getAddress(), '1JHyB1oPXufr4FXkfitsjgNB5yRY9jAaa7')
    assert.equal(child1b.getAddress(), '1JHyB1oPXufr4FXkfitsjgNB5yRY9jAaa7')
  })

  it('can create a BIP44, bitcoin, account 0, external address', function () {
    const root = bitcoin.HDNode.fromSeedHex('dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd')

    const child1 = root.derivePath("m/44'/0'/0'/0/0")

    // option 2, manually
    const child1b = root.deriveHardened(44)
      .deriveHardened(0)
      .deriveHardened(0)
      .derive(0)
      .derive(0)

    assert.equal(child1.getAddress(), '12Tyvr1U8A3ped6zwMEU5M8cx3G38sP5Au')
    assert.equal(child1b.getAddress(), '12Tyvr1U8A3ped6zwMEU5M8cx3G38sP5Au')
  })

  it('can create a BIP49, bitcoin testnet, account 0, external address', function () {
    const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'
    const seed = bip39.mnemonicToSeed(mnemonic)
    const root = bitcoin.HDNode.fromSeedBuffer(seed)

    const path = "m/49'/1'/0'/0/0"
    const child = root.derivePath(path)

    const keyhash = bitcoin.crypto.hash160(child.getPublicKeyBuffer())
    const scriptSig = bitcoin.script.witnessPubKeyHash.output.encode(keyhash)
    const addressBytes = bitcoin.crypto.hash160(scriptSig)
    const outputScript = bitcoin.script.scriptHash.output.encode(addressBytes)
    const address = bitcoin.address.fromOutputScript(outputScript, bitcoin.networks.testnet)

    assert.equal(address, '2Mww8dCYPUpKHofjgcXcBCEGmniw9CoaiD2')
  })

  it('can use BIP39 to generate BIP32 addresses', function () {
    //     var mnemonic = bip39.generateMnemonic()
    const mnemonic = 'praise you muffin lion enable neck grocery crumble super myself license ghost'
    assert(bip39.validateMnemonic(mnemonic))

    const seed = bip39.mnemonicToSeed(mnemonic)
    const root = bitcoin.HDNode.fromSeedBuffer(seed)

    // receive addresses
    assert.strictEqual(root.derivePath("m/0'/0/0").getAddress(), '1AVQHbGuES57wD68AJi7Gcobc3RZrfYWTC')
    assert.strictEqual(root.derivePath("m/0'/0/1").getAddress(), '1Ad6nsmqDzbQo5a822C9bkvAfrYv9mc1JL')

    // change addresses
    assert.strictEqual(root.derivePath("m/0'/1/0").getAddress(), '1349KVc5NgedaK7DvuD4xDFxL86QN1Hvdn')
    assert.strictEqual(root.derivePath("m/0'/1/1").getAddress(), '1EAvj4edpsWcSer3duybAd4KiR4bCJW5J6')
  })
})
