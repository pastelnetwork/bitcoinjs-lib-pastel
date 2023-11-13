/* global describe, it */

const assert = require('assert')
const bigi = require('bigi')
const bitcoin = require('../../')

const ecurve = require('ecurve')
const secp256k1 = ecurve.getCurveByName('secp256k1')
const G = secp256k1.G
const n = secp256k1.n

// vG = (dG \+ sha256(e * dG)G)
function stealthSend (e, Q) {
  const eQ = Q.multiply(e) // shared secret
  const c = bigi.fromBuffer(bitcoin.crypto.sha256(eQ.getEncoded()))
  const cG = G.multiply(c)
  const vG = new bitcoin.ECPair(null, Q.add(cG))

  return vG
}

// v = (d + sha256(eG * d))
function stealthReceive (d, eG) {
  const eQ = eG.multiply(d) // shared secret
  const c = bigi.fromBuffer(bitcoin.crypto.sha256(eQ.getEncoded()))
  const v = new bitcoin.ECPair(d.add(c).mod(n))

  return v
}

// d = (v - sha256(e * dG))
function stealthRecoverLeaked (v, e, Q) {
  const eQ = Q.multiply(e) // shared secret
  const c = bigi.fromBuffer(bitcoin.crypto.sha256(eQ.getEncoded()))
  const d = new bitcoin.ECPair(v.subtract(c).mod(n))

  return d
}

// vG = (rG \+ sha256(e * dG)G)
function stealthDualSend (e, R, Q) {
  const eQ = Q.multiply(e) // shared secret
  const c = bigi.fromBuffer(bitcoin.crypto.sha256(eQ.getEncoded()))
  const cG = G.multiply(c)
  const vG = new bitcoin.ECPair(null, R.add(cG))

  return vG
}

// vG = (rG \+ sha256(eG * d)G)
function stealthDualScan (d, R, eG) {
  const eQ = eG.multiply(d) // shared secret
  const c = bigi.fromBuffer(bitcoin.crypto.sha256(eQ.getEncoded()))
  const cG = G.multiply(c)
  const vG = new bitcoin.ECPair(null, R.add(cG))

  return vG
}

// v = (r + sha256(eG * d))
function stealthDualReceive (d, r, eG) {
  const eQ = eG.multiply(d) // shared secret
  const c = bigi.fromBuffer(bitcoin.crypto.sha256(eQ.getEncoded()))
  const v = new bitcoin.ECPair(r.add(c).mod(n))

  return v
}

describe('bitcoinjs-lib (crypto)', function () {
  it('can generate a single-key stealth address', function () {
    // XXX: should be randomly generated, see next test for example
    const recipient = bitcoin.ECPair.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss') // private to recipient
    const nonce = bitcoin.ECPair.fromWIF('KxVqB96pxbw1pokzQrZkQbLfVBjjHFfp2mFfEp8wuEyGenLFJhM9') // private to sender

    // ... recipient reveals public key (recipient.Q) to sender
    const forSender = stealthSend(nonce.d, recipient.Q)
    assert.equal(forSender.getAddress(), '1CcZWwCpACJL3AxqoDbwEt4JgDFuTHUspE')
    assert.throws(function () { forSender.toWIF() }, /Error: Missing private key/)

    // ... sender reveals nonce public key (nonce.Q) to recipient
    const forRecipient = stealthReceive(recipient.d, nonce.Q)
    assert.equal(forRecipient.getAddress(), '1CcZWwCpACJL3AxqoDbwEt4JgDFuTHUspE')
    assert.equal(forRecipient.toWIF(), 'L1yjUN3oYyCXV3LcsBrmxCNTa62bZKWCybxVJMvqjMmmfDE8yk7n')

    // sender and recipient, both derived same address
    assert.equal(forSender.getAddress(), forRecipient.getAddress())
  })

  it('can generate a single-key stealth address (randomly)', function () {
    const recipient = bitcoin.ECPair.makeRandom() // private to recipient
    const nonce = bitcoin.ECPair.makeRandom() // private to sender

    // ... recipient reveals public key (recipient.Q) to sender
    const forSender = stealthSend(nonce.d, recipient.Q)
    assert.throws(function () { forSender.toWIF() }, /Error: Missing private key/)

    // ... sender reveals nonce public key (nonce.Q) to recipient
    const forRecipient = stealthReceive(recipient.d, nonce.Q)
    assert.doesNotThrow(function () { forRecipient.toWIF() })

    // sender and recipient, both derived same address
    assert.equal(forSender.getAddress(), forRecipient.getAddress())
  })

  it('can recover parent recipient.d, if a derived private key is leaked [and nonce was revealed]', function () {
    const recipient = bitcoin.ECPair.makeRandom() // private to recipient
    const nonce = bitcoin.ECPair.makeRandom() // private to sender

    // ... recipient reveals public key (recipient.Q) to sender
    const forSender = stealthSend(nonce.d, recipient.Q)
    assert.throws(function () { forSender.toWIF() }, /Error: Missing private key/)

    // ... sender reveals nonce public key (nonce.Q) to recipient
    const forRecipient = stealthReceive(recipient.d, nonce.Q)
    assert.doesNotThrow(function () { forRecipient.toWIF() })

    // ... recipient accidentally leaks forRecipient.d on the blockchain
    const leaked = stealthRecoverLeaked(forRecipient.d, nonce.d, recipient.Q)
    assert.equal(leaked.toWIF(), recipient.toWIF())
  })

  it('can generate a dual-key stealth address', function () {
    // XXX: should be randomly generated, see next test for example
    const recipient = bitcoin.ECPair.fromWIF('5KYZdUEo39z3FPrtuX2QbbwGnNP5zTd7yyr2SC1j299sBCnWjss') // private to recipient
    const scan = bitcoin.ECPair.fromWIF('L5DkCk3xLLoGKncqKsWQTdaPSR4V8gzc14WVghysQGkdryRudjBM') // private to scanner/recipient
    const nonce = bitcoin.ECPair.fromWIF('KxVqB96pxbw1pokzQrZkQbLfVBjjHFfp2mFfEp8wuEyGenLFJhM9') // private to sender

    // ... recipient reveals public key(s) (recipient.Q, scan.Q) to sender
    const forSender = stealthDualSend(nonce.d, recipient.Q, scan.Q)
    assert.throws(function () { forSender.toWIF() }, /Error: Missing private key/)

    // ... sender reveals nonce public key (nonce.Q) to scanner
    const forScanner = stealthDualScan(scan.d, recipient.Q, nonce.Q)
    assert.throws(function () { forScanner.toWIF() }, /Error: Missing private key/)

    // ... scanner reveals relevant transaction + nonce public key (nonce.Q) to recipient
    const forRecipient = stealthDualReceive(scan.d, recipient.d, nonce.Q)
    assert.doesNotThrow(function () { forRecipient.toWIF() })

    // scanner, sender and recipient, all derived same address
    assert.equal(forSender.getAddress(), forScanner.getAddress())
    assert.equal(forSender.getAddress(), forRecipient.getAddress())
  })

  it('can generate a dual-key stealth address (randomly)', function () {
    const recipient = bitcoin.ECPair.makeRandom() // private to recipient
    const scan = bitcoin.ECPair.makeRandom() // private to scanner/recipient
    const nonce = bitcoin.ECPair.makeRandom() // private to sender

    // ... recipient reveals public key(s) (recipient.Q, scan.Q) to sender
    const forSender = stealthDualSend(nonce.d, recipient.Q, scan.Q)
    assert.throws(function () { forSender.toWIF() }, /Error: Missing private key/)

    // ... sender reveals nonce public key (nonce.Q) to scanner
    const forScanner = stealthDualScan(scan.d, recipient.Q, nonce.Q)
    assert.throws(function () { forScanner.toWIF() }, /Error: Missing private key/)

    // ... scanner reveals relevant transaction + nonce public key (nonce.Q) to recipient
    const forRecipient = stealthDualReceive(scan.d, recipient.d, nonce.Q)
    assert.doesNotThrow(function () { forRecipient.toWIF() })

    // scanner, sender and recipient, all derived same address
    assert.equal(forSender.getAddress(), forScanner.getAddress())
    assert.equal(forSender.getAddress(), forRecipient.getAddress())
  })
})
