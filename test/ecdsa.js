/* global describe, it */

const assert = require('assert')
const bcrypto = require('../src/crypto')
const ecdsa = require('../src/ecdsa')
const sinon = require('sinon')

const BigInteger = require('bigi')
const ECSignature = require('../src/ecsignature')

const curve = ecdsa.__curve

const fixtures = require('./fixtures/ecdsa.json')

describe('ecdsa', function () {
  describe('deterministicGenerateK', function () {
    function checkSig () {
      return true
    }

    fixtures.valid.ecdsa.forEach(function (f) {
      it('for "' + f.message + '"', function () {
        const x = BigInteger.fromHex(f.d).toBuffer(32)
        const h1 = bcrypto.sha256(f.message)

        const k = ecdsa.deterministicGenerateK(h1, x, checkSig)
        assert.strictEqual(k.toHex(), f.k)
      })
    })

    it('loops until an appropriate k value is found', sinon.test(function () {
      this.mock(BigInteger).expects('fromBuffer')
        .exactly(3)
        .onCall(0).returns(new BigInteger('0')) // < 1
        .onCall(1).returns(curve.n) // > n-1
        .onCall(2).returns(new BigInteger('42')) // valid

      const x = new BigInteger('1').toBuffer(32)
      const h1 = Buffer.alloc(32)
      const k = ecdsa.deterministicGenerateK(h1, x, checkSig)

      assert.strictEqual(k.toString(), '42')
    }))

    it('loops until a suitable signature is found', sinon.test(function () {
      this.mock(BigInteger).expects('fromBuffer')
        .exactly(4)
        .onCall(0).returns(new BigInteger('0')) // < 1
        .onCall(1).returns(curve.n) // > n-1
        .onCall(2).returns(new BigInteger('42')) // valid, but 'bad' signature
        .onCall(3).returns(new BigInteger('53')) // valid, good signature

      const mockCheckSig = this.mock()
      mockCheckSig.exactly(2)
      mockCheckSig.onCall(0).returns(false) // bad signature
      mockCheckSig.onCall(1).returns(true) // good signature

      const x = new BigInteger('1').toBuffer(32)
      const h1 = Buffer.alloc(32)
      const k = ecdsa.deterministicGenerateK(h1, x, mockCheckSig)

      assert.strictEqual(k.toString(), '53')
    }))

    fixtures.valid.rfc6979.forEach(function (f) {
      it('produces the expected k values for ' + f.message + " if k wasn't suitable", function () {
        const x = BigInteger.fromHex(f.d).toBuffer(32)
        const h1 = bcrypto.sha256(f.message)

        const results = []
        ecdsa.deterministicGenerateK(h1, x, function (k) {
          results.push(k)

          return results.length === 16
        })

        assert.strictEqual(results[0].toHex(), f.k0)
        assert.strictEqual(results[1].toHex(), f.k1)
        assert.strictEqual(results[15].toHex(), f.k15)
      })
    })
  })

  describe('sign', function () {
    fixtures.valid.ecdsa.forEach(function (f) {
      it('produces a deterministic signature for "' + f.message + '"', function () {
        const d = BigInteger.fromHex(f.d)
        const hash = bcrypto.sha256(f.message)
        const signature = ecdsa.sign(hash, d).toDER()

        assert.strictEqual(signature.toString('hex'), f.signature)
      })
    })

    it('should sign with low S value', function () {
      const hash = bcrypto.sha256('Vires in numeris')
      const sig = ecdsa.sign(hash, BigInteger.ONE)

      // See BIP62 for more information
      const N_OVER_TWO = curve.n.shiftRight(1)
      assert(sig.s.compareTo(N_OVER_TWO) <= 0)
    })
  })

  describe('verify', function () {
    fixtures.valid.ecdsa.forEach(function (f) {
      it('verifies a valid signature for "' + f.message + '"', function () {
        const d = BigInteger.fromHex(f.d)
        const H = bcrypto.sha256(f.message)
        const signature = ECSignature.fromDER(Buffer.from(f.signature, 'hex'))
        const Q = curve.G.multiply(d)

        assert(ecdsa.verify(H, signature, Q))
      })
    })

    fixtures.invalid.verify.forEach(function (f) {
      it('fails to verify with ' + f.description, function () {
        const H = bcrypto.sha256(f.message)
        const d = BigInteger.fromHex(f.d)

        let signature
        if (f.signature) {
          signature = ECSignature.fromDER(Buffer.from(f.signature, 'hex'))
        } else if (f.signatureRaw) {
          signature = new ECSignature(new BigInteger(f.signatureRaw.r, 16), new BigInteger(f.signatureRaw.s, 16))
        }

        const Q = curve.G.multiply(d)

        assert.strictEqual(ecdsa.verify(H, signature, Q), false)
      })
    })
  })
})
