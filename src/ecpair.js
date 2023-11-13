const baddress = require('./address')
const bcrypto = require('./crypto')
const ecdsa = require('./ecdsa')
const randomBytes = require('randombytes')
const typeforce = require('typeforce')
const types = require('./types')
const wif = require('wif')

const NETWORKS = require('./networks')
const BigInteger = require('bigi')

const ecurve = require('ecurve')
const secp256k1 = ecdsa.__curve

function ECPair (d, Q, options) {
  if (options) {
    typeforce({
      compressed: types.maybe(types.Boolean),
      network: types.maybe(types.Network)
    }, options)
  }

  options = options || {}

  if (d) {
    if (d.signum() <= 0) throw new Error('Private key must be greater than 0')
    if (d.compareTo(secp256k1.n) >= 0) throw new Error('Private key must be less than the curve order')
    if (Q) throw new TypeError('Unexpected publicKey parameter')

    this.d = d
  } else {
    typeforce(types.ECPoint, Q)

    this.__Q = Q
  }

  this.compressed = options.compressed === undefined ? true : options.compressed
  this.network = options.network || NETWORKS.bitcoin
}

Object.defineProperty(ECPair.prototype, 'Q', {
  get: function () {
    if (!this.__Q && this.d) {
      this.__Q = secp256k1.G.multiply(this.d)
    }

    return this.__Q
  }
})

ECPair.fromPublicKeyBuffer = function (buffer, network) {
  const Q = ecurve.Point.decodeFrom(secp256k1, buffer)

  return new ECPair(null, Q, {
    compressed: Q.compressed,
    network
  })
}

ECPair.fromWIF = function (string, network) {
  const decoded = wif.decode(string)
  const version = decoded.version

  // list of networks?
  if (types.Array(network)) {
    network = network.filter(function (x) {
      return version === x.wif
    }).pop() // We should not use pop since it depends on the order of the networks for the same wif

    if (!network) throw new Error('Unknown network version')

  // otherwise, assume a network object (or default to vrsc style network)
  } else {
    network = network || NETWORKS.default
    console.log('Network WIF: ' + network.wif + ', Version: ' + version)
    // if (version !== network.wif) throw new Error('Invalid network version')
    if (version !== network.wif) console.log('Warning: current network version does not match wif key version')
  }

  const d = BigInteger.fromBuffer(decoded.privateKey)

  return new ECPair(d, null, {
    compressed: decoded.compressed,
    network
  })
}

ECPair.makeRandom = function (options) {
  options = options || {}

  const rng = options.rng || randomBytes

  let d
  do {
    const buffer = rng(32)
    typeforce(types.Buffer256bit, buffer)

    d = BigInteger.fromBuffer(buffer)
  } while (d.signum() <= 0 || d.compareTo(secp256k1.n) >= 0)

  return new ECPair(d, null, options)
}

ECPair.prototype.getAddress = function () {
  return baddress.toBase58Check(bcrypto.hash160(this.getPublicKeyBuffer()), this.getNetwork().pubKeyHash)
}

ECPair.prototype.getNetwork = function () {
  return this.network
}

ECPair.prototype.getPublicKeyBuffer = function () {
  return this.Q.getEncoded(this.compressed)
}

/**
 * Get the private key as a 32 bytes buffer. If it is smaller than 32 bytes, pad it with zeros
 * @return Buffer
 */
ECPair.prototype.getPrivateKeyBuffer = function () {
  if (!this.d) throw new Error('Missing private key')

  const bigIntBuffer = this.d.toBuffer()
  if (bigIntBuffer.length > 32) throw new Error('Private key size exceeds 32 bytes')

  if (bigIntBuffer.length === 32) {
    return bigIntBuffer
  }
  const newBuffer = Buffer.alloc(32)
  bigIntBuffer.copy(newBuffer, newBuffer.length - bigIntBuffer.length, 0, bigIntBuffer.length)
  return newBuffer
}

ECPair.prototype.sign = function (hash) {
  if (!this.d) throw new Error('Missing private key')

  return ecdsa.sign(hash, this.d)
}

ECPair.prototype.toWIF = function () {
  if (!this.d) throw new Error('Missing private key')

  return wif.encode(this.network.wif, this.d.toBuffer(32), this.compressed)
}

ECPair.prototype.verify = function (hash, signature) {
  return ecdsa.verify(hash, signature, this.Q)
}

module.exports = ECPair
