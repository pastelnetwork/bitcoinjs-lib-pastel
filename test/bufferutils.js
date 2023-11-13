/* global describe, it */

const assert = require('assert')
const bufferutils = require('../src/bufferutils')

const fixtures = require('./fixtures/bufferutils.json')

describe('bufferutils', function () {
  describe('pushDataSize', function () {
    fixtures.valid.forEach(function (f) {
      it('determines the pushDataSize of ' + f.dec + ' correctly', function () {
        if (!f.hexPD) return

        const size = bufferutils.pushDataSize(f.dec)

        assert.strictEqual(size, f.hexPD.length / 2)
      })
    })
  })

  describe('readPushDataInt', function () {
    fixtures.valid.forEach(function (f) {
      if (!f.hexPD) return

      it('decodes ' + f.hexPD + ' correctly', function () {
        const buffer = Buffer.from(f.hexPD, 'hex')
        const d = bufferutils.readPushDataInt(buffer, 0)
        const fopcode = parseInt(f.hexPD.substr(0, 2), 16)

        assert.strictEqual(d.opcode, fopcode)
        assert.strictEqual(d.number, f.dec)
        assert.strictEqual(d.size, buffer.length)
      })
    })

    fixtures.invalid.readPushDataInt.forEach(function (f) {
      if (!f.hexPD) return

      it('decodes ' + f.hexPD + ' as null', function () {
        const buffer = Buffer.from(f.hexPD, 'hex')

        const n = bufferutils.readPushDataInt(buffer, 0)
        assert.strictEqual(n, null)
      })
    })
  })

  describe('readInt64LE', function () {
    fixtures.negative.forEach(function (f) {
      it('decodes ' + f.hex64 + ' correctly', function () {
        const buffer = Buffer.from(f.hex64, 'hex')
        const number = bufferutils.readInt64LE(buffer, 0)

        assert.strictEqual(number, f.dec)
      })
    })
  })

  describe('readUInt64LE', function () {
    fixtures.valid.forEach(function (f) {
      it('decodes ' + f.hex64 + ' correctly', function () {
        const buffer = Buffer.from(f.hex64, 'hex')
        const number = bufferutils.readUInt64LE(buffer, 0)

        assert.strictEqual(number, f.dec)
      })
    })

    fixtures.invalid.readUInt64LE.forEach(function (f) {
      it('throws on ' + f.description, function () {
        const buffer = Buffer.from(f.hex64, 'hex')

        assert.throws(function () {
          bufferutils.readUInt64LE(buffer, 0)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('readVarInt', function () {
    fixtures.valid.forEach(function (f) {
      it('decodes ' + f.hexVI + ' correctly', function () {
        const buffer = Buffer.from(f.hexVI, 'hex')
        const d = bufferutils.readVarInt(buffer, 0)

        assert.strictEqual(d.number, f.dec)
        assert.strictEqual(d.size, buffer.length)
      })
    })

    fixtures.invalid.readUInt64LE.forEach(function (f) {
      it('throws on ' + f.description, function () {
        const buffer = Buffer.from(f.hexVI, 'hex')

        assert.throws(function () {
          bufferutils.readVarInt(buffer, 0)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('varIntBuffer', function () {
    fixtures.valid.forEach(function (f) {
      it('encodes ' + f.dec + ' correctly', function () {
        const buffer = bufferutils.varIntBuffer(f.dec)

        assert.strictEqual(buffer.toString('hex'), f.hexVI)
      })
    })
  })

  describe('varIntSize', function () {
    fixtures.valid.forEach(function (f) {
      it('determines the varIntSize of ' + f.dec + ' correctly', function () {
        const size = bufferutils.varIntSize(f.dec)

        assert.strictEqual(size, f.hexVI.length / 2)
      })
    })
  })

  describe('writePushDataInt', function () {
    fixtures.valid.forEach(function (f) {
      if (!f.hexPD) return

      it('encodes ' + f.dec + ' correctly', function () {
        const buffer = Buffer.alloc(5, 0)

        const n = bufferutils.writePushDataInt(buffer, f.dec, 0)
        assert.strictEqual(buffer.slice(0, n).toString('hex'), f.hexPD)
      })
    })
  })

  describe('writeUInt64LE', function () {
    fixtures.valid.forEach(function (f) {
      it('encodes ' + f.dec + ' correctly', function () {
        const buffer = Buffer.alloc(8, 0)

        bufferutils.writeUInt64LE(buffer, f.dec, 0)
        assert.strictEqual(buffer.toString('hex'), f.hex64)
      })
    })

    fixtures.invalid.readUInt64LE.forEach(function (f) {
      it('throws on ' + f.description, function () {
        const buffer = Buffer.alloc(8, 0)

        assert.throws(function () {
          bufferutils.writeUInt64LE(buffer, f.dec, 0)
        }, new RegExp(f.exception))
      })
    })
  })

  describe('writeVarInt', function () {
    fixtures.valid.forEach(function (f) {
      it('encodes ' + f.dec + ' correctly', function () {
        const buffer = Buffer.alloc(9, 0)

        const n = bufferutils.writeVarInt(buffer, f.dec, 0)
        assert.strictEqual(buffer.slice(0, n).toString('hex'), f.hexVI)
      })
    })

    fixtures.invalid.readUInt64LE.forEach(function (f) {
      it('throws on ' + f.description, function () {
        const buffer = Buffer.alloc(9, 0)

        assert.throws(function () {
          bufferutils.writeVarInt(buffer, f.dec, 0)
        }, new RegExp(f.exception))
      })
    })
  })
})
