'use strict'

// https://datatracker.ietf.org/doc/html/rfc4493
// https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38B.pdf

const { aes256 } = require('./native')
const { AES_BLOCK_SIZE } = require('./native/constants')
const { pad, xor } = require('./util')

const R128 = Buffer.concat([
  Buffer.alloc(15).fill(0),
  Buffer.from([0b10000111])
])

const CIPHER = {
  AES_256: {
    sizes: { block: AES_BLOCK_SIZE },
    R: R128,
    encrypt: aes256.encrypt
  }
}

async function deriveKeys (cipher, key) {
  let zero = Buffer.alloc(cipher.sizes.block / 8).fill(0)
  let l = await cipher.encrypt(key, zero)
  let k1 = deriveKey(l, cipher.R)
  let k2 = deriveKey(k1, cipher.R)
  return [k1, k2]
}

function deriveKey (key, R) {
  let l = Buffer.from(key)
  let msb = 0

  for (let i = l.length - 1; i >= 0; i--) {
    let b = l[i]
    l[i] = ((b << 1) | msb) & 0xff
    msb = (b >> 7) & 0xff
  }

  if (msb === 1) xor(l, R)
  return l
}

class CMAC {
  static async create (key) {
    let cipher = CIPHER.AES_256
    let subkeys = await deriveKeys(cipher, key)
    return new CMAC(cipher, key, subkeys)
  }

  constructor (cipher, key, [k1, k2]) {
    this._cipher = cipher
    this._key = key
    this._k1 = k1
    this._k2 = k2
  }

  async digest (msg) {
    let len = this._cipher.sizes.block / 8
    let n = Math.ceil(msg.length / len)
    let c = Buffer.alloc(len).fill(0)

    for (let i = 0; i < n; i++) {
      let ofs = Math.min(msg.length, (i + 1) * len)
      let blk = msg.subarray(i * len, ofs)

      if (i === n - 1) {
        blk = this._finalBlock(blk)
      }
      c = await this._ciph(xor(c, blk))
    }

    return c
  }

  _finalBlock (blk) {
    let len = this._cipher.sizes.block / 8

    if (blk.length === len) {
      return xor(Buffer.from(blk), this._k1)
    } else {
      let p = pad(blk, len, 0)
      p[blk.length] = 0x80
      return xor(p, this._k2)
    }
  }

  _ciph (data) {
    return this._cipher.encrypt(this._key, data)
  }
}

module.exports = CMAC
