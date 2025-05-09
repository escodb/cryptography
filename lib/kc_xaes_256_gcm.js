'use strict'

// Blockcipher-Based Key Commitment for Nonce-Derived Schemes
// https://eprint.iacr.org/2025/758.pdf

const { timingSafeEqual } = require('crypto')
const { XAes256Gcm } = require('./xaes_256_gcm')
const { AES_BLOCK_SIZE } = require('./native/constants')

// only needed for inline commit key implementation
const { aes256 } = require('./native')
const { xor } = require('./util')

const C3 = Buffer.from([0x58, 0x43, 0x4d, 0x54])
const C4 = Buffer.from([0x00, 0x01, 0x00, 0x01])
const C5 = Buffer.from([0x00, 0x01, 0x00, 0x02])

class KcXAes256Gcm {
  static async create (key) {
    let cipher = await XAes256Gcm.create(key)
    return new KcXAes256Gcm(key, cipher)
  }

  constructor (key, cipher) {
    this._key = key
    this._cipher = cipher
  }

  async encrypt (iv, data, aad = null) {
    let ct = await this._cipher.encrypt(iv, data, aad)
    let kc = await this._commitKey(iv)
    return Buffer.concat([ct, kc])
  }

  async decrypt (iv, data, aad = null) {
    let kc = await this._commitKey(iv)

    let ofs = 2 * AES_BLOCK_SIZE / 8
    let ct = data.subarray(0, data.length - ofs)
    let kc_in = data.subarray(data.length - ofs, data.length)

    let plaintext = this._cipher.decrypt(iv, ct, aad)

    if (timingSafeEqual(kc, kc_in)) {
      return plaintext
    } else {
      throw new Error('oh no')
    }
  }

  async _commitKey (iv) {
    let m1 = Buffer.concat([C3, iv, C4])
    let m2 = Buffer.concat([C3, iv, C5])

    return Buffer.concat([
      await this._cipher.cmac.digest(m1),
      await this._cipher.cmac.digest(m2)
    ])
  }

  // Rather than the above concise definition, the paper actually defines the
  // algorithm by "inlining" the workings of CMAC-AES-256. By splitting the
  // 24-byte IV into two 12-byte pieces, U and V, then CMAC(C3 || IV || C4)
  // becomes:
  //
  //            C3 || U             V || C4
  //               |                  |
  //               |                  |
  //               |                  v
  //               |        +------> XOR <----- K1
  //               |        |         |
  //               |        |         |
  //               v        |         v
  //             AES(K) ----+       AES(K) -->> CMAC
  //
  // This definition skips some work by only computing AES(K, C3 || U) once,
  // and using the fixed 2-block length of the input to avoid the general-case
  // loop of the full CMAC algorithm.

  async _commitKeyInline (iv) {
    let k1 = this._cipher.cmac._k1

    let u = iv.subarray(0, 12)
    let v = iv.subarray(12, iv.length)

    let x1 = await this._ciph(Buffer.concat([C3, u]))
    let w1 = [Buffer.concat([v, C4]), x1, k1].reduce(xor)
    let w2 = [Buffer.concat([v, C5]), x1, k1].reduce(xor)

    return Buffer.concat([
      await this._ciph(w1),
      await this._ciph(w2)
    ])
  }

  _ciph (data) {
    return aes256.encrypt(this._key, data)
  }
}

module.exports = {
  KcXAes256Gcm,

  async encrypt (key, iv, data, aad = null) {
    let instance = await KcXAes256Gcm.create(key)
    return instance.encrypt(iv, data, aad)
  },

  async decrypt (key, iv, data, aad = null) {
    let instance = await KcXAes256Gcm.create(key)
    return instance.decrypt(iv, data, aad)
  }
}
