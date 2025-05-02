'use strict'

// https://datatracker.ietf.org/doc/html/rfc2104

const HASH = require('./hash')
const { pad, xor } = require('./util')

class HMAC {
  constructor (hashName) {
    this._hash = HASH[hashName]
    this.size = this._hash.sizes.output
  }

  async sign (key, message) {
    if (key.length * 8 > this._hash.sizes.block) {
      key = await this._hash.fn(key)
    }

    key = pad(key, this._hash.sizes.block / 8, 0)

    let klen = this._hash.sizes.block / 8
    let ipad = Buffer.alloc(klen).fill(0x36)
    let opad = Buffer.alloc(klen).fill(0x5c)

    return this._hash.fn(Buffer.concat([
      xor(opad, key),
      await this._hash.fn(Buffer.concat([
        xor(ipad, key),
        message
      ]))
    ]))
  }
}

module.exports = HMAC
