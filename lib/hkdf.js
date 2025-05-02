'use strict'

// https://datatracker.ietf.org/doc/html/rfc5869

const HMAC = require('./hmac')
const binaries = require('./binaries')

class HKDF {
  constructor (hashName) {
    this._hmac = new HMAC(hashName)
  }

  async derive (key, salt, info, size) {
    key = await this.extract(key, salt)
    return this.expand(key, info, size)
  }

  async extract (key, salt) {
    return this._hmac.sign(salt, key)
  }

  async expand (key, info, size) {
    let n = Math.ceil(size / this._hmac.size)
    let t = [Buffer.alloc(0)]
    let pattern = ['bytes', 'bytes', 'u8']

    for (let i = 1; i <= n; i++) {
      let chunk = binaries.dump(pattern, [t[i - 1], info, i])
      t.push(await this._hmac.sign(key, chunk))
    }

    let cat = Buffer.concat(t)
    return cat.subarray(0, size / 8)
  }
}

module.exports = HKDF
