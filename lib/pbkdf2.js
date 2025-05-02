'use strict'

// https://datatracker.ietf.org/doc/html/rfc2898#section-5.2
// https://datatracker.ietf.org/doc/html/rfc8018#section-5.2

const binaries = require('./binaries')
const { xor } = require('./util')

class PBKDF2 {
  constructor (prf) {
    this._prf = prf
  }

  async digest (password, salt, iterations, size) {
    let pw = Buffer.from(password, 'utf8')
    let blocks = Math.ceil(size / this._prf.sizes.output)
    let t = []

    for (let j = 0; j < blocks; j++) {
      t[j] = await this._F(pw, salt, iterations, j + 1)
    }

    let cat = Buffer.concat(t)
    return cat.subarray(0, size / 8)
  }

  async _F (pw, salt, iterations, i) {
    let acc = Buffer.alloc(this._prf.sizes.output / 8)
    let buf = binaries.dump(['bytes', 'u32'], [salt, i])

    for (let j = 0; j < iterations; j++) {
      buf = await this._prf.fn(pw, buf)
      acc = xor(acc, buf)
    }

    return acc
  }
}

module.exports = PBKDF2
