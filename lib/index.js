'use strict'

const native = require('./native')

const HKDF = require('./hkdf')
const HMAC = require('./hmac')
const PBKDF2 = require('./pbkdf2')

module.exports = {
  ...native,

  hmacSha256: {
    ...native.hmacSha256,

    sign (key, data) {
      return new HMAC('sha256').sign(key, data)
    }
  },

  hkdfSha256: {
    derive (key, salt, info, size) {
      return new HKDF('sha256').derive(key, salt, info, size)
    }
  },

  pbkdf2: {
    ...native.pbkdf2,

    async digest (password, salt, iterations, size) {
      let hmac = new HMAC('sha256')

      let prf = {
        sizes: { output: hmac.size },
        fn: (key, data) => hmac.sign(key, data)
      }

      let pbkdf2 = new PBKDF2(prf)
      password = password.normalize('NFKD')
      return pbkdf2.digest(password, salt, iterations, size)
    }
  }
}
