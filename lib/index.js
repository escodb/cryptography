'use strict'

const native = require('./native')

const HMAC = require('./hmac')

module.exports = {
  ...native,

  hmacSha256: {
    ...native.hmacSha256,

    sign (key, data) {
      return new HMAC('sha256').sign(key, data)
    }
  }
}
