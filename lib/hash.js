'use strict'

const native = require('./native')

module.exports = {
  sha256: {
    sizes: { block: 512, output: 256 },
    fn: native.sha256.digest
  }
}
