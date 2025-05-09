'use strict'

// https://words.filippo.io/dispatches/xaes-256-gcm/
// https://github.com/C2SP/C2SP/blob/main/XAES-256-GCM.md

const { aes256gcm } = require('./native')
const CMAC = require('./cmac')

const P1 = Buffer.from([0x00, 0x01, 0x58, 0x00])
const P2 = Buffer.from([0x00, 0x02, 0x58, 0x00])

async function deriveKeys (cmac, iv) {
  let n1 = iv.subarray(0, 12)
  let nx = iv.subarray(12, iv.length)

  let m1 = Buffer.concat([P1, n1])
  let m2 = Buffer.concat([P2, n1])

  // The specification actually gives a more "direct" definition where it uses
  // the fact that the CMAC inputs are exactly one block long to reduce the
  // computation to AES(K, M ^ K1) and avoid the computation of K2.

  let kx = Buffer.concat([
    await cmac.digest(m1),
    await cmac.digest(m2)
  ])

  return [kx, nx]
}

class XAes256Gcm {
  static async create (key) {
    let cmac = await CMAC.create(key)
    return new XAes256Gcm(cmac)
  }

  constructor (cmac) {
    this.cmac = cmac
  }

  async encrypt (iv, data, aad = null) {
    let [kx, nx] = await deriveKeys(this.cmac, iv)
    return aes256gcm.encrypt(kx, nx, data, aad)
  }

  async decrypt (iv, data, aad = null) {
    let [kx, nx] = await deriveKeys(this.cmac, iv)
    return aes256gcm.decrypt(kx, nx, data, aad)
  }
}

module.exports = {
  XAes256Gcm,

  async encrypt (key, iv, data, aad = null) {
    let instance = await XAes256Gcm.create(key)
    return instance.encrypt(iv, data, aad)
  },

  async decrypt (key, iv, data, aad = null) {
    let instance = await XAes256Gcm.create(key)
    return instance.decrypt(iv, data, aad)
  }
}
