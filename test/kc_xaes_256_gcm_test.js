'use strict'

const kcxaes256gcm = require('../lib/kc_xaes_256_gcm')
const { assert } = require('chai')

describe('KC-XAES-256-GCM', () => {
  it('encrypts when MSB = 0', async () => {
    let key = Buffer.from('0101010101010101010101010101010101010101010101010101010101010101', 'hex')
    let iv = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWX', 'utf8')
    let msg = Buffer.from('XAES-256-GCM', 'utf8')

    let ct = await kcxaes256gcm.encrypt(key, iv, msg)
    let pt = await kcxaes256gcm.decrypt(key, iv, ct)

    assert.equal(
      ct.toString('hex'),
      'ce546ef63c9cc60765923609b33a9a1974e96e52daf2fcf7075e227104076b6085eebab138855fe57811c04112eff989d44120dfff662d5475a383c3')

    assert.equal(pt, 'XAES-256-GCM')
  })

  it('encrypts with AAD when MSB = 1', async () => {
    let key = Buffer.from('0303030303030303030303030303030303030303030303030303030303030303', 'hex')
    let iv = Buffer.from('ABCDEFGHIJKLMNOPQRSTUVWX', 'utf8')
    let msg = Buffer.from('XAES-256-GCM', 'utf8')
    let aad = Buffer.from('c2sp.org/XAES-256-GCM', 'utf8')

    let ct = await kcxaes256gcm.encrypt(key, iv, msg, aad)
    let pt = await kcxaes256gcm.decrypt(key, iv, ct, aad)

    assert.equal(
      ct.toString('hex'),
      '986ec1832593df5443a179437fd083bf3fdb41abd740a21f71eb769d5553cd21d1592b422e3129632a3187eee8a658cdca5c5b32ce86308dcc18e9d1')

    assert.equal(pt, 'XAES-256-GCM')
  })
})
