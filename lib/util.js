'use strict'

function pad (buf, len, val = 0) {
  let pad = Buffer.alloc(len).fill(val)
  buf.copy(pad, 0)
  return pad
}

function xor (a, b) {
  if (a.length !== b.length) {
    throw new Error('mismatched buffer sizes')
  }

  for (let i = 0; i < a.length; i++) {
    a[i] ^= (b[i] || 0)
  }
  return a
}

module.exports = {
  pad,
  xor
}
