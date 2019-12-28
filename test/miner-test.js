'use strict';

const assert = require('assert');
const miner = require('../bin/miner');
const mheader = require('./data/miner-header.json');

const hex = ''
  + mheader.nonce
  + mheader.timestamp
  + mheader.pad20
  + mheader.prevBlock
  + mheader.treeRoot
  + mheader.maskHash
  + mheader.extraNonce
  + mheader.reservedRoot
  + mheader.witnessRoot
  + mheader.merkleRoot
  + mheader.version
  + mheader.bits;

describe('Miner', function () {
  it('should read header', () => {
    const raw = Buffer.from(hex, 'hex');

    const header = miner.readHeader(raw);

    // Assert strings equal
    assert.deepEqual(mheader.nonce, header.nonce);
    assert.deepEqual(mheader.pad20, header.pad20);
    assert.deepEqual(mheader.prevBlock, header.prevBlock);
    assert.deepEqual(mheader.treeRoot, header.treeRoot);
    assert.deepEqual(mheader.maskHash, header.maskHash);
    assert.deepEqual(mheader.extraNonce, header.extraNonce);
    assert.deepEqual(mheader.reservedRoot, header.reservedRoot);
    assert.deepEqual(mheader.witnessRoot, header.witnessRoot);
    assert.deepEqual(mheader.merkleRoot, header.merkleRoot);

    // Assert numbers equal
    assert.deepEqual(parseInt(header.time), header.time);
    assert.deepEqual(parseInt(header.version), header.version);
    assert.deepEqual(parseInt(header.bits), header.bits);
  });

  it('should increment', () => {
    const raw = Buffer.from(hex, 'hex');
    const h1 = miner.readHeader(raw);
    miner.increment(raw, Date.now());
    const h2 = miner.readHeader(raw);

    // TODO: add test case for mainnet/regtest
    // that updates the date
    if (miner.binding.NETWORK === 'testnet') {
      assert.deepEqual(
        parseInt(h1.nonce) + 1,
        Buffer.from(h2.nonce, 'hex').readUInt32LE()
      );
    };
  });

  it('should convert to block', () => {
    const raw = Buffer.from(hex, 'hex');
    const templated = miner.toBlock(raw, 1000);
    const header = miner.readHeader(templated);

    assert.deepEqual(
      Buffer.from(header.nonce, 'hex').readUInt32LE(),
      1000
    )
  });
});
