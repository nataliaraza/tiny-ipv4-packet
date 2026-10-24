import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  parseIPv4,
  formatIPv4,
  MIN_HEADER_LENGTH,
  MIN_IHL,
  MAX_IHL,
} from '../src/index.js';

/**
 * Builds a 20-byte (no options) IPv4 header with caller-specified overrides.
 * @param {Object} [overrides]
 * @returns {Uint8Array}
 */
function buildHeader(overrides = {}) {
  const b = new Uint8Array(20);
  // version=4, IHL=5
  b[0] = 0x45;
  // total length 20 (filled by default)
  b[2] = 0x00;
  b[3] = 20;
  // TTL
  b[8] = 64;
  // protocol = UDP (17)
  b[9] = 17;
  // source 192.168.1.1
  b[12] = 192;
  b[13] = 168;
  b[14] = 1;
  b[15] = 1;
  // destination 10.0.0.2
  b[16] = 10;
  b[17] = 0;
  b[18] = 0;
  b[19] = 2;
  if (overrides.version !== undefined) {
    b[0] = (overrides.version << 4) | (overrides.ihl ?? 5);
  } else if (overrides.ihl !== undefined) {
    b[0] = 0x40 | (overrides.ihl & 0x0f);
  }
  if (overrides.totalLength !== undefined) {
    b[2] = (overrides.totalLength >> 8) & 0xff;
    b[3] = overrides.totalLength & 0xff;
  }
  if (overrides.protocol !== undefined) b[9] = overrides.protocol;
  if (overrides.ttl !== undefined) b[8] = overrides.ttl;
  if (overrides.identification !== undefined) {
    b[4] = (overrides.identification >> 8) & 0xff;
    b[5] = overrides.identification & 0xff;
  }
  if (overrides.flags !== undefined) {
    b[6] = (b[6] & 0x1f) | ((overrides.flags & 0x07) << 5);
  }
  if (overrides.fragmentOffset !== undefined) {
    // preserve top 3 bits (flags)
    const flagBits = b[6] & 0xe0;
    b[6] = flagBits | ((overrides.fragmentOffset >> 8) & 0x1f);
    b[7] = overrides.fragmentOffset & 0xff;
  }
  if (overrides.headerChecksum !== undefined) {
    b[10] = (overrides.headerChecksum >> 8) & 0xff;
    b[11] = overrides.headerChecksum & 0xff;
  }
  if (overrides.src) {
    b[12] = overrides.src[0];
    b[13] = overrides.src[1];
    b[14] = overrides.src[2];
    b[15] = overrides.src[3];
  }
  if (overrides.dst) {
    b[16] = overrides.dst[0];
    b[17] = overrides.dst[1];
    b[18] = overrides.dst[2];
    b[19] = overrides.dst[3];
  }
  return b;
}

test('parses a minimal 20-byte UDP datagram', () => {
  const buf = buildHeader();
  const pkt = parseIPv4(buf);
  assert.equal(pkt.version, 4);
  assert.equal(pkt.ihl, 5);
  assert.equal(pkt.headerLength, 20);
  assert.equal(pkt.totalLength, 20);
  assert.equal(pkt.protocol, 17);
  assert.equal(pkt.ttl, 64);
  assert.equal(pkt.sourceAddress, '192.168.1.1');
  assert.equal(pkt.destinationAddress, '10.0.0.2');
  assert.equal(pkt.options, null);
  assert.equal(pkt.payloadOffset, 20);
  assert.equal(pkt.payloadLength, 0);
  assert.equal(pkt.identification, 0);
  assert.equal(pkt.flags, 0);
  assert.equal(pkt.fragmentOffset, 0);
  assert.equal(pkt.headerChecksum, 0);
});

test('parses a header with 8 bytes of options (IHL=7)', () => {
  const buf = new Uint8Array(28); // 20 + 8 option bytes, no payload
  buf[0] = 0x47; // version 4, IHL 7
  buf[2] = 0x00; buf[3] = 28; // total length 28
  buf[8] = 64; buf[9] = 6;    // TTL 64, TCP
  buf[12] = 172; buf[13] = 16; buf[14] = 0; buf[15] = 1; // 172.16.0.1
  buf[16] = 8; buf[17] = 8; buf[18] = 8; buf[19] = 8;   // 8.8.8.8
  // option bytes 20–27: a NOP and an end-of-options-list for padding
  buf[20] = 1; // NOP
  buf[21] = 0; // End of Options List
  for (let i = 22; i < 28; i++) buf[i] = 0;
  const pkt = parseIPv4(buf);
  assert.equal(pkt.ihl, 7);
  assert.equal(pkt.headerLength, 28);
  assert.equal(pkt.options.length, 8);
  assert.equal(pkt.options[0], 1);
  assert.equal(pkt.options[1], 0);
  assert.equal(pkt.payloadOffset, 28);
  assert.equal(pkt.payloadLength, 0);
});

test('parses a datagram with payload', () => {
  const payload = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
  const buf = new Uint8Array(20 + payload.length);
  buf.set(buildHeader({ totalLength: 20 + payload.length }), 0);
  buf.set(payload, 20);
  const pkt = parseIPv4(buf);
  assert.equal(pkt.payloadOffset, 20);
  assert.equal(pkt.payloadLength, 4);
});

test('parses flags and fragment offset correctly', () => {
  // DF set, fragment offset 0
  let pkt = parseIPv4(buildHeader({ flags: 0b010 }));
  assert.equal(pkt.flags, 2);
  assert.equal(pkt.fragmentOffset, 0);
  // MF set, fragment offset 1480 (185 * 8)
  pkt = parseIPv4(buildHeader({ flags: 0b001, fragmentOffset: 185 }));
  assert.equal(pkt.flags, 1);
  assert.equal(pkt.fragmentOffset, 185);
});

test('parses identification and checksum fields', () => {
  const pkt = parseIPv4(buildHeader({
    identification: 0x1234,
    headerChecksum: 0xabcd,
  }));
  assert.equal(pkt.identification, 0x1234);
  assert.equal(pkt.headerChecksum, 0xabcd);
});

test('formatIPv4 produces dotted-quad notation', () => {
  const bytes = new Uint8Array([10, 0, 0, 1, 0, 0, 0, 0]);
  assert.equal(formatIPv4(bytes.subarray(0, 4)), '10.0.0.1');
  assert.equal(formatIPv4(bytes.subarray(4, 8)), '0.0.0.0');
});

test('rejects non-Uint8Array inputs', () => {
  assert.throws(() => parseIPv4(null), TypeError);
  assert.throws(() => parseIPv4('not a buffer'), TypeError);
  assert.throws(() => parseIPv4(new ArrayBuffer(20)), TypeError);
});

test('rejects a buffer shorter than the minimum header', () => {
  assert.throws(() => parseIPv4(new Uint8Array(19)), RangeError);
});

test('rejects a non-IPv4 version', () => {
  assert.throws(() => parseIPv4(buildHeader({ version: 6 })), RangeError);
});

test('rejects an out-of-range IHL value', () => {
  assert.throws(() => parseIPv4(buildHeader({ ihl: 4 })), RangeError);
  assert.throws(() => parseIPv4(buildHeader({ ihl: 16 })), RangeError);
});

test('rejects a buffer shorter than the declared header', () => {
  // IHL=7 requires 28 bytes; supply only 20
  const buf = new Uint8Array(20);
  buf[0] = 0x47;
  buf[2] = 0x00; buf[3] = 28;
  assert.throws(() => parseIPv4(buf), RangeError);
});

test('rejects a totalLength smaller than the header length', () => {
  assert.throws(() => parseIPv4(buildHeader({ totalLength: 19 })), RangeError);
});

test('clamps payload when totalLength exceeds buffer length', () => {
  // Capture padding can make the buffer larger than totalLength; here we test the
  // opposite case: totalLength larger than the buffer. The parser must not overrun.
  const buf = buildHeader({ totalLength: 100 }); // only 20 bytes present
  const pkt = parseIPv4(buf);
  assert.equal(pkt.totalLength, 100);
  assert.equal(pkt.payloadLength, 0); // usable = min(100, 20) - 20
});

test('exposes header constants', () => {
  assert.equal(MIN_HEADER_LENGTH, 20);
  assert.equal(MIN_IHL, 5);
  assert.equal(MAX_IHL, 15);
});

test('parses maximum 60-byte header (IHL=15)', () => {
  const buf = new Uint8Array(60);
  buf[0] = 0x4f; // version 4, IHL 15
  buf[2] = 0x00; buf[3] = 60;
  buf[8] = 255; buf[9] = 1; // TTL 255, ICMP
  buf[12] = 0; buf[13] = 0; buf[14] = 0; buf[15] = 0; // 0.0.0.0
  buf[16] = 255; buf[17] = 255; buf[18] = 255; buf[19] = 255; // 255.255.255.255
  const pkt = parseIPv4(buf);
  assert.equal(pkt.ihl, 15);
  assert.equal(pkt.headerLength, 60);
  assert.equal(pkt.options.length, 40);
  assert.equal(pkt.sourceAddress, '0.0.0.0');
  assert.equal(pkt.destinationAddress, '255.255.255.255');
  assert.equal(pkt.payloadOffset, 60);
  assert.equal(pkt.payloadLength, 0);
});
