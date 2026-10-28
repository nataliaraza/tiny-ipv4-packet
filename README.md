# tiny-ipv4-packet

Decodes an IPv4 datagram buffer into version, IHL, total length, protocol, source/destination addresses, options, and payload offset. Zero runtime dependencies, ESM only.

## Usage

```js
import { parseIPv4 } from 'tiny-ipv4-packet';

const datagram = new Uint8Array([
  // 20-byte IPv4 header (no options), UDP payload of 4 bytes
  0x45, 0x00, 0x00, 0x18, // ver=4 ihl=5, tos=0, totalLen=24
  0x00, 0x01, 0x00, 0x00, // id=1, flags=0, fragOff=0
  0x40, 0x11, 0x00, 0x00, // ttl=64, proto=17 (UDP), checksum=0
  192, 168, 1, 1,         // src
  10, 0, 0, 2,            // dst
  0xde, 0xad, 0xbe, 0xef  // payload
]);

const pkt = parseIPv4(datagram);
console.log(pkt.version);             // 4
console.log(pkt.ihl);                // 5
console.log(pkt.headerLength);       // 20
console.log(pkt.totalLength);        // 24
console.log(pkt.protocol);           // 17
console.log(pkt.sourceAddress);      // "192.168.1.1"
console.log(pkt.destinationAddress); // "10.0.0.2"
console.log(pkt.options);            // null (no options present)
console.log(pkt.payloadOffset);      // 20
console.log(pkt.payloadLength);      // 4
```

## Why

Parsing IPv4 headers by hand is repetitive and error-prone — bit-shifting IHL, reconstructing fragment offsets, formatting dotted-quad addresses. This library does exactly that and nothing more: it reads the 20-byte fixed header plus any options (up to the 60-byte maximum) and tells you where the payload starts and how many bytes are usable.

The deliberate trade-off: this library does **not** reassemble fragments, does **not** verify the header checksum, and does **not** interpret IP options semantically. Options are returned as a raw byte slice. If you need fragment reassembly or checksum validation, do it downstream where you have the full datagram context.

## Edge case

If the buffer is longer than the datagram's `totalLength` (common when a capture stack pads small frames to a minimum Ethernet size), `payloadLength` is derived from `totalLength` and will be smaller than `buffer.length - payloadOffset`. Conversely, if `totalLength` exceeds the actual buffer size — which can happen with truncated captures — the parser clamps the usable payload to the buffer rather than throwing, so `payloadLength` reflects what is actually available. Callers that need to detect truncation should compare `pkt.totalLength` against `pkt.buffer.length`.

## Exports

- `parseIPv4(buffer: Uint8Array): IPv4Packet` — decode an IPv4 datagram.
- `formatIPv4(bytes: Uint8Array): string` — format 4 bytes as dotted-quad.
- `IPv4Packet` — the class returned by `parseIPv4`; see source for all fields.
- `MIN_HEADER_LENGTH` (20), `MIN_IHL` (5), `MAX_IHL` (15) — constants.

## Design notes

The window stores values eagerly rather than keeping running aggregates. Running
sums drift with floating point over long streams, and recomputing from a small
buffer is cheap enough that the drift is not worth the speed.

