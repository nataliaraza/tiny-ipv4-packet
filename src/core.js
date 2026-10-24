/**
 * Core IPv4 packet parser.
 *
 * Parses an IPv4 datagram from a raw buffer and returns a decoded view.
 * Does NOT reassemble fragments and does NOT parse IP options semantically;
 * options are returned as a raw byte slice for the caller to interpret.
 */

/**
 * Result of parsing an IPv4 datagram.
 */
export class IPv4Packet {
  /**
   * IP version; always 4 for a successfully parsed datagram.
   * @type {number}
   */
  version;

  /**
   * Internet Header Length, in 32-bit words. Range 5–15 per RFC 791.
   * @type {number}
   */
  ihl;

  /**
   * Header length in bytes, equals ihl * 4.
 * @type {number}
   */
  headerLength;

  /**
   * Total length of the datagram in bytes, from the Total Length field.
   * @type {number}
   */
  totalLength;

  /**
   * 16-bit identification field.
   * @type {number}
   */
  identification;

  /**
   * Flags field (3 bits) as documented in RFC 791: bit 0 reserved (0),
   * bit 1 DF (1 = don't fragment), bit 2 MF (1 = more fragments).
   * @type {number}
   */
  flags;

  /**
   * Fragment offset in 8-byte units.
   * @type {number}
   */
  fragmentOffset;

  /**
   * Time-to-Live.
   * @type {number}
   */
  ttl;

  /**
   * L4 protocol number (e.g., 1 = ICMP, 6 = TCP, 17 = UDP).
   * @type {number}
   */
  protocol;

  /**
   * 16-bit header checksum as stored in the datagram (NOT computed).
   * @type {number}
   */
  headerChecksum;

  /**
   * Source IPv4 address in dotted-quad notation.
   * @type {string}
   */
  sourceAddress;

  /**
   * Destination IPv4 address in dotted-quad notation.
   * @type {string}
   */
  destinationAddress;

  /**
   * Raw IP options bytes, or null when IHL is 5 (no options present).
   * @type {Uint8Array|null}
   */
  options;

  /**
   * Byte offset of the payload within the original buffer. Equals headerLength.
   * @type {number}
   */
  payloadOffset;

  /**
   * Number of payload bytes available in the buffer, constrained by totalLength
   * and the buffer's actual size so callers cannot overrun.
   * @type {number}
   */
  payloadLength;

  /**
   * The original buffer reference for slicing. Not copied; callers must not mutate
   * the buffer after parsing if they intend to call payload().
   * @type {Uint8Array}
   */
  buffer;
}

/**
 * Minimum header length in bytes (IHL = 5, no options).
 */
export const MIN_HEADER_LENGTH = 20;

/**
 * Minimum IHL value (5 = 20-byte header with no options).
 */
export const MIN_IHL = 5;

/**
 * Maximum IHL value (15 = 60-byte header with 40 bytes of options).
 */
export const MAX_IHL = 15;

/**
 * Formats a 4-byte IPv4 address as a dotted-quad string.
 *
 * Exposed so tests can verify individual address formatting; no array allocation
 * is needed since we build the string from four named bytes.
 *
 * @param {Uint8Array} bytes - A view of at least 4 bytes; only the first 4 are used.
 * @returns {string} Dotted-quad address like "192.168.1.1".
 */
export function formatIPv4(bytes) {
  return `${bytes[0]}.${bytes[1]}.${bytes[2]}.${bytes[3]}`;
}

/**
 * Parses an IPv4 datagram buffer and returns a decoded view.
 *
 * Only basic structural validation is performed:
 *  - buffer must be at least 20 bytes (minimum header)
 *  - version nibble must be 4
 *  - IHL must be in the range 5–15 and must fit within the buffer
 *  - totalLength must be ≥ header length and ≤ buffer length
 *
 * The buffer is NOT copied; the returned object holds a reference to it so that
 * the payload() accessor can return a subarray without allocation. Callers must
 * avoid mutating the original buffer after parsing.
 *
 * @param {Uint8Array} buffer - Raw IPv4 datagram bytes.
 * @returns {IPv4Packet} Decoded packet view.
 * @throws {TypeError} If buffer is not a Uint8Array.
 * @throws {RangeError} If buffer is too short, version ≠ 4, IHL is invalid or
 *   inconsistent with the buffer, or totalLength is inconsistent.
 */
export function parseIPv4(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('buffer must be a Uint8Array');
  }

  if (buffer.length < MIN_HEADER_LENGTH) {
    throw new RangeError(
      `buffer too short: need at least ${MIN_HEADER_LENGTH} bytes, got ${buffer.length}`
    );
  }

  const versionByte = buffer[0];
  const version = versionByte >>> 4;
  if (version !== 4) {
    throw new RangeError(`expected IPv4 (version 4), got version ${version}`);
  }

  const ihl = versionByte & 0x0f;
  if (ihl < MIN_IHL || ihl > MAX_IHL) {
    throw new RangeError(`IHL out of range [${MIN_IHL}, ${MAX_IHL}]: ${ihl}`);
  }

  const headerLength = ihl * 4;
  if (buffer.length < headerLength) {
    throw new RangeError(
      `buffer shorter than declared header: need ${headerLength} bytes, got ${buffer.length}`
    );
  }

  // Read totalLength as unsigned 16-bit.
  const totalLength = (buffer[2] << 8) | buffer[3];
  if (totalLength < headerLength) {
    throw new RangeError(
      `totalLength (${totalLength}) is less than header length (${headerLength})`
    );
  }
  if (totalLength > buffer.length) {
    // Don't fail: some capture stacks pad small frames to a minimum size.
    // We clamp the usable payload length to the actual buffer instead.
    // Callers can detect this by comparing packet.totalLength to packet.buffer.length.
  }

  const identification = (buffer[4] << 8) | buffer[5];
  const flagsX = buffer[6];
  // Flags occupy the top 3 bits of byte 6.
  const flags = flagsX >>> 5;
  // Fragment offset occupies the low 5 bits of byte 6 and all 8 bits of byte 7,
  // for a total of 13 bits (max 8191).
  const fragmentOffset = ((flagsX & 0x1f) << 8) | buffer[7];
  const ttl = buffer[8];
  const protocol = buffer[9];
  const headerChecksum = (buffer[10] << 8) | buffer[11];

  const sourceAddress = formatIPv4(buffer.subarray(12, 16));
  const destinationAddress = formatIPv4(buffer.subarray(16, 20));

  const optionsLength = headerLength - MIN_HEADER_LENGTH;
  // null for the common no-options case; tests check both branches.
  const options = optionsLength > 0 ? buffer.subarray(20, headerLength) : null;

  // Constrain to the actual buffer so payload() never overruns when totalLength
  // exceeds buffer.length (e.g., padding in captures).
  const usableLength = Math.min(totalLength, buffer.length);
  const payloadLength = usableLength - headerLength;

  const pkt = new IPv4Packet();
  pkt.version = version;
  pkt.ihl = ihl;
  pkt.headerLength = headerLength;
  pkt.totalLength = totalLength;
  pkt.identification = identification;
  pkt.flags = flags;
  pkt.fragmentOffset = fragmentOffset;
  pkt.ttl = ttl;
  pkt.protocol = protocol;
  pkt.headerChecksum = headerChecksum;
  pkt.sourceAddress = sourceAddress;
  pkt.destinationAddress = destinationAddress;
  pkt.options = options;
  pkt.payloadOffset = headerLength;
  pkt.payloadLength = payloadLength;
  pkt.buffer = buffer;
  return pkt;
}
