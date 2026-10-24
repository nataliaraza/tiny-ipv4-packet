/**
 * tiny-ipv4-packet — decode an IPv4 datagram buffer into its header fields
 * and payload offset. Zero dependencies, ESM only.
 */

export { parseIPv4, formatIPv4, IPv4Packet } from './core.js';
export { MIN_HEADER_LENGTH, MIN_IHL, MAX_IHL } from './core.js';
