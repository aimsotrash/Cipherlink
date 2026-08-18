/**
 * Deterministic corruption helpers for authenticity tests.
 *
 * Kept in one place so every "an attacker modified this" test flips bits the
 * same way, and so index access satisfies `noUncheckedIndexedAccess` without
 * scattering non-null assertions through the suite.
 */

/** Return a copy of `bytes` with one bit flipped at `index`. */
export function flipBitAt(bytes: Uint8Array, index: number, mask = 0x01): Uint8Array {
  const copy = Uint8Array.from(bytes);
  const position = index < 0 ? copy.length + index : index;
  const current = copy.at(position);
  if (current === undefined) {
    throw new RangeError(`cannot tamper at index ${index} of a ${bytes.length}-byte buffer`);
  }
  copy[position] = current ^ mask;
  return copy;
}

/** Same, for a Node Buffer (used where a base64 field is decoded first). */
export function flipBufferBit(buffer: Buffer, index = 0, mask = 0x01): Buffer {
  const copy = Buffer.from(buffer);
  const current = copy.at(index);
  if (current === undefined) throw new RangeError('empty buffer');
  copy[index] = current ^ mask;
  return copy;
}
