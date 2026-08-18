/**
 * Device *server-authentication* key.
 *
 * This is deliberately a different key from the device's MLS signature
 * credential, and the distinction matters:
 *
 *   - The MLS credential key authenticates *messages to other users*. It lives
 *     inside core-crypto's encrypted store, is never exported, and is what
 *     safety numbers verify.
 *   - This key authenticates *this device to the server*. It replaces
 *     password-based API auth after registration, so a stolen password alone
 *     cannot impersonate a device on the signaling layer.
 *
 * Neither private key is ever transmitted. Compromise of this one lets an
 * attacker talk to the signaling server as the device; it does not let them
 * read or forge messages, because it plays no part in MLS.
 *
 * Ed25519 signing/verification is provided by @noble/curves (audited,
 * actively maintained). We do not implement Ed25519.
 */
import { ed25519 } from '@noble/curves/ed25519';
import { concatBytes, utf8Encode, toBase64, fromBase64 } from '@p2pchat/shared';
import { wipe } from '../crypto/random.js';

export interface DeviceAuthKeyPair {
  readonly privateKey: Uint8Array;
  readonly publicKey: Uint8Array;
}

export function generateDeviceAuthKey(): DeviceAuthKeyPair {
  // noble draws from the platform CSPRNG.
  const privateKey = ed25519.utils.randomPrivateKey();
  const publicKey = ed25519.getPublicKey(privateKey);
  return { privateKey, publicKey };
}

export function devicePublicKeyFrom(privateKey: Uint8Array): Uint8Array {
  return ed25519.getPublicKey(privateKey);
}

/**
 * Build the exact byte string that gets signed for a server challenge.
 *
 * Domain separation (`context`) plus the account and device identifiers means
 * a signature captured in one setting cannot be replayed as another, and a
 * signature for user A's device cannot be presented as user B's.
 */
export function buildChallengeMessage(params: {
  context: string;
  userId: string;
  deviceId: string;
  nonce: Uint8Array;
}): Uint8Array {
  return concatBytes(
    utf8Encode(`${params.context}\n${params.userId}\n${params.deviceId}\n`),
    params.nonce,
  );
}

export function signChallenge(privateKey: Uint8Array, message: Uint8Array): Uint8Array {
  return ed25519.sign(message, privateKey);
}

export function verifyChallenge(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
): boolean {
  try {
    return ed25519.verify(signature, message, publicKey);
  } catch {
    // Malformed points/signatures must be a plain failure, never a throw that
    // could be distinguished from an invalid-but-well-formed signature.
    return false;
  }
}

export function encodePublicKey(publicKey: Uint8Array): string {
  return toBase64(publicKey);
}

export function decodePublicKey(encoded: string): Uint8Array {
  const bytes = fromBase64(encoded);
  if (bytes.length !== 32) throw new Error('Ed25519 public keys are 32 bytes');
  return bytes;
}

export function wipeDeviceKey(pair: DeviceAuthKeyPair): void {
  wipe(pair.privateKey);
}
