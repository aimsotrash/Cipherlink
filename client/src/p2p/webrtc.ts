/**
 * WebRTC DataChannel transport.
 *
 * Establishes a peer-to-peer SCTP DataChannel using the signaling server only
 * to exchange SDP and ICE candidates. Once connected, chat frames never touch
 * the server.
 *
 * A note on layering, because it is easy to get wrong: WebRTC DataChannels are
 * already encrypted with DTLS-SRTP. That protects the hop, and it is NOT what
 * makes this application end-to-end encrypted. DTLS terminates at whatever the
 * peer connection actually reaches, and when TURN is in play the media path is
 * relayed by the operator's server. The end-to-end guarantee comes entirely
 * from the MLS layer above: frames handed to `send()` are already ciphertext.
 * See SECURITY.md, "P2P vs relay".
 */
import { silentLogger, type Logger, type PeerAddress, type SignalPayload } from '@p2pchat/shared';
import {
  EventChannel,
  type DirectChannel,
  type DirectChannelConnectOptions,
  type DirectChannelFactory,
} from './types.js';

const DATA_CHANNEL_LABEL = 'p2pchat';

/** Injectable so tests can supply a stub; production uses the platform class. */
export type PeerConnectionConstructor = new (config: RTCConfiguration) => RTCPeerConnection;

function defaultPeerConnectionConstructor(): PeerConnectionConstructor {
  const impl = (globalThis as { RTCPeerConnection?: PeerConnectionConstructor }).RTCPeerConnection;
  if (!impl) throw new Error('WebRTC is not available in this environment');
  return impl;
}

class WebRtcChannel implements DirectChannel {
  readonly onMessage = new EventChannel<string>();
  readonly onClose = new EventChannel<{ reason: string }>();

  private closed = false;

  constructor(
    private readonly connection: RTCPeerConnection,
    private readonly channel: RTCDataChannel,
    readonly relayed: boolean,
    private readonly cleanup: () => void,
  ) {
    channel.onmessage = (event: MessageEvent) => {
      if (typeof event.data === 'string') this.onMessage.emit(event.data);
    };
    channel.onclose = () => this.handleClosed('datachannel closed');
    channel.onerror = () => this.handleClosed('datachannel error');
    connection.onconnectionstatechange = () => {
      const state = connection.connectionState;
      if (state === 'failed' || state === 'disconnected' || state === 'closed') {
        this.handleClosed(`peer connection ${state}`);
      }
    };
  }

  private handleClosed(reason: string): void {
    if (this.closed) return;
    this.closed = true;
    this.cleanup();
    try {
      this.connection.close();
    } catch {
      /* already torn down */
    }
    this.onClose.emit({ reason });
  }

  send(data: string): void {
    if (this.closed || this.channel.readyState !== 'open') {
      throw new Error('data channel is not open');
    }
    this.channel.send(data);
  }

  close(): void {
    this.handleClosed('closed locally');
  }
}

export interface WebRtcFactoryOptions {
  readonly logger?: Logger;
  readonly peerConnectionConstructor?: PeerConnectionConstructor;
}

export class WebRtcChannelFactory implements DirectChannelFactory {
  private readonly logger: Logger;
  private readonly constructPeerConnection: () => PeerConnectionConstructor;

  constructor(options: WebRtcFactoryOptions = {}) {
    this.logger = (options.logger ?? silentLogger).child('webrtc');
    this.constructPeerConnection = options.peerConnectionConstructor
      ? () => options.peerConnectionConstructor!
      : defaultPeerConnectionConstructor;
  }

  async connect(options: DirectChannelConnectOptions): Promise<DirectChannel> {
    const PeerConnection = this.constructPeerConnection();
    // Always 'all': WebRTC offers no "everything except relay" policy, and
    // 'relay' would *force* TURN — the opposite of what directOnly wants. The
    // direct-only guarantee is enforced instead by dropping our own relay
    // candidates and by re-checking the selected pair after connecting.
    const connection = new PeerConnection({
      iceServers: options.iceServers,
      iceTransportPolicy: 'all',
    });

    const disposers: Array<() => void> = [];
    const cleanup = (): void => {
      for (const dispose of disposers.splice(0)) {
        try {
          dispose();
        } catch {
          /* ignore */
        }
      }
    };

    try {
      return await this.negotiate(connection, options, disposers, cleanup);
    } catch (error) {
      cleanup();
      try {
        connection.close();
      } catch {
        /* ignore */
      }
      throw error;
    }
  }

  private async negotiate(
    connection: RTCPeerConnection,
    options: DirectChannelConnectOptions,
    disposers: Array<() => void>,
    cleanup: () => void,
  ): Promise<DirectChannel> {
    const { peer, sessionId, initiator, signal, directOnly } = options;

    // Buffer remote candidates that arrive before the remote description.
    const pendingCandidates: RTCIceCandidateInit[] = [];
    let remoteDescriptionSet = false;

    const channelPromise = new Promise<RTCDataChannel>((resolve, reject) => {
      if (initiator) {
        const channel = connection.createDataChannel(DATA_CHANNEL_LABEL, {
          ordered: true,
        });
        channel.onopen = () => resolve(channel);
        channel.onerror = () => reject(new Error('data channel failed to open'));
      } else {
        connection.ondatachannel = (event: RTCDataChannelEvent) => {
          const channel = event.channel;
          if (channel.label !== DATA_CHANNEL_LABEL) {
            channel.close();
            return;
          }
          if (channel.readyState === 'open') resolve(channel);
          else channel.onopen = () => resolve(channel);
        };
      }
    });

    connection.onicecandidate = (event: RTCPeerConnectionIceEvent) => {
      if (!event.candidate) return;
      const candidate = event.candidate;
      // When the user demands a strictly direct path, never advertise the
      // relayed candidates that would route traffic through the operator.
      if (directOnly && candidate.candidate.includes(' typ relay')) return;
      signal.send(peer, {
        kind: 'ice-candidate',
        sessionId,
        candidate: candidate.candidate,
        sdpMid: candidate.sdpMid,
        sdpMLineIndex: candidate.sdpMLineIndex,
      });
    };

    const applyPendingCandidates = async (): Promise<void> => {
      remoteDescriptionSet = true;
      for (const candidate of pendingCandidates.splice(0)) {
        try {
          await connection.addIceCandidate(candidate);
        } catch (error) {
          this.logger.warn('failed to add buffered ICE candidate', {
            reason: error instanceof Error ? error.name : 'unknown',
          });
        }
      }
    };

    const answered = new Promise<void>((resolve, reject) => {
      const unsubscribe = signal.subscribe(peer, sessionId, (payload: SignalPayload) => {
        void (async () => {
          try {
            switch (payload.kind) {
              case 'offer': {
                if (initiator) return;
                await connection.setRemoteDescription({ type: 'offer', sdp: payload.sdp });
                await applyPendingCandidates();
                const answer = await connection.createAnswer();
                await connection.setLocalDescription(answer);
                signal.send(peer, { kind: 'answer', sdp: answer.sdp ?? '', sessionId });
                resolve();
                break;
              }
              case 'answer': {
                if (!initiator) return;
                await connection.setRemoteDescription({ type: 'answer', sdp: payload.sdp });
                await applyPendingCandidates();
                resolve();
                break;
              }
              case 'ice-candidate': {
                const candidate: RTCIceCandidateInit = {
                  candidate: payload.candidate,
                  sdpMid: payload.sdpMid,
                  sdpMLineIndex: payload.sdpMLineIndex,
                };
                if (!remoteDescriptionSet) pendingCandidates.push(candidate);
                else await connection.addIceCandidate(candidate);
                break;
              }
              case 'hangup':
                reject(new Error('peer hung up during negotiation'));
                break;
            }
          } catch (error) {
            reject(error instanceof Error ? error : new Error('signaling failure'));
          }
        })();
      });
      disposers.push(unsubscribe);
    });

    if (initiator) {
      const offer = await connection.createOffer();
      await connection.setLocalDescription(offer);
      signal.send(peer, { kind: 'offer', sdp: offer.sdp ?? '', sessionId });
    }

    const timeout = new Promise<never>((_, reject) => {
      const timer = setTimeout(
        () => reject(new Error('timed out establishing a direct connection')),
        options.timeoutMs,
      );
      disposers.push(() => clearTimeout(timer));
    });

    const aborted = new Promise<never>((_, reject) => {
      const abortSignal = options.abortSignal;
      if (!abortSignal) return;
      if (abortSignal.aborted) reject(new Error('connection attempt aborted'));
      const onAbort = (): void => reject(new Error('connection attempt aborted'));
      abortSignal.addEventListener('abort', onAbort, { once: true });
      disposers.push(() => abortSignal.removeEventListener('abort', onAbort));
    });

    const channel = await Promise.race([
      (async () => {
        await answered;
        return channelPromise;
      })(),
      timeout,
      aborted,
    ]);

    const relayed = await this.isRelayed(connection);
    if (directOnly && relayed) {
      throw new Error('only a relayed path was available but direct-only is required');
    }

    this.logger.info('direct channel established', {
      peerUserId: peer.userId,
      peerDeviceId: peer.deviceId,
      relayed,
    });

    return new WebRtcChannel(connection, channel, relayed, cleanup);
  }

  /** Inspect the selected candidate pair to see whether TURN is in the path. */
  private async isRelayed(connection: RTCPeerConnection): Promise<boolean> {
    try {
      const stats = await connection.getStats();
      let selectedPairId: string | undefined;
      const candidates = new Map<string, { candidateType?: string }>();
      const pairs = new Map<string, { selected?: boolean; state?: string; localCandidateId?: string }>();

      stats.forEach((report: Record<string, unknown> & { type: string; id: string }) => {
        if (report.type === 'transport' && typeof report.selectedCandidatePairId === 'string') {
          selectedPairId = report.selectedCandidatePairId;
        } else if (report.type === 'candidate-pair') {
          pairs.set(report.id, report as never);
        } else if (report.type === 'local-candidate') {
          candidates.set(report.id, report as never);
        }
      });

      const pair =
        (selectedPairId ? pairs.get(selectedPairId) : undefined) ??
        [...pairs.values()].find((p) => p.selected === true || p.state === 'succeeded');
      if (!pair?.localCandidateId) return false;
      return candidates.get(pair.localCandidateId)?.candidateType === 'relay';
    } catch {
      // If stats are unavailable we cannot prove the path is direct, so report
      // the more conservative answer rather than claiming a direct connection.
      return true;
    }
  }
}

export type { PeerAddress };
