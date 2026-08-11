/**
 * Owns one {@link PeerLink} per peer device and routes frames between the
 * messaging layer and the network.
 *
 * This is the last layer that still knows *who* a frame is for. It never knows
 * what a frame says.
 */
import {
  silentLogger,
  type Logger,
  type PeerAddress,
  type TransportFrame,
} from '@p2pchat/shared';
import {
  EventChannel,
  peerKey,
  type InboundFrame,
  type DirectChannelFactory,
  type PeerLinkStatus,
  type SignalTransport,
  type TransportKind,
} from './types.js';
import { PeerLink, type PeerLinkPolicy, type PeerLinkRelay, type PeerLinkTimings } from './peerLink.js';

export interface TransportManagerOptions {
  readonly self: PeerAddress;
  readonly channelFactory: DirectChannelFactory;
  readonly signal: SignalTransport;
  readonly relay: PeerLinkRelay;
  readonly getIceServers: () => Promise<RTCIceServer[]>;
  readonly policy: () => PeerLinkPolicy;
  readonly logger?: Logger;
  readonly timings?: Partial<PeerLinkTimings>;
}

export class TransportManager {
  readonly onFrame = new EventChannel<InboundFrame>();
  readonly onStatus = new EventChannel<PeerLinkStatus>();

  private readonly links = new Map<string, PeerLink>();
  private readonly logger: Logger;

  constructor(private readonly options: TransportManagerOptions) {
    this.logger = (options.logger ?? silentLogger).child('transport');
  }

  private link(peer: PeerAddress): PeerLink {
    const key = peerKey(peer);
    let link = this.links.get(key);
    if (!link) {
      link = new PeerLink({
        self: this.options.self,
        peer,
        channelFactory: this.options.channelFactory,
        signal: this.options.signal,
        relay: this.options.relay,
        getIceServers: this.options.getIceServers,
        policy: this.options.policy,
        logger: this.logger,
        ...(this.options.timings ? { timings: this.options.timings } : {}),
      });
      link.onFrame.subscribe(({ frame, via }) => this.onFrame.emit({ from: peer, frame, via }));
      link.onStatus.subscribe((status) => this.onStatus.emit(status));
      this.links.set(key, link);
    }
    return link;
  }

  /** Start reaching a peer eagerly, e.g. when a conversation is opened. */
  warmUp(peer: PeerAddress): void {
    this.link(peer).connect();
  }

  async send(peer: PeerAddress, frame: TransportFrame): Promise<TransportKind> {
    return this.link(peer).send(frame);
  }

  /** Deliver a relay envelope that the signaling client received. */
  deliverRelayFrame(from: PeerAddress, frame: TransportFrame): void {
    this.link(from).acceptRelayFrame(frame);
  }

  statusFor(peer: PeerAddress): PeerLinkStatus | undefined {
    return this.links.get(peerKey(peer))?.status;
  }

  allStatuses(): PeerLinkStatus[] {
    return [...this.links.values()].map((link) => link.status);
  }

  closePeer(peer: PeerAddress): void {
    const key = peerKey(peer);
    this.links.get(key)?.close();
    this.links.delete(key);
  }

  closeAll(): void {
    for (const link of this.links.values()) link.close();
    this.links.clear();
  }
}
