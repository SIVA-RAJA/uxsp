/**
 * UXSP Keystore Implementations
 *
 * In-memory and browser-persistent public key registry for peers.
 */

import { PublicCard } from "./types.js";
import { validatePublicCard } from "./schema.js";

export class KeyStoreError extends Error {}
export class PeerNotFoundError extends KeyStoreError {}
export class DuplicatePeerError extends KeyStoreError {}

export abstract class KeyStore {
  abstract get(entityId: string): PublicCard | null | Promise<PublicCard | null>;
  abstract put(card: PublicCard, overwrite?: boolean): void | Promise<void>;
  abstract delete(entityId: string): boolean | Promise<boolean>;
  abstract list(): PublicCard[] | Promise<PublicCard[]>;
  abstract has(entityId: string): boolean | Promise<boolean>;
}

export class MemoryKeyStore extends KeyStore {
  protected cards = new Map<string, PublicCard>();

  get(entityId: string): PublicCard | null {
    return this.cards.get(entityId) || null;
  }

  put(card: PublicCard, overwrite: boolean = true): void {
    if (!validatePublicCard(card)) {
      throw new KeyStoreError("Invalid PublicCard format.");
    }
    if (!overwrite && this.cards.has(card.entity_id)) {
      throw new DuplicatePeerError(`Peer '${card.entity_id}' already registered in keystore.`);
    }
    this.cards.set(card.entity_id, card);
  }

  delete(entityId: string): boolean {
    return this.cards.delete(entityId);
  }

  list(): PublicCard[] {
    return Array.from(this.cards.values());
  }

  has(entityId: string): boolean {
    return this.cards.has(entityId);
  }

  clear(): void {
    this.cards.clear();
  }

  get size(): number {
    return this.cards.size;
  }
}

export class LocalStorageKeyStore extends KeyStore {
  private prefix: string;
  private memoryFallback: MemoryKeyStore;
  private storage: Storage | null = null;

  constructor(prefix: string = "uxsp:peer:") {
    super();
    this.prefix = prefix;
    this.memoryFallback = new MemoryKeyStore();
    try {
      if (typeof window !== "undefined" && window.localStorage) {
        this.storage = window.localStorage;
      }
    } catch {
      this.storage = null;
    }
  }

  get(entityId: string): PublicCard | null {
    if (!this.storage) {
      return this.memoryFallback.get(entityId);
    }
    const raw = this.storage.getItem(this.prefix + entityId);
    if (!raw) return null;
    try {
      return JSON.parse(raw) as PublicCard;
    } catch {
      return null;
    }
  }

  put(card: PublicCard, overwrite: boolean = true): void {
    if (!validatePublicCard(card)) {
      throw new KeyStoreError("Invalid PublicCard format.");
    }
    if (!this.storage) {
      return this.memoryFallback.put(card, overwrite);
    }
    const key = this.prefix + card.entity_id;
    if (!overwrite && this.storage.getItem(key) !== null) {
      throw new DuplicatePeerError(`Peer '${card.entity_id}' already registered in keystore.`);
    }
    this.storage.setItem(key, JSON.stringify(card));
  }

  delete(entityId: string): boolean {
    if (!this.storage) {
      return this.memoryFallback.delete(entityId);
    }
    const key = this.prefix + entityId;
    if (this.storage.getItem(key) === null) return false;
    this.storage.removeItem(key);
    return true;
  }

  list(): PublicCard[] {
    if (!this.storage) {
      return this.memoryFallback.list();
    }
    const cards: PublicCard[] = [];
    for (let i = 0; i < this.storage.length; i++) {
      const k = this.storage.key(i);
      if (k && k.startsWith(this.prefix)) {
        try {
          const raw = this.storage.getItem(k);
          if (raw) cards.push(JSON.parse(raw));
        } catch {
          // ignore corrupted
        }
      }
    }
    return cards;
  }

  has(entityId: string): boolean {
    if (!this.storage) {
      return this.memoryFallback.has(entityId);
    }
    return this.storage.getItem(this.prefix + entityId) !== null;
  }

  clear(): void {
    if (!this.storage) {
      this.memoryFallback.clear();
      return;
    }
    const keysToRemove: string[] = [];
    for (let i = 0; i < this.storage.length; i++) {
      const k = this.storage.key(i);
      if (k && k.startsWith(this.prefix)) {
        keysToRemove.push(k);
      }
    }
    for (const k of keysToRemove) {
      this.storage.removeItem(k);
    }
  }
}
