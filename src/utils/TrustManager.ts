import { createHash, createVerify } from 'node:crypto';
import { TrustStore, TrustedServer, PublicKey, ProvenanceAttestation } from '../types/index.js';
import { Logger } from './Logger.js';

export class TrustManager {
  private trustStore: TrustStore;
  private logger: Logger;

  constructor(logger: Logger) {
    this.logger = logger;
    this.trustStore = {
      servers: [],
      publicKeys: [],
      allowlist: [],
      denylist: [],
      lastUpdated: new Date().toISOString()
    };
  }

  /**
   * Add a trusted MCP server to the trust store
   */
  async addTrustedServer(
    name: string,
    url: string,
    publicKey: string,
    sha256: string,
    version: string,
    capabilities: string[] = []
  ): Promise<void> {
    const server: TrustedServer = {
      name,
      url,
      publicKey,
      sha256,
      version,
      capabilities,
      verifiedAt: new Date().toISOString()
    };

    // Verify the public key format
    if (!this.verifyPublicKey(publicKey)) {
      throw new Error(`Invalid public key format for server: ${name}`);
    }

    // Check if server already exists
    const existingIndex = this.trustStore.servers.findIndex(s => s.name === name);
    if (existingIndex >= 0) {
      this.trustStore.servers[existingIndex] = server;
      this.logger.info(`Updated trusted server: ${name}`);
    } else {
      this.trustStore.servers.push(server);
      this.logger.info(`Added trusted server: ${name}`);
    }

    this.trustStore.lastUpdated = new Date().toISOString();
    await this.saveTrustStore();
  }

  /**
   * Remove a server from the trust store
   */
  async removeTrustedServer(name: string): Promise<void> {
    const index = this.trustStore.servers.findIndex(s => s.name === name);
    if (index >= 0) {
      this.trustStore.servers.splice(index, 1);
      this.trustStore.lastUpdated = new Date().toISOString();
      await this.saveTrustStore();
      this.logger.info(`Removed trusted server: ${name}`);
    }
  }

  /**
   * Verify if a server is trusted
   */
  isServerTrusted(name: string, url: string): boolean {
    // Check denylist first
    if (this.trustStore.denylist.includes(name) || this.trustStore.denylist.includes(url)) {
      return false;
    }

    // Check allowlist
    if (this.trustStore.allowlist.includes(name) || this.trustStore.allowlist.includes(url)) {
      return true;
    }

    // Check trusted servers
    return this.trustStore.servers.some(server => 
      server.name === name || server.url === url
    );
  }

  /**
   * Verify server signature and provenance
   */
  async verifyServerProvenance(
    serverName: string,
    attestation: ProvenanceAttestation
  ): Promise<boolean> {
    try {
      const server = this.trustStore.servers.find(s => s.name === serverName);
      if (!server) {
        this.logger.warn(`Server not found in trust store: ${serverName}`);
        return false;
      }

      // Verify signature
      const verifier = createVerify('SHA256');
      verifier.update(JSON.stringify(attestation.payload));
      const isValid = verifier.verify(server.publicKey, attestation.signature, 'base64');

      if (!isValid) {
        this.logger.warn(`Invalid signature for server: ${serverName}`);
        return false;
      }

      // Verify timestamp (not too old)
      const attestationTime = new Date(attestation.timestamp);
      const now = new Date();
      const maxAge = 30 * 24 * 60 * 60 * 1000; // 30 days
      if (now.getTime() - attestationTime.getTime() > maxAge) {
        this.logger.warn(`Attestation too old for server: ${serverName}`);
        return false;
      }

      this.logger.info(`Provenance verified for server: ${serverName}`);
      return true;
    } catch (error) {
      this.logger.error(`Error verifying provenance for ${serverName}:`, error as Error);
      return false;
    }
  }

  /**
   * Add server to allowlist
   */
  addToAllowlist(server: string): void {
    if (!this.trustStore.allowlist.includes(server)) {
      this.trustStore.allowlist.push(server);
      this.logger.info(`Added to allowlist: ${server}`);
    }
  }

  /**
   * Add server to denylist
   */
  addToDenylist(server: string): void {
    if (!this.trustStore.denylist.includes(server)) {
      this.trustStore.denylist.push(server);
      this.logger.info(`Added to denylist: ${server}`);
    }
  }

  /**
   * Get trust store
   */
  getTrustStore(): TrustStore {
    return this.trustStore;
  }

  /**
   * Load trust store from file
   */
  async loadTrustStore(): Promise<void> {
    try {
      // In a real implementation, this would load from a secure file
      // For now, we'll use a default trust store
      this.logger.info('Loaded default trust store');
    } catch (error) {
      this.logger.warn('Could not load trust store, using defaults');
    }
  }

  /**
   * Save trust store to file
   */
  private async saveTrustStore(): Promise<void> {
    try {
      // In a real implementation, this would save to a secure file
      this.logger.info('Trust store updated');
    } catch (error) {
      this.logger.error('Failed to save trust store:', error as Error);
    }
  }

  /**
   * Verify public key format
   */
  private verifyPublicKey(publicKey: string): boolean {
    try {
      // Basic validation - in production, use proper key validation
      return publicKey.length > 100 && publicKey.includes('-----BEGIN PUBLIC KEY-----');
    } catch {
      return false;
    }
  }

  /**
   * Generate SHA256 hash
   */
  generateHash(data: string): string {
    return createHash('sha256').update(data).digest('hex');
  }
}
