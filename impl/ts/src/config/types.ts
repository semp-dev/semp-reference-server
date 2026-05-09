/**
 * Server config types per shared/docs/config-schema.md.
 *
 * Mirrors impl/go/internal/config/config.go field-for-field. Shapes
 * match the TOML wire form one-to-one.
 *
 * @module
 */

export interface CryptoConfig {
  suite: string;
}

export interface TLSConfig {
  cert_file: string;
  key_file: string;
  external_tls: boolean;
  quic_addr: string;
}

export interface DatabaseConfig {
  path: string;
  master_key: string;
}

export interface UserConfig {
  address: string;
  password: string;
}

export interface PeerConfig {
  domain: string;
  endpoint: string;
  domain_signing_key: string;
}

export interface FederationConfig {
  session_ttl: number;
  retention: string;
  peers: PeerConfig[];
}

export interface PoWConfig {
  enabled: boolean;
  difficulty: number;
  ttl: number;
}

export interface PolicyConfig {
  session_ttl: number;
  blocked_domains: string[];
  permissions: string[];
  pow: PoWConfig;
}

export interface LoggingConfig {
  level: string;
  format: string;
}

export interface Config {
  domain: string;
  listen_addr: string;
  tls: TLSConfig;
  crypto: CryptoConfig;
  database: DatabaseConfig;
  users: UserConfig[];
  federation: FederationConfig;
  policy: PolicyConfig;
  logging: LoggingConfig;
}
