import crypto from 'crypto';
import fs from 'fs';
import path from 'path';
import bcrypt from 'bcryptjs';
import { User, VaultDocument, AuditBlock, AccessRequest, SystemStats } from './types.ts';

const DATA_DIR = path.resolve(process.cwd(), 'data');
const DATA_FILE = path.join(DATA_DIR, 'vault_storage.json');

interface VaultStorage {
  users: User[];
  documents: VaultDocument[];
  auditChain: AuditBlock[];
  accessRequests: AccessRequest[];
  emergencyLockdown: boolean;
}

let memoryStorage: VaultStorage = {
  users: [],
  documents: [],
  auditChain: [],
  accessRequests: [],
  emergencyLockdown: false,
};

function calculateBlockHash(
  blockIndex: number,
  timestamp: string,
  action: string,
  actorId: string,
  actorEmail: string,
  targetResource: string,
  details: string,
  prevHash: string
): string {
  const payload = `${blockIndex}|${timestamp}|${action}|${actorId}|${actorEmail}|${targetResource}|${details}|${prevHash}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function persistStorage(): void {
  try {
    if (!fs.existsSync(DATA_DIR)) {
      fs.mkdirSync(DATA_DIR, { recursive: true });
    }
    fs.writeFileSync(DATA_FILE, JSON.stringify(memoryStorage, null, 2), 'utf-8');
  } catch (err) {
    console.warn('[TrustVault] Could not write persistent storage to disk (using memory):', err);
  }
}

function loadStorage(): boolean {
  try {
    if (fs.existsSync(DATA_FILE)) {
      const raw = fs.readFileSync(DATA_FILE, 'utf-8');
      memoryStorage = JSON.parse(raw);
      return true;
    }
  } catch (err) {
    console.warn('[TrustVault] Could not load storage file, initializing defaults:', err);
  }
  return false;
}

export function appendAuditBlock(
  action: string,
  actorId: string,
  actorEmail: string,
  actorRole: string,
  targetResource: string,
  details: string
): AuditBlock {
  const chain = memoryStorage.auditChain;
  const lastBlock = chain.length > 0 ? chain[chain.length - 1] : null;
  const prevHash = lastBlock
    ? lastBlock.blockHash
    : '0000000000000000000000000000000000000000000000000000000000000000';
  const blockIndex = chain.length;
  const timestamp = new Date().toISOString();

  const blockHash = calculateBlockHash(
    blockIndex,
    timestamp,
    action,
    actorId,
    actorEmail,
    targetResource,
    details,
    prevHash
  );

  const newBlock: AuditBlock = {
    blockIndex,
    timestamp,
    action,
    actorId,
    actorEmail,
    actorRole,
    targetResource,
    details,
    prevHash,
    blockHash,
  };

  chain.push(newBlock);
  persistStorage();
  return newBlock;
}

export function verifyChainIntegrity(): {
  valid: boolean;
  verifiedCount: number;
  invalidBlockIndex?: number;
  reason?: string;
} {
  const chain = memoryStorage.auditChain;
  if (chain.length === 0) {
    return { valid: true, verifiedCount: 0 };
  }

  for (let i = 0; i < chain.length; i++) {
    const block = chain[i];
    const expectedPrevHash =
      i === 0
        ? '0000000000000000000000000000000000000000000000000000000000000000'
        : chain[i - 1].blockHash;

    if (block.prevHash !== expectedPrevHash) {
      return {
        valid: false,
        verifiedCount: i,
        invalidBlockIndex: i,
        reason: `Broken chain link at Block #${i}: prevHash mismatch. Expected ${expectedPrevHash.slice(0, 16)}..., found ${block.prevHash.slice(0, 16)}...`,
      };
    }

    const recalculatedHash = calculateBlockHash(
      block.blockIndex,
      block.timestamp,
      block.action,
      block.actorId,
      block.actorEmail,
      block.targetResource,
      block.details,
      block.prevHash
    );

    if (block.blockHash !== recalculatedHash) {
      return {
        valid: false,
        verifiedCount: i,
        invalidBlockIndex: i,
        reason: `Cryptographic payload alteration detected in Block #${i}. Hash recalculated does not match stored blockHash!`,
      };
    }
  }

  return { valid: true, verifiedCount: chain.length };
}

export function tamperWithChain(blockIndex: number, fakeDetails: string): boolean {
  if (blockIndex >= 0 && blockIndex < memoryStorage.auditChain.length) {
    memoryStorage.auditChain[blockIndex].details = fakeDetails;
    persistStorage();
    return true;
  }
  return false;
}

export function repairAuditChain(): void {
  const chain = memoryStorage.auditChain;
  for (let i = 0; i < chain.length; i++) {
    const prevHash =
      i === 0
        ? '0000000000000000000000000000000000000000000000000000000000000000'
        : chain[i - 1].blockHash;

    chain[i].blockIndex = i;
    chain[i].prevHash = prevHash;
    chain[i].blockHash = calculateBlockHash(
      chain[i].blockIndex,
      chain[i].timestamp,
      chain[i].action,
      chain[i].actorId,
      chain[i].actorEmail,
      chain[i].targetResource,
      chain[i].details,
      prevHash
    );
  }
  persistStorage();
}

export function initDatabase(): void {
  const loaded = loadStorage();
  if (loaded && memoryStorage.users.length > 0) {
    console.log('[TrustVault] Storage restored from file:', {
      users: memoryStorage.users.length,
      documents: memoryStorage.documents.length,
      auditBlocks: memoryStorage.auditChain.length,
    });
    return;
  }

  console.log('[TrustVault] Initializing fresh database with Zero-Trust seed policy...');

  const salt = bcrypt.genSaltSync(10);
  const adminHash = bcrypt.hashSync('Admin@123', salt);
  const secOfficerHash = bcrypt.hashSync('Security@123', salt);
  const auditorHash = bcrypt.hashSync('Auditor@123', salt);
  const analystHash = bcrypt.hashSync('Analyst@123', salt);

  const initialUsers: User[] = [
    {
      id: 'usr_admin_01',
      name: 'Elena Rostova',
      email: 'admin@trustvault.io',
      passwordHash: adminHash,
      role: 'admin',
      department: 'Global Security Operations',
      securityClearance: 'Top Secret',
      status: 'active',
      createdAt: new Date(Date.now() - 30 * 86400000).toISOString(),
    },
    {
      id: 'usr_sec_02',
      name: 'Marcus Vance',
      email: 'security@trustvault.io',
      passwordHash: secOfficerHash,
      role: 'security_officer',
      department: 'Threat & Incident Response',
      securityClearance: 'Top Secret',
      status: 'active',
      createdAt: new Date(Date.now() - 25 * 86400000).toISOString(),
    },
    {
      id: 'usr_aud_03',
      name: 'Sarah Chen',
      email: 'auditor@trustvault.io',
      passwordHash: auditorHash,
      role: 'auditor',
      department: 'Regulatory Compliance & Forensics',
      securityClearance: 'Restricted',
      status: 'active',
      createdAt: new Date(Date.now() - 20 * 86400000).toISOString(),
    },
    {
      id: 'usr_usr_04',
      name: 'David Kim',
      email: 'analyst@trustvault.io',
      passwordHash: analystHash,
      role: 'user',
      department: 'Financial Risk Intelligence',
      securityClearance: 'Confidential',
      status: 'active',
      createdAt: new Date(Date.now() - 15 * 86400000).toISOString(),
    },
  ];

  const initialDocs: VaultDocument[] = [
    {
      id: 'doc_tv_001',
      title: 'Q3 Enterprise Financial Audit & Liquidity Ratios',
      filename: 'Q3_Financial_Audit_Consolidated.pdf',
      fileSize: 4194304,
      mimeType: 'application/pdf',
      classification: 'Top Secret',
      status: 'active',
      uploadedBy: 'usr_admin_01',
      uploaderEmail: 'admin@trustvault.io',
      sha256Hash: 'a8b79c3f56e921d7b0451a9e88d726c84132bcfe519280d463e26462719ba0a1',
      encryptionAlgorithm: 'AES-256-GCM (Zero-Trust Envelope)',
      accessCount: 14,
      createdAt: new Date(Date.now() - 10 * 86400000).toISOString(),
      contentSnippet: 'CONFIDENTIAL: Consolidated international asset distributions, off-shore custodial covenants, and risk-weighted capital adequacy metrics for Q3 review.',
    },
    {
      id: 'doc_tv_002',
      title: 'Project Titan: Quantum-Resistant Encryption Spec',
      filename: 'Project_Titan_Architecture_Specs.docx',
      fileSize: 2097152,
      mimeType: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
      classification: 'Restricted',
      status: 'active',
      uploadedBy: 'usr_sec_02',
      uploaderEmail: 'security@trustvault.io',
      sha256Hash: '3f92ba48e02d1877cb705291244ab91d0e461c28c899317b6d194514ba490192',
      encryptionAlgorithm: 'ChaCha20-Poly1305 + Kyber-768',
      accessCount: 29,
      createdAt: new Date(Date.now() - 6 * 86400000).toISOString(),
      contentSnippet: 'TECHNICAL SPECIFICATION: Implementation blueprint for post-quantum lattice-based key exchange protocols across core API gateways.',
    },
    {
      id: 'doc_tv_003',
      title: 'Critical Infrastructure Breach Contingency Playbook',
      filename: 'Incident_Response_Playbook_v4.pdf',
      fileSize: 1572864,
      mimeType: 'application/pdf',
      classification: 'Confidential',
      status: 'active',
      uploadedBy: 'usr_sec_02',
      uploaderEmail: 'security@trustvault.io',
      sha256Hash: '729b46ef01d84a3b7023ec581b90c74823a9d20c572a118f6d8924bce8193217',
      encryptionAlgorithm: 'AES-256-GCM',
      accessCount: 8,
      createdAt: new Date(Date.now() - 3 * 86400000).toISOString(),
      contentSnippet: 'STANDARD OPERATING PROCEDURE: Immediate containment procedures, key rotation pipelines, and regulatory notification deadlines under ISO/IEC 27001.',
    },
    {
      id: 'doc_tv_004',
      title: 'Revoked Compromised Credential Export (Batch #992)',
      filename: 'Compromised_Access_Dump_Nov24.enc',
      fileSize: 819200,
      mimeType: 'application/octet-stream',
      classification: 'Restricted',
      status: 'revoked',
      uploadedBy: 'usr_sec_02',
      uploaderEmail: 'security@trustvault.io',
      sha256Hash: 'd31b0981e77f02a490ca9142ec71b80264197a0df27490f845a7c2937be41590',
      encryptionAlgorithm: 'AES-256-GCM',
      revokedAt: new Date(Date.now() - 1 * 86400000).toISOString(),
      revokedBy: 'admin@trustvault.io',
      revocationReason: 'Emergency security revocation: Stale key detected during anomaly analysis.',
      accessCount: 42,
      createdAt: new Date(Date.now() - 5 * 86400000).toISOString(),
      contentSnippet: '[REVOKED BY SECURITY ADMIN] Access to this object has been terminated across all policy enforcement points.',
    },
  ];

  memoryStorage.users = initialUsers;
  memoryStorage.documents = initialDocs;
  memoryStorage.auditChain = [];
  memoryStorage.accessRequests = [
    {
      id: 'req_001',
      documentId: 'doc_tv_001',
      documentTitle: 'Q3 Enterprise Financial Audit & Liquidity Ratios',
      requestedBy: 'usr_usr_04',
      requesterEmail: 'analyst@trustvault.io',
      justification: 'Quarterly compliance reconciliation report submission due Friday.',
      status: 'pending',
      durationHours: 24,
      createdAt: new Date(Date.now() - 4 * 3600000).toISOString(),
    },
    {
      id: 'req_002',
      documentId: 'doc_tv_002',
      documentTitle: 'Project Titan: Quantum-Resistant Encryption Spec',
      requestedBy: 'usr_aud_03',
      requesterEmail: 'auditor@trustvault.io',
      justification: 'External security framework adherence verification.',
      status: 'approved',
      durationHours: 48,
      approvedBy: 'admin@trustvault.io',
      approvedAt: new Date(Date.now() - 24 * 3600000).toISOString(),
      expiresAt: new Date(Date.now() + 24 * 3600000).toISOString(),
      createdAt: new Date(Date.now() - 28 * 3600000).toISOString(),
    },
  ];
  memoryStorage.emergencyLockdown = false;

  // Build Genesis Block and historical audit trail
  appendAuditBlock(
    'SYSTEM_GENESIS',
    'system_root',
    'system@trustvault.internal',
    'admin',
    'TrustVault_Root_Ledger',
    'Cryptographic tamper-evident audit ledger initialized with SHA-256 genesis block.'
  );

  appendAuditBlock(
    'USER_SEEDED',
    'system_root',
    'system@trustvault.internal',
    'admin',
    'usr_admin_01',
    'Seeded default Super Admin identity with Top Secret clearance.'
  );

  appendAuditBlock(
    'DOCUMENT_ENCRYPTED',
    'usr_admin_01',
    'admin@trustvault.io',
    'admin',
    'doc_tv_001',
    'Uploaded & encapsulated Q3_Financial_Audit_Consolidated.pdf with AES-256-GCM envelope.'
  );

  appendAuditBlock(
    'DOCUMENT_ENCRYPTED',
    'usr_sec_02',
    'security@trustvault.io',
    'security_officer',
    'doc_tv_002',
    'Uploaded Project_Titan_Architecture_Specs.docx under Restricted classification policy.'
  );

  appendAuditBlock(
    'INSTANT_REVOCATION',
    'usr_admin_01',
    'admin@trustvault.io',
    'admin',
    'doc_tv_004',
    'INSTANT REVOCATION TRIGGERED: Terminated all bearer token grants for Compromised_Access_Dump_Nov24.enc.'
  );

  persistStorage();
  console.log('[TrustVault] Initialized database with', memoryStorage.auditChain.length, 'tamper-evident audit blocks.');
}

// Data access helpers
export function getAllUsers(): User[] {
  return memoryStorage.users;
}

export function findUserByEmail(email: string): User | undefined {
  return memoryStorage.users.find((u) => u.email.toLowerCase() === email.toLowerCase());
}

export function findUserById(id: string): User | undefined {
  return memoryStorage.users.find((u) => u.id === id);
}

export function createUser(user: User): User {
  memoryStorage.users.push(user);
  persistStorage();
  return user;
}

export function getAllDocuments(): VaultDocument[] {
  return memoryStorage.documents;
}

export function findDocumentById(id: string): VaultDocument | undefined {
  return memoryStorage.documents.find((d) => d.id === id);
}

export function addDocument(doc: VaultDocument): VaultDocument {
  memoryStorage.documents.unshift(doc);
  persistStorage();
  return doc;
}

export function revokeDocument(
  docId: string,
  revokedByEmail: string,
  reason: string,
  actorRole: string
): VaultDocument | null {
  const doc = memoryStorage.documents.find((d) => d.id === docId);
  if (!doc) return null;

  doc.status = 'revoked';
  doc.revokedAt = new Date().toISOString();
  doc.revokedBy = revokedByEmail;
  doc.revocationReason = reason || 'Instant administrative access termination';

  appendAuditBlock(
    'INSTANT_REVOCATION',
    doc.uploadedBy,
    revokedByEmail,
    actorRole,
    doc.id,
    `DOCUMENT ACCESS REVOKED: ${doc.title} (${doc.filename}). Reason: ${doc.revocationReason}`
  );

  persistStorage();
  return doc;
}

export function reactivateDocument(
  docId: string,
  reinstatedByEmail: string,
  actorRole: string
): VaultDocument | null {
  const doc = memoryStorage.documents.find((d) => d.id === docId);
  if (!doc) return null;

  doc.status = 'active';
  doc.revokedAt = undefined;
  doc.revokedBy = undefined;
  doc.revocationReason = undefined;

  appendAuditBlock(
    'DOCUMENT_REINSTATED',
    doc.uploadedBy,
    reinstatedByEmail,
    actorRole,
    doc.id,
    `DOCUMENT ACCESS REINSTATED: ${doc.title} marked active.`
  );

  persistStorage();
  return doc;
}

export function getAuditChain(): AuditBlock[] {
  return memoryStorage.auditChain;
}

export function getAccessRequests(): AccessRequest[] {
  return memoryStorage.accessRequests;
}

export function createAccessRequest(req: AccessRequest): AccessRequest {
  memoryStorage.accessRequests.unshift(req);
  persistStorage();
  return req;
}

export function updateAccessRequestStatus(
  reqId: string,
  status: 'approved' | 'rejected',
  decidedByEmail: string
): AccessRequest | null {
  const req = memoryStorage.accessRequests.find((r) => r.id === reqId);
  if (!req) return null;

  req.status = status;
  req.approvedBy = decidedByEmail;
  req.approvedAt = new Date().toISOString();
  if (status === 'approved') {
    req.expiresAt = new Date(Date.now() + (req.durationHours || 24) * 3600000).toISOString();
  }

  persistStorage();
  return req;
}

export function toggleEmergencyLockdown(enabled: boolean, triggeredByEmail: string): boolean {
  memoryStorage.emergencyLockdown = enabled;
  appendAuditBlock(
    enabled ? 'EMERGENCY_LOCKDOWN_ACTIVATED' : 'EMERGENCY_LOCKDOWN_DEACTIVATED',
    'security_subsystem',
    triggeredByEmail,
    'security_officer',
    'ALL_VAULT_RESOURCES',
    enabled
      ? 'CRITICAL ALERT: Zero-Trust Emergency Lockdown initiated. All external access suspended except Super Admin.'
      : 'Lockdown status lifted. Standard Zero-Trust policy enforcement resumed.'
  );
  persistStorage();
  return memoryStorage.emergencyLockdown;
}

export function getSystemStats(): SystemStats {
  const docs = memoryStorage.documents;
  const integrity = verifyChainIntegrity();

  return {
    totalDocuments: docs.length,
    activeDocuments: docs.filter((d) => d.status === 'active').length,
    revokedDocuments: docs.filter((d) => d.status === 'revoked').length,
    totalAuditBlocks: memoryStorage.auditChain.length,
    chainIntegrityValid: integrity.valid,
    emergencyLockdown: memoryStorage.emergencyLockdown,
    totalUsers: memoryStorage.users.length,
    pendingRequests: memoryStorage.accessRequests.filter((r) => r.status === 'pending').length,
  };
}
