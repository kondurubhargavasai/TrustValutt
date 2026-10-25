export type UserRole = 'admin' | 'security_officer' | 'auditor' | 'user';

export type Classification = 'Top Secret' | 'Restricted' | 'Confidential' | 'Internal' | 'Public';

export type DocumentStatus = 'active' | 'revoked' | 'quarantined' | 'expired';

export interface User {
  id: string;
  name: string;
  email: string;
  passwordHash: string;
  role: UserRole;
  department: string;
  securityClearance: Classification;
  status: 'active' | 'suspended';
  createdAt: string;
}

export interface VaultDocument {
  id: string;
  title: string;
  filename: string;
  fileSize: number;
  mimeType: string;
  classification: Classification;
  status: DocumentStatus;
  uploadedBy: string;
  uploaderEmail: string;
  sha256Hash: string;
  encryptionAlgorithm: string;
  revokedAt?: string;
  revokedBy?: string;
  revocationReason?: string;
  expiresAt?: string;
  accessCount: number;
  createdAt: string;
  contentSnippet?: string;
}

export interface AuditBlock {
  blockIndex: number;
  timestamp: string;
  action: string;
  actorId: string;
  actorEmail: string;
  actorRole: UserRole | string;
  targetResource: string;
  details: string;
  prevHash: string;
  blockHash: string;
}

export interface AccessRequest {
  id: string;
  documentId: string;
  documentTitle: string;
  requestedBy: string;
  requesterEmail: string;
  justification: string;
  status: 'pending' | 'approved' | 'rejected' | 'revoked';
  durationHours: number;
  approvedBy?: string;
  approvedAt?: string;
  expiresAt?: string;
  createdAt: string;
}

export interface SystemStats {
  totalDocuments: number;
  activeDocuments: number;
  revokedDocuments: number;
  totalAuditBlocks: number;
  chainIntegrityValid: boolean;
  emergencyLockdown: boolean;
  totalUsers: number;
  pendingRequests: number;
}
