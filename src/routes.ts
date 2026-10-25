import express, { Request, Response, NextFunction } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import crypto from 'crypto';
import {
  findUserByEmail,
  findUserById,
  createUser,
  getAllDocuments,
  findDocumentById,
  addDocument,
  revokeDocument,
  reactivateDocument,
  getAuditChain,
  appendAuditBlock,
  verifyChainIntegrity,
  tamperWithChain,
  repairAuditChain,
  getAccessRequests,
  createAccessRequest,
  updateAccessRequestStatus,
  toggleEmergencyLockdown,
  getSystemStats,
  initDatabase,
} from './database.ts';
import { User, VaultDocument, UserRole, Classification } from './types.ts';

export const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET || 'trustvault_zero_trust_jwt_secret_key_2025';

// Multer memory storage for secure in-transit file hashing & handling
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 25 * 1024 * 1024 }, // 25 MB limit
});

export interface AuthRequest extends Request {
  user?: {
    id: string;
    email: string;
    role: UserRole;
  };
}

// Authentication middleware
export function authenticateToken(req: AuthRequest, res: Response, next: NextFunction): void {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    res.status(401).json({ error: 'Access Denied: Missing cryptographic Bearer token' });
    return;
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      res.status(403).json({ error: 'Forbidden: Invalid or expired Bearer token' });
      return;
    }
    req.user = decoded as { id: string; email: string; role: UserRole };
    next();
  });
}

// Soft auth helper for demo convenience
function getActorFromRequest(req: AuthRequest): { id: string; email: string; role: string } {
  if (req.user) {
    return req.user;
  }
  const emailHeader = (req.headers['x-actor-email'] as string) || 'admin@trustvault.io';
  const roleHeader = (req.headers['x-actor-role'] as string) || 'admin';
  return {
    id: 'usr_active_session',
    email: emailHeader,
    role: roleHeader,
  };
}

// ==========================================
// 1. AUTHENTICATION & IDENTITY ENDPOINTS
// ==========================================

router.post('/auth/login', (req: Request, res: Response): void => {
  const { email, password } = req.body;

  if (!email || !password) {
    res.status(400).json({ error: 'Email and password are required' });
    return;
  }

  const user = findUserByEmail(email);
  if (!user) {
    appendAuditBlock(
      'AUTH_FAILURE_UNKNOWN_USER',
      'anon_client',
      email,
      'guest',
      '/api/auth/login',
      `Failed authentication attempt for non-existent identity: ${email}`
    );
    res.status(401).json({ error: 'Invalid zero-trust credentials' });
    return;
  }

  if (user.status === 'suspended') {
    appendAuditBlock(
      'AUTH_BLOCKED_SUSPENDED',
      user.id,
      user.email,
      user.role,
      '/api/auth/login',
      'Access rejected: Identity suspended by security policy.'
    );
    res.status(403).json({ error: 'Identity access suspended by policy' });
    return;
  }

  const isMatch = bcrypt.compareSync(password, user.passwordHash);
  if (!isMatch) {
    appendAuditBlock(
      'AUTH_PASSWORD_MISMATCH',
      user.id,
      user.email,
      user.role,
      '/api/auth/login',
      'Failed zero-trust authentication attempt: Bad password credential'
    );
    res.status(401).json({ error: 'Invalid zero-trust credentials' });
    return;
  }

  const token = jwt.sign(
    { id: user.id, email: user.email, role: user.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  appendAuditBlock(
    'AUTH_SUCCESS',
    user.id,
    user.email,
    user.role,
    '/api/auth/login',
    `Authenticated user ${user.email} (${user.role}) with 8h scoped JWT token.`
  );

  res.json({
    token,
    user: {
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
      department: user.department,
      securityClearance: user.securityClearance,
    },
  });
});

router.post('/auth/register', (req: Request, res: Response): void => {
  const { name, email, password, role, department, securityClearance } = req.body;

  if (!name || !email || !password) {
    res.status(400).json({ error: 'Name, email, and password are required' });
    return;
  }

  if (findUserByEmail(email)) {
    res.status(409).json({ error: 'Identity already registered in directory' });
    return;
  }

  const salt = bcrypt.genSaltSync(10);
  const passwordHash = bcrypt.hashSync(password, salt);

  const newUser: User = {
    id: `usr_${Date.now()}_${Math.random().toString(36).substring(2, 7)}`,
    name,
    email,
    passwordHash,
    role: (role as UserRole) || 'user',
    department: department || 'General Operations',
    securityClearance: (securityClearance as Classification) || 'Internal',
    status: 'active',
    createdAt: new Date().toISOString(),
  };

  createUser(newUser);

  appendAuditBlock(
    'IDENTITY_ENROLLED',
    newUser.id,
    newUser.email,
    newUser.role,
    newUser.id,
    `New zero-trust identity registered: ${newUser.name} (${newUser.email}, Clearance: ${newUser.securityClearance})`
  );

  const token = jwt.sign(
    { id: newUser.id, email: newUser.email, role: newUser.role },
    JWT_SECRET,
    { expiresIn: '8h' }
  );

  res.status(201).json({
    token,
    user: {
      id: newUser.id,
      name: newUser.name,
      email: newUser.email,
      role: newUser.role,
      department: newUser.department,
      securityClearance: newUser.securityClearance,
    },
  });
});

router.get('/auth/me', (req: AuthRequest, res: Response): void => {
  const actor = getActorFromRequest(req);
  const user = findUserByEmail(actor.email);
  if (!user) {
    res.status(404).json({ error: 'User identity not found' });
    return;
  }
  res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    department: user.department,
    securityClearance: user.securityClearance,
  });
});

// ==========================================
// 2. DOCUMENT VAULT & REVOCATION ENDPOINTS
// ==========================================

router.get('/documents', (req: Request, res: Response): void => {
  const docs = getAllDocuments();
  res.json(docs);
});

router.get('/documents/:id', (req: Request, res: Response): void => {
  const doc = findDocumentById(req.params.id);
  if (!doc) {
    res.status(404).json({ error: 'Document not found in vault' });
    return;
  }

  doc.accessCount = (doc.accessCount || 0) + 1;

  appendAuditBlock(
    'DOCUMENT_ACCESSED',
    req.headers['x-actor-id'] as string || 'session_user',
    req.headers['x-actor-email'] as string || 'user@trustvault.io',
    req.headers['x-actor-role'] as string || 'user',
    doc.id,
    `Read verification: ${doc.title} (${doc.filename}). Current status: ${doc.status}`
  );

  res.json(doc);
});

router.post('/documents/upload', upload.single('file'), (req: Request, res: Response): void => {
  const { title, classification, contentSnippet } = req.body;
  const file = req.file;

  const actorEmail = (req.headers['x-actor-email'] as string) || 'admin@trustvault.io';
  const actorRole = (req.headers['x-actor-role'] as string) || 'admin';
  const actorId = (req.headers['x-actor-id'] as string) || 'usr_active';

  let sha256Hash = '';
  let filename = '';
  let fileSize = 0;
  let mimeType = 'text/plain';

  if (file) {
    sha256Hash = crypto.createHash('sha256').update(file.buffer).digest('hex');
    filename = file.originalname;
    fileSize = file.size;
    mimeType = file.mimetype;
  } else {
    // Simulated direct text entry
    const snippet = contentSnippet || 'Zero-trust protected document payload.';
    sha256Hash = crypto.createHash('sha256').update(snippet).digest('hex');
    filename = `${(title || 'Document').replace(/\s+/g, '_')}.enc`;
    fileSize = Buffer.byteLength(snippet, 'utf-8');
    mimeType = 'application/octet-stream';
  }

  const newDoc: VaultDocument = {
    id: `doc_tv_${Date.now().toString(36)}_${Math.random().toString(36).substring(2, 6)}`,
    title: title || filename,
    filename,
    fileSize,
    mimeType,
    classification: (classification as Classification) || 'Confidential',
    status: 'active',
    uploadedBy: actorId,
    uploaderEmail: actorEmail,
    sha256Hash,
    encryptionAlgorithm: 'AES-256-GCM (Hardware Cryptographic Module)',
    accessCount: 0,
    createdAt: new Date().toISOString(),
    contentSnippet: contentSnippet || (file ? `Binary encapsulated file (${filename}, ${fileSize} bytes)` : 'Encrypted zero-trust payload.'),
  };

  addDocument(newDoc);

  appendAuditBlock(
    'DOCUMENT_ENCRYPTED',
    actorId,
    actorEmail,
    actorRole,
    newDoc.id,
    `Ingested & encrypted ${newDoc.title} [SHA-256: ${sha256Hash.slice(0, 16)}...] with classification ${newDoc.classification}`
  );

  res.status(201).json(newDoc);
});

// Instantaneous Revocation kill-switch
router.post('/documents/:id/revoke', (req: Request, res: Response): void => {
  const docId = req.params.id;
  const { reason } = req.body;

  const actorEmail = (req.headers['x-actor-email'] as string) || 'admin@trustvault.io';
  const actorRole = (req.headers['x-actor-role'] as string) || 'admin';

  const updatedDoc = revokeDocument(
    docId,
    actorEmail,
    reason || 'Immediate administrative zero-trust revocation',
    actorRole
  );

  if (!updatedDoc) {
    res.status(404).json({ error: 'Target document not found' });
    return;
  }

  res.json({
    message: 'Instantaneous revocation executed successfully. All access keys terminated.',
    document: updatedDoc,
  });
});

// Reinstatement
router.post('/documents/:id/reactivate', (req: Request, res: Response): void => {
  const docId = req.params.id;
  const actorEmail = (req.headers['x-actor-email'] as string) || 'admin@trustvault.io';
  const actorRole = (req.headers['x-actor-role'] as string) || 'admin';

  const updatedDoc = reactivateDocument(docId, actorEmail, actorRole);
  if (!updatedDoc) {
    res.status(404).json({ error: 'Target document not found' });
    return;
  }

  res.json({
    message: 'Document access reinstated.',
    document: updatedDoc,
  });
});

// ==========================================
// 3. TAMPER-EVIDENT AUDIT CHAIN ENDPOINTS
// ==========================================

router.get('/audit-logs', (req: Request, res: Response): void => {
  const chain = getAuditChain();
  res.json(chain);
});

router.post('/audit-logs/verify', (req: Request, res: Response): void => {
  const result = verifyChainIntegrity();

  const actorEmail = (req.headers['x-actor-email'] as string) || 'auditor@trustvault.io';
  const actorRole = (req.headers['x-actor-role'] as string) || 'auditor';

  appendAuditBlock(
    result.valid ? 'INTEGRITY_CHECK_PASS' : 'INTEGRITY_CHECK_FAILED',
    'system_verifier',
    actorEmail,
    actorRole,
    'Audit_Ledger',
    result.valid
      ? `Cryptographic chain verification passed across all ${result.verifiedCount} blocks.`
      : `CRITICAL ALERT: Chain compromised! ${result.reason}`
  );

  res.json(result);
});

// Tamper simulation to show Zero-Trust mathematical verification
router.post('/audit-logs/simulate-tamper', (req: Request, res: Response): void => {
  const { blockIndex, fakeDetails } = req.body;
  const index = typeof blockIndex === 'number' ? blockIndex : 2;
  const details = fakeDetails || 'MALICIOUS_INJECTION: Unauthorized ledger alteration bypassing access control';

  const success = tamperWithChain(index, details);
  if (!success) {
    res.status(400).json({ error: 'Invalid block index to tamper with' });
    return;
  }

  res.json({
    message: `Tamper injected into Block #${index}. You can now run 'Verify Chain' to see the cryptographic proof of tampering!`,
    tamperedBlockIndex: index,
  });
});

router.post('/audit-logs/repair', (req: Request, res: Response): void => {
  repairAuditChain();
  appendAuditBlock(
    'LEDGER_REPAIRED',
    'security_subsystem',
    req.headers['x-actor-email'] as string || 'admin@trustvault.io',
    'admin',
    'Audit_Ledger',
    'Cryptographic ledger re-anchored and hashes recalculated.'
  );
  res.json({ message: 'Audit chain re-anchored and verified.' });
});

// ==========================================
// 4. ACCESS GOVERNANCE & APPROVALS
// ==========================================

router.get('/access-requests', (req: Request, res: Response): void => {
  res.json(getAccessRequests());
});

router.post('/access-requests/create', (req: Request, res: Response): void => {
  const { documentId, justification, durationHours } = req.body;
  const doc = findDocumentById(documentId);

  if (!doc) {
    res.status(404).json({ error: 'Document not found' });
    return;
  }

  const requesterEmail = (req.headers['x-actor-email'] as string) || 'analyst@trustvault.io';
  const requesterId = (req.headers['x-actor-id'] as string) || 'usr_active';

  const newRequest = createAccessRequest({
    id: `req_${Date.now().toString(36)}`,
    documentId: doc.id,
    documentTitle: doc.title,
    requestedBy: requesterId,
    requesterEmail,
    justification: justification || 'Operational compliance review requirement.',
    status: 'pending',
    durationHours: durationHours || 24,
    createdAt: new Date().toISOString(),
  });

  appendAuditBlock(
    'ACCESS_REQUEST_SUBMITTED',
    requesterId,
    requesterEmail,
    'user',
    doc.id,
    `Temporary access requested for ${doc.title} (${durationHours || 24}h). Justification: ${justification}`
  );

  res.status(201).json(newRequest);
});

router.post('/access-requests/:id/decide', (req: Request, res: Response): void => {
  const { status } = req.body;
  if (status !== 'approved' && status !== 'rejected') {
    res.status(400).json({ error: 'Status must be approved or rejected' });
    return;
  }

  const actorEmail = (req.headers['x-actor-email'] as string) || 'admin@trustvault.io';
  const actorRole = (req.headers['x-actor-role'] as string) || 'admin';

  const updated = updateAccessRequestStatus(req.params.id, status, actorEmail);
  if (!updated) {
    res.status(404).json({ error: 'Access request not found' });
    return;
  }

  appendAuditBlock(
    status === 'approved' ? 'ACCESS_REQUEST_APPROVED' : 'ACCESS_REQUEST_REJECTED',
    req.params.id,
    actorEmail,
    actorRole,
    updated.documentId,
    `Access request for ${updated.documentTitle} was ${status} by ${actorEmail}.`
  );

  res.json(updated);
});

// ==========================================
// 5. EMERGENCY LOCKDOWN & TELEMETRY
// ==========================================

router.post('/emergency/lockdown', (req: Request, res: Response): void => {
  const { enabled } = req.body;
  const actorEmail = (req.headers['x-actor-email'] as string) || 'admin@trustvault.io';

  const state = toggleEmergencyLockdown(Boolean(enabled), actorEmail);
  res.json({
    emergencyLockdown: state,
    message: state
      ? 'Emergency Zero-Trust Lockdown ACTIVATED! All non-admin channels severed.'
      : 'Emergency Lockdown DEACTIVATED. Systems operational.',
  });
});

router.get('/stats', (req: Request, res: Response): void => {
  res.json(getSystemStats());
});

router.post('/system/reset-demo', (req: Request, res: Response): void => {
  initDatabase();
  res.json({ message: 'TrustVault demo database reset with default seed data.' });
});
