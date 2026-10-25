import React, { useState, useEffect, useMemo } from 'react';
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Lock,
  Unlock,
  FileText,
  Key,
  Users,
  Search,
  Plus,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Eye,
  Trash2,
  ArrowRight,
  Database,
  Hash,
  Activity,
  Layers,
  ChevronRight,
  Download,
  Copy,
  ExternalLink,
  Flame,
  FileCheck,
  Ban,
  Radio,
  UserCheck,
} from 'lucide-react';
import { VaultDocument, AuditBlock, AccessRequest, SystemStats, Classification, UserRole } from './types.ts';

// Pre-defined identities for instant role switching & testing
const DEMO_USERS = [
  {
    id: 'usr_admin_01',
    name: 'Elena Rostova',
    email: 'admin@trustvault.io',
    role: 'admin' as UserRole,
    department: 'Global Security Operations',
    securityClearance: 'Top Secret' as Classification,
  },
  {
    id: 'usr_sec_02',
    name: 'Marcus Vance',
    email: 'security@trustvault.io',
    role: 'security_officer' as UserRole,
    department: 'Threat & Incident Response',
    securityClearance: 'Top Secret' as Classification,
  },
  {
    id: 'usr_aud_03',
    name: 'Sarah Chen',
    email: 'auditor@trustvault.io',
    role: 'auditor' as UserRole,
    department: 'Regulatory Compliance & Forensics',
    securityClearance: 'Restricted' as Classification,
  },
  {
    id: 'usr_usr_04',
    name: 'David Kim',
    email: 'analyst@trustvault.io',
    role: 'user' as UserRole,
    department: 'Financial Risk Intelligence',
    securityClearance: 'Confidential' as Classification,
  },
];

export default function App() {
  const [currentUser, setCurrentUser] = useState(DEMO_USERS[0]);
  const [activeTab, setActiveTab] = useState<'vault' | 'audit' | 'governance' | 'command'>('vault');
  
  // Data state
  const [documents, setDocuments] = useState<VaultDocument[]>([]);
  const [auditChain, setAuditChain] = useState<AuditBlock[]>([]);
  const [accessRequests, setAccessRequests] = useState<AccessRequest[]>([]);
  const [stats, setStats] = useState<SystemStats | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [statusMessage, setStatusMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);

  // Search & Filter state
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedClassification, setSelectedClassification] = useState<string>('ALL');
  const [selectedStatus, setSelectedStatus] = useState<string>('ALL');

  // Modals state
  const [isUploadOpen, setIsUploadOpen] = useState(false);
  const [isRevokeOpen, setIsRevokeOpen] = useState(false);
  const [selectedDocForRevoke, setSelectedDocForRevoke] = useState<VaultDocument | null>(null);
  const [revokeReason, setRevokeReason] = useState('Immediate administrative zero-trust revocation due to key compromise risk');
  const [viewingDoc, setViewingDoc] = useState<VaultDocument | null>(null);
  const [isRequestOpen, setIsRequestOpen] = useState(false);
  const [selectedDocForRequest, setSelectedDocForRequest] = useState<VaultDocument | null>(null);
  const [requestJustification, setRequestJustification] = useState('');
  const [requestHours, setRequestHours] = useState(24);

  // Verification state
  const [verifying, setVerifying] = useState(false);
  const [verificationResult, setVerificationResult] = useState<{
    valid: boolean;
    verifiedCount: number;
    invalidBlockIndex?: number;
    reason?: string;
  } | null>(null);

  // Upload Form State
  const [uploadTitle, setUploadTitle] = useState('');
  const [uploadClassification, setUploadClassification] = useState<Classification>('Confidential');
  const [uploadContent, setUploadContent] = useState('');
  const [uploadFile, setUploadFile] = useState<File | null>(null);

  // Headers helper with actor context
  const getHeaders = () => ({
    'Content-Type': 'application/json',
    'x-actor-id': currentUser.id,
    'x-actor-email': currentUser.email,
    'x-actor-role': currentUser.role,
  });

  // Fetch all core resources
  const fetchAllData = async () => {
    try {
      setLoading(true);
      const [docsRes, auditRes, reqsRes, statsRes] = await Promise.all([
        fetch('/api/documents'),
        fetch('/api/audit-logs'),
        fetch('/api/access-requests'),
        fetch('/api/stats'),
      ]);

      if (docsRes.ok) setDocuments(await docsRes.json());
      if (auditRes.ok) setAuditChain(await auditRes.json());
      if (reqsRes.ok) setAccessRequests(await reqsRes.json());
      if (statsRes.ok) setStats(await statsRes.json());
    } catch (err) {
      console.warn('[TrustVault] Could not fetch remote API:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllData();
  }, []);

  const showNotification = (type: 'success' | 'error' | 'info', text: string) => {
    setStatusMessage({ type, text });
    setTimeout(() => {
      setStatusMessage(null);
    }, 4500);
  };

  // Instant Revocation Trigger
  const handleInstantRevoke = async () => {
    if (!selectedDocForRevoke) return;
    try {
      const res = await fetch(`/api/documents/${selectedDocForRevoke.id}/revoke`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ reason: revokeReason }),
      });
      if (res.ok) {
        showNotification('success', `INSTANT REVOCATION EXECUTED: All access to "${selectedDocForRevoke.title}" severed.`);
        setIsRevokeOpen(false);
        setSelectedDocForRevoke(null);
        await fetchAllData();
      } else {
        showNotification('error', 'Failed to execute revocation.');
      }
    } catch (err) {
      showNotification('error', 'Network error during revocation.');
    }
  };

  // Reactivate Document Access
  const handleReactivate = async (docId: string, docTitle: string) => {
    try {
      const res = await fetch(`/api/documents/${docId}/reactivate`, {
        method: 'POST',
        headers: getHeaders(),
      });
      if (res.ok) {
        showNotification('success', `Access reinstated for "${docTitle}".`);
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to reinstate document.');
    }
  };

  // Run Cryptographic Hash Chain Verification
  const handleVerifyChain = async () => {
    try {
      setVerifying(true);
      const res = await fetch('/api/audit-logs/verify', {
        method: 'POST',
        headers: getHeaders(),
      });
      if (res.ok) {
        const data = await res.json();
        setVerificationResult(data);
        if (data.valid) {
          showNotification('success', `Cryptographic Proof Verified: All ${data.verifiedCount} SHA-256 blocks are untampered.`);
        } else {
          showNotification('error', `CRITICAL: Hash chain compromise detected at Block #${data.invalidBlockIndex}!`);
        }
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Error running cryptographic verification.');
    } finally {
      setVerifying(false);
    }
  };

  // Simulate Adversary Tamper Attack
  const handleSimulateTamper = async () => {
    try {
      const targetIndex = auditChain.length > 2 ? 2 : 1;
      const res = await fetch('/api/audit-logs/simulate-tamper', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          blockIndex: targetIndex,
          fakeDetails: 'ATTACKER_OVERRIDE: Altered clearance level from Restricted to Public [TAMPERED_ENTRY]',
        }),
      });
      if (res.ok) {
        showNotification('info', `Simulated adversary payload alteration injected into Block #${targetIndex}. Run "Verify Chain" to catch it!`);
        setVerificationResult(null);
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to simulate tamper attack.');
    }
  };

  // Repair Chain
  const handleRepairChain = async () => {
    try {
      const res = await fetch('/api/audit-logs/repair', {
        method: 'POST',
        headers: getHeaders(),
      });
      if (res.ok) {
        showNotification('success', 'Audit ledger recalculated and cryptographic integrity re-anchored.');
        setVerificationResult(null);
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to repair chain.');
    }
  };

  // Handle Document Ingestion (Upload)
  const handleUploadSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!uploadTitle.trim()) {
      showNotification('error', 'Document title is required.');
      return;
    }

    try {
      const formData = new FormData();
      formData.append('title', uploadTitle);
      formData.append('classification', uploadClassification);
      if (uploadContent) formData.append('contentSnippet', uploadContent);
      if (uploadFile) formData.append('file', uploadFile);

      const res = await fetch('/api/documents/upload', {
        method: 'POST',
        headers: {
          'x-actor-id': currentUser.id,
          'x-actor-email': currentUser.email,
          'x-actor-role': currentUser.role,
        },
        body: formData,
      });

      if (res.ok) {
        showNotification('success', `Document "${uploadTitle}" encrypted and vaulted.`);
        setIsUploadOpen(false);
        setUploadTitle('');
        setUploadContent('');
        setUploadFile(null);
        await fetchAllData();
      } else {
        showNotification('error', 'Upload failed.');
      }
    } catch (err) {
      showNotification('error', 'Error uploading document.');
    }
  };

  // Submit Access Request
  const handleRequestSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedDocForRequest) return;
    try {
      const res = await fetch('/api/access-requests/create', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({
          documentId: selectedDocForRequest.id,
          justification: requestJustification,
          durationHours: Number(requestHours),
        }),
      });
      if (res.ok) {
        showNotification('success', 'Zero-Trust access request submitted for policy approval.');
        setIsRequestOpen(false);
        setSelectedDocForRequest(null);
        setRequestJustification('');
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to submit request.');
    }
  };

  // Decide on Access Request
  const handleDecideRequest = async (requestId: string, decision: 'approved' | 'rejected') => {
    try {
      const res = await fetch(`/api/access-requests/${requestId}/decide`, {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ status: decision }),
      });
      if (res.ok) {
        showNotification('success', `Access request has been ${decision}.`);
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to update access request.');
    }
  };

  // Toggle Emergency Lockdown
  const handleToggleLockdown = async () => {
    const newState = !stats?.emergencyLockdown;
    try {
      const res = await fetch('/api/emergency/lockdown', {
        method: 'POST',
        headers: getHeaders(),
        body: JSON.stringify({ enabled: newState }),
      });
      if (res.ok) {
        showNotification(newState ? 'error' : 'success', newState ? 'EMERGENCY ZERO-TRUST LOCKDOWN ACTIVATED!' : 'Lockdown lifted. Systems nominal.');
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to change lockdown state.');
    }
  };

  // Reset Demo
  const handleResetDemo = async () => {
    try {
      const res = await fetch('/api/system/reset-demo', {
        method: 'POST',
        headers: getHeaders(),
      });
      if (res.ok) {
        showNotification('success', 'Database reset with default seed configuration.');
        setVerificationResult(null);
        await fetchAllData();
      }
    } catch (err) {
      showNotification('error', 'Failed to reset demo data.');
    }
  };

  // Filtered documents
  const filteredDocuments = useMemo(() => {
    return documents.filter((doc) => {
      const matchesSearch =
        doc.title.toLowerCase().includes(searchQuery.toLowerCase()) ||
        doc.filename.toLowerCase().includes(searchQuery.toLowerCase()) ||
        doc.sha256Hash.toLowerCase().includes(searchQuery.toLowerCase());
      const matchesClass = selectedClassification === 'ALL' || doc.classification === selectedClassification;
      const matchesStatus = selectedStatus === 'ALL' || doc.status === selectedStatus;
      return matchesSearch && matchesClass && matchesStatus;
    });
  }, [documents, searchQuery, selectedClassification, selectedStatus]);

  const getClassificationBadge = (cls: Classification) => {
    switch (cls) {
      case 'Top Secret':
        return 'bg-rose-950 text-rose-300 border-rose-700/60';
      case 'Restricted':
        return 'bg-amber-950 text-amber-300 border-amber-700/60';
      case 'Confidential':
        return 'bg-blue-950 text-blue-300 border-blue-700/60';
      case 'Internal':
        return 'bg-emerald-950 text-emerald-300 border-emerald-700/60';
      default:
        return 'bg-slate-900 text-slate-300 border-slate-700';
    }
  };

  const getActionBadge = (action: string) => {
    if (action.includes('REVOCATION')) return 'bg-rose-950 text-rose-300 border-rose-700';
    if (action.includes('LOCKDOWN')) return 'bg-red-950 text-red-200 border-red-600 animate-pulse';
    if (action.includes('ENCRYPTED') || action.includes('INGEST')) return 'bg-emerald-950 text-emerald-300 border-emerald-700';
    if (action.includes('AUTH')) return 'bg-sky-950 text-sky-300 border-sky-700';
    if (action.includes('INTEGRITY')) return 'bg-indigo-950 text-indigo-300 border-indigo-700';
    return 'bg-slate-900 text-slate-300 border-slate-800';
  };

  return (
    <div className="min-h-screen bg-[#070b14] text-slate-100 flex flex-col selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Top Banner: Emergency Lockdown Alert if active */}
      {stats?.emergencyLockdown && (
        <div className="bg-red-950/90 border-b border-red-600/70 text-red-200 px-4 py-2.5 flex items-center justify-between text-xs sm:text-sm font-semibold tracking-wide">
          <div className="flex items-center gap-2">
            <Flame className="w-5 h-5 text-red-400 animate-bounce" />
            <span>CRITICAL: ZERO-TRUST EMERGENCY LOCKDOWN ACTIVE. ALL NON-ADMIN TOKEN ACCESS SUSPENDED.</span>
          </div>
          {(currentUser.role === 'admin' || currentUser.role === 'security_officer') && (
            <button
              onClick={handleToggleLockdown}
              className="bg-red-800 hover:bg-red-700 text-white px-3 py-1 rounded text-xs transition border border-red-500"
            >
              Lift Lockdown
            </button>
          )}
        </div>
      )}

      {/* Floating Status Notification */}
      {statusMessage && (
        <div
          className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-2xl backdrop-blur-md text-sm transition-all animate-in fade-in slide-in-from-top-4 ${
            statusMessage.type === 'success'
              ? 'bg-emerald-950/90 text-emerald-200 border-emerald-600'
              : statusMessage.type === 'error'
              ? 'bg-rose-950/90 text-rose-200 border-rose-600'
              : 'bg-cyan-950/90 text-cyan-200 border-cyan-600'
          }`}
        >
          {statusMessage.type === 'success' && <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />}
          {statusMessage.type === 'error' && <AlertTriangle className="w-5 h-5 text-rose-400 shrink-0" />}
          {statusMessage.type === 'info' && <Radio className="w-5 h-5 text-cyan-400 shrink-0" />}
          <span>{statusMessage.text}</span>
        </div>
      )}

      {/* Navigation Header */}
      <header className="border-b border-slate-800/80 bg-[#0a0f1d]/90 backdrop-blur-md sticky top-0 z-40">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-3.5 flex flex-wrap items-center justify-between gap-4">
          {/* Logo & Brand */}
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-gradient-to-br from-cyan-500 to-blue-600 p-0.5 shadow-lg shadow-cyan-500/20 flex items-center justify-center">
              <div className="w-full h-full bg-[#0a0f1d] rounded-[10px] flex items-center justify-center">
                <ShieldCheck className="w-6 h-6 text-cyan-400" />
              </div>
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-lg tracking-tight text-white">TrustVault</span>
                <span className="px-2 py-0.5 text-[10px] uppercase tracking-widest font-mono font-bold rounded bg-cyan-950 text-cyan-400 border border-cyan-800/60">
                  Zero-Trust
                </span>
              </div>
              <p className="text-xs text-slate-400 hidden sm:block">
                Tamper-Evident Audit Chaining & Instantaneous Revocation
              </p>
            </div>
          </div>

          {/* Quick Role / Identity Switcher */}
          <div className="flex items-center gap-2 sm:gap-3">
            <div className="flex items-center gap-2 bg-slate-900/80 border border-slate-800 rounded-lg px-3 py-1.5 text-xs">
              <UserCheck className="w-4 h-4 text-cyan-400" />
              <span className="text-slate-400 hidden md:inline">Identity:</span>
              <select
                aria-label="Select Demo User Identity"
                value={currentUser.id}
                onChange={(e) => {
                  const found = DEMO_USERS.find((u) => u.id === e.target.value);
                  if (found) setCurrentUser(found);
                }}
                className="bg-transparent text-slate-200 font-medium focus:outline-none cursor-pointer"
              >
                {DEMO_USERS.map((user) => (
                  <option key={user.id} value={user.id} className="bg-slate-900 text-white">
                    {user.name} ({user.role.toUpperCase()} - {user.securityClearance})
                  </option>
                ))}
              </select>
            </div>

            {/* Emergency Killswitch Toggle Button */}
            {(currentUser.role === 'admin' || currentUser.role === 'security_officer') && (
              <button
                onClick={handleToggleLockdown}
                title="Toggle Instant Zero-Trust Lockdown"
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold border transition ${
                  stats?.emergencyLockdown
                    ? 'bg-red-600 hover:bg-red-500 text-white border-red-400 animate-pulse'
                    : 'bg-slate-900 hover:bg-rose-950/60 text-rose-300 border-rose-900/60'
                }`}
              >
                <Ban className="w-3.5 h-3.5" />
                <span className="hidden sm:inline">
                  {stats?.emergencyLockdown ? 'Lockdown Active' : 'Lockdown'}
                </span>
              </button>
            )}

            <button
              onClick={fetchAllData}
              title="Refresh Data"
              className="p-2 rounded-lg bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 transition"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>

        {/* Navigation Tabs */}
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex space-x-1 sm:space-x-4 border-t border-slate-800/40 overflow-x-auto text-xs sm:text-sm font-medium">
          <button
            onClick={() => setActiveTab('vault')}
            className={`py-3 px-3 border-b-2 transition flex items-center gap-2 shrink-0 ${
              activeTab === 'vault'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Document Vault</span>
            <span className="ml-1 px-1.5 py-0.2 bg-slate-800 rounded-full text-[10px] text-slate-300">
              {documents.length}
            </span>
          </button>

          <button
            onClick={() => setActiveTab('audit')}
            className={`py-3 px-3 border-b-2 transition flex items-center gap-2 shrink-0 ${
              activeTab === 'audit'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Tamper-Evident Ledger</span>
            <span className="ml-1 px-1.5 py-0.2 bg-slate-800 rounded-full text-[10px] text-slate-300">
              {auditChain.length} blocks
            </span>
          </button>

          <button
            onClick={() => setActiveTab('governance')}
            className={`py-3 px-3 border-b-2 transition flex items-center gap-2 shrink-0 ${
              activeTab === 'governance'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Key className="w-4 h-4" />
            <span>Access Governance</span>
            {accessRequests.filter((r) => r.status === 'pending').length > 0 && (
              <span className="ml-1 px-1.5 py-0.2 bg-amber-600 rounded-full text-[10px] text-white animate-pulse">
                {accessRequests.filter((r) => r.status === 'pending').length}
              </span>
            )}
          </button>

          <button
            onClick={() => setActiveTab('command')}
            className={`py-3 px-3 border-b-2 transition flex items-center gap-2 shrink-0 ${
              activeTab === 'command'
                ? 'border-cyan-500 text-cyan-400 font-semibold'
                : 'border-transparent text-slate-400 hover:text-slate-200'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>Security Command Center</span>
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-6">
        {/* ======================================================== */}
        {/* TAB 1: ZERO-TRUST DOCUMENT VAULT                          */}
        {/* ======================================================== */}
        {activeTab === 'vault' && (
          <div className="space-y-6">
            {/* Top Toolbar */}
            <div className="flex flex-col md:flex-row gap-4 items-stretch md:items-center justify-between">
              <div className="flex-1 flex flex-wrap gap-2 items-center">
                {/* Search Input */}
                <div className="relative min-w-[240px] flex-1 max-w-md">
                  <Search className="w-4 h-4 absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input
                    type="text"
                    placeholder="Search documents by title, file, or SHA-256..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="w-full bg-[#0d1424] border border-slate-800 rounded-lg pl-9 pr-4 py-2 text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition"
                  />
                </div>

                {/* Classification Filter */}
                <select
                  aria-label="Filter by Classification"
                  value={selectedClassification}
                  onChange={(e) => setSelectedClassification(e.target.value)}
                  className="bg-[#0d1424] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Clearances</option>
                  <option value="Top Secret">Top Secret</option>
                  <option value="Restricted">Restricted</option>
                  <option value="Confidential">Confidential</option>
                  <option value="Internal">Internal</option>
                </select>

                {/* Status Filter */}
                <select
                  aria-label="Filter by Document Status"
                  value={selectedStatus}
                  onChange={(e) => setSelectedStatus(e.target.value)}
                  className="bg-[#0d1424] border border-slate-800 rounded-lg px-3 py-2 text-xs text-slate-300 focus:outline-none focus:border-cyan-500"
                >
                  <option value="ALL">All Statuses</option>
                  <option value="active">Active</option>
                  <option value="revoked">Revoked</option>
                </select>
              </div>

              {/* Upload Action */}
              <button
                onClick={() => setIsUploadOpen(true)}
                className="flex items-center justify-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium px-4 py-2 rounded-lg text-sm shadow-lg shadow-cyan-600/20 transition"
              >
                <Plus className="w-4 h-4" />
                <span>Ingest &amp; Encrypt Document</span>
              </button>
            </div>

            {/* Document Count & Active Policy Summary */}
            <div className="flex flex-wrap items-center justify-between text-xs text-slate-400 bg-[#0d1424]/60 border border-slate-800/80 rounded-lg px-4 py-2.5">
              <div className="flex items-center gap-4">
                <span>Showing <strong>{filteredDocuments.length}</strong> of {documents.length} objects</span>
                <span className="hidden sm:inline text-slate-600">•</span>
                <span className="hidden sm:inline">Active Zero-Trust Policy: <strong>Continuous Dynamic Authentication</strong></span>
              </div>
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse"></span>
                <span className="text-emerald-400 font-mono">Hardware Security Module Online</span>
              </div>
            </div>

            {/* Documents Grid / Table */}
            {filteredDocuments.length === 0 ? (
              <div className="text-center py-16 bg-[#0a0f1d] border border-dashed border-slate-800 rounded-xl">
                <FileText className="w-12 h-12 text-slate-600 mx-auto mb-3" />
                <h3 className="text-base font-semibold text-slate-300">No documents match the criteria</h3>
                <p className="text-xs text-slate-500 mt-1">Try adjusting your search terms or classification filters.</p>
              </div>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {filteredDocuments.map((doc) => {
                  const isRevoked = doc.status === 'revoked';
                  return (
                    <div
                      key={doc.id}
                      className={`relative bg-[#0d1424] border rounded-xl p-5 transition flex flex-col justify-between ${
                        isRevoked
                          ? 'border-rose-900/60 bg-rose-950/10'
                          : 'border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      {/* Revoked watermarking badge */}
                      {isRevoked && (
                        <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-1 rounded bg-rose-950/80 text-rose-300 border border-rose-700/80 text-[11px] font-bold tracking-wider uppercase animate-pulse">
                          <Ban className="w-3.5 h-3.5" />
                          <span>REVOKED</span>
                        </div>
                      )}

                      {!isRevoked && (
                        <div className="absolute top-3 right-3 flex items-center gap-1.5 px-2.5 py-1 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-700/80 text-[11px] font-bold tracking-wider uppercase">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          <span>ACTIVE</span>
                        </div>
                      )}

                      <div>
                        {/* Title and Classification */}
                        <div className="pr-24">
                          <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-semibold tracking-wider uppercase border mb-2 ${getClassificationBadge(doc.classification)}`}>
                            {doc.classification}
                          </span>
                          <h3 className="font-semibold text-base text-white tracking-tight flex items-center gap-2">
                            {doc.title}
                          </h3>
                          <p className="text-xs text-slate-400 font-mono mt-0.5 truncate">
                            {doc.filename} • {(doc.fileSize / 1024 / 1024).toFixed(2)} MB
                          </p>
                        </div>

                        {/* Revocation Warning Box if revoked */}
                        {isRevoked && (
                          <div className="mt-3 p-2.5 rounded bg-rose-950/40 border border-rose-900/60 text-xs text-rose-300 flex items-start gap-2">
                            <AlertTriangle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
                            <div>
                              <p className="font-semibold">INSTANT ACCESS REVOCATION ENFORCED</p>
                              <p className="text-[11px] text-rose-300/80 mt-0.5">
                                Revoked by {doc.revokedBy} on {new Date(doc.revokedAt || '').toLocaleString()}
                              </p>
                              {doc.revocationReason && (
                                <p className="text-[11px] text-rose-200 mt-1 italic">
                                  "{doc.revocationReason}"
                                </p>
                              )}
                            </div>
                          </div>
                        )}

                        {/* Metadata Details */}
                        <div className="mt-4 pt-3 border-t border-slate-800/80 space-y-2 text-xs">
                          <div className="flex items-center justify-between text-slate-400">
                            <span>SHA-256 Fingerprint:</span>
                            <span className="font-mono text-cyan-400 text-[11px] bg-slate-900/90 px-2 py-0.5 rounded border border-slate-800 flex items-center gap-1.5">
                              <Hash className="w-3 h-3 text-cyan-500" />
                              {doc.sha256Hash.slice(0, 16)}...
                            </span>
                          </div>

                          <div className="flex items-center justify-between text-slate-400">
                            <span>Envelope Encryption:</span>
                            <span className="text-slate-300 text-[11px]">{doc.encryptionAlgorithm}</span>
                          </div>

                          <div className="flex items-center justify-between text-slate-400">
                            <span>Ingested By:</span>
                            <span className="text-slate-300 text-[11px] font-mono">{doc.uploaderEmail}</span>
                          </div>
                        </div>
                      </div>

                      {/* Card Action Controls */}
                      <div className="mt-5 pt-3 border-t border-slate-800 flex flex-wrap items-center justify-between gap-2">
                        <div className="flex items-center gap-2">
                          {/* Secure Decrypted View */}
                          <button
                            onClick={() => setViewingDoc(doc)}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-medium transition"
                          >
                            <Eye className="w-3.5 h-3.5 text-cyan-400" />
                            <span>Zero-Trust View</span>
                          </button>

                          {/* Request Access Button (if user clearance lower than Top Secret or if revoked) */}
                          <button
                            onClick={() => {
                              setSelectedDocForRequest(doc);
                              setIsRequestOpen(true);
                            }}
                            className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-900 hover:bg-slate-800 text-slate-300 border border-slate-800 rounded-lg text-xs font-medium transition"
                          >
                            <Key className="w-3.5 h-3.5 text-amber-400" />
                            <span>Request Access</span>
                          </button>
                        </div>

                        {/* Killswitch Revoke / Reinstate buttons */}
                        <div className="flex items-center gap-2">
                          {!isRevoked ? (
                            <button
                              onClick={() => {
                                setSelectedDocForRevoke(doc);
                                setIsRevokeOpen(true);
                              }}
                              className="flex items-center gap-1.5 px-3 py-1.5 bg-rose-950/80 hover:bg-rose-900 text-rose-300 border border-rose-700/80 rounded-lg text-xs font-bold transition shadow-sm hover:shadow-rose-950/40"
                            >
                              <Ban className="w-3.5 h-3.5 text-rose-400" />
                              <span>Instant Revoke</span>
                            </button>
                          ) : (
                            (currentUser.role === 'admin' || currentUser.role === 'security_officer') && (
                              <button
                                onClick={() => handleReactivate(doc.id, doc.title)}
                                className="flex items-center gap-1.5 px-3 py-1.5 bg-emerald-950 hover:bg-emerald-900 text-emerald-300 border border-emerald-700 rounded-lg text-xs font-medium transition"
                              >
                                <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
                                <span>Reinstate Access</span>
                              </button>
                            )
                          )}
                        </div>
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        )}

        {/* ======================================================== */}
        {/* TAB 2: TAMPER-EVIDENT CRYPTOGRAPHIC AUDIT LEDGER          */}
        {/* ======================================================== */}
        {activeTab === 'audit' && (
          <div className="space-y-6">
            {/* Header with Verification Control Panel */}
            <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 flex flex-col md:flex-row gap-4 items-start md:items-center justify-between">
              <div>
                <div className="flex items-center gap-2">
                  <Layers className="w-5 h-5 text-cyan-400" />
                  <h2 className="text-lg font-bold text-white tracking-tight">
                    Cryptographic Tamper-Evident Ledger
                  </h2>
                </div>
                <p className="text-xs text-slate-400 mt-1">
                  Every state transition is appended to an immutable SHA-256 hash chain with linked parent pointers.
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex flex-wrap items-center gap-2.5">
                <button
                  onClick={handleVerifyChain}
                  disabled={verifying}
                  className="flex items-center gap-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-medium px-4 py-2 rounded-lg text-xs sm:text-sm shadow-md transition disabled:opacity-50"
                >
                  <ShieldCheck className={`w-4 h-4 ${verifying ? 'animate-spin' : ''}`} />
                  <span>{verifying ? 'Recalculating Hashes...' : 'Verify Ledger Cryptography'}</span>
                </button>

                <button
                  onClick={handleSimulateTamper}
                  title="Simulate an adversary modifying a block in the database"
                  className="flex items-center gap-1.5 bg-amber-950/80 hover:bg-amber-900 text-amber-200 border border-amber-700/80 px-3 py-2 rounded-lg text-xs font-medium transition"
                >
                  <AlertTriangle className="w-4 h-4 text-amber-400" />
                  <span>Simulate Tamper Attack</span>
                </button>

                <button
                  onClick={handleRepairChain}
                  title="Re-anchor hashes across the ledger"
                  className="flex items-center gap-1.5 bg-slate-800 hover:bg-slate-700 text-slate-300 px-3 py-2 rounded-lg text-xs font-medium transition"
                >
                  <RefreshCw className="w-4 h-4 text-slate-400" />
                  <span>Repair Chain</span>
                </button>
              </div>
            </div>

            {/* Verification Result Notification Card if run */}
            {verificationResult && (
              <div
                className={`p-4 rounded-xl border flex items-start gap-3 ${
                  verificationResult.valid
                    ? 'bg-emerald-950/40 border-emerald-600 text-emerald-200'
                    : 'bg-rose-950/60 border-rose-600 text-rose-200'
                }`}
              >
                {verificationResult.valid ? (
                  <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0 mt-0.5" />
                ) : (
                  <AlertTriangle className="w-6 h-6 text-rose-400 shrink-0 mt-0.5 animate-bounce" />
                )}
                <div>
                  <h4 className="font-bold text-sm">
                    {verificationResult.valid
                      ? 'Cryptographic Proof: 100% Hash Continuity Verified'
                      : 'INTEGRITY ALERT: Chain Integrity Violated'}
                  </h4>
                  <p className="text-xs mt-1 text-slate-300">
                    {verificationResult.valid
                      ? `All ${verificationResult.verifiedCount} sequential blocks verified. Every SHA-256 block hash exactly matches recalculated payload and predecessor link.`
                      : verificationResult.reason}
                  </p>
                </div>
              </div>
            )}

            {/* Visual Blockchain Graph & Block Cards */}
            <div className="space-y-3">
              {auditChain.map((block, index) => {
                const isGenesis = block.blockIndex === 0;
                const isTampered =
                  verificationResult &&
                  !verificationResult.valid &&
                  verificationResult.invalidBlockIndex === block.blockIndex;

                return (
                  <div key={block.blockIndex} className="relative group">
                    {/* Connecting line */}
                    {index < auditChain.length - 1 && (
                      <div className="absolute left-6 top-14 bottom-0 w-0.5 bg-slate-800 group-hover:bg-cyan-600 transition -z-0"></div>
                    )}

                    <div
                      className={`relative z-10 bg-[#0d1424] border rounded-xl p-4 sm:p-5 transition ${
                        isTampered
                          ? 'border-rose-500 bg-rose-950/20'
                          : 'border-slate-800 hover:border-slate-700'
                      }`}
                    >
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
                        <div className="flex items-center gap-2.5">
                          <span className="w-7 h-7 rounded-lg bg-cyan-950 border border-cyan-800 flex items-center justify-center font-mono font-bold text-xs text-cyan-300">
                            #{block.blockIndex}
                          </span>
                          <span
                            className={`px-2.5 py-0.5 rounded text-xs font-semibold tracking-wider uppercase border ${getActionBadge(
                              block.action
                            )}`}
                          >
                            {block.action}
                          </span>
                          {isGenesis && (
                            <span className="px-2 py-0.5 rounded text-[10px] font-bold tracking-widest bg-amber-950 text-amber-300 border border-amber-700">
                              GENESIS
                            </span>
                          )}
                        </div>

                        <div className="flex items-center gap-3 text-xs text-slate-400">
                          <Clock className="w-3.5 h-3.5 text-slate-500" />
                          <span>{new Date(block.timestamp).toLocaleString()}</span>
                        </div>
                      </div>

                      {/* Event Payload Description */}
                      <div className="my-3 text-sm text-slate-200">
                        <p>{block.details}</p>
                      </div>

                      {/* Cryptographic Link Details (PrevHash & BlockHash) */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-[11px] pt-3 border-t border-slate-800/60 font-mono">
                        <div className="bg-slate-900/90 rounded px-3 py-1.5 border border-slate-800 flex items-center justify-between">
                          <span className="text-slate-500">Prev Hash:</span>
                          <span className="text-slate-400 truncate ml-2" title={block.prevHash}>
                            {block.prevHash.slice(0, 16)}...{block.prevHash.slice(-8)}
                          </span>
                        </div>

                        <div className="bg-slate-900/90 rounded px-3 py-1.5 border border-slate-800 flex items-center justify-between">
                          <span className="text-slate-500">Block Hash:</span>
                          <span className="text-cyan-400 font-semibold truncate ml-2" title={block.blockHash}>
                            {block.blockHash.slice(0, 16)}...{block.blockHash.slice(-8)}
                          </span>
                        </div>
                      </div>

                      {/* Actor & Target Badge */}
                      <div className="flex items-center justify-between mt-3 text-xs text-slate-400">
                        <div>
                          <span>Actor: </span>
                          <span className="text-slate-200 font-mono font-medium">{block.actorEmail}</span>
                          <span className="ml-1 text-[11px] text-slate-500">({block.actorRole})</span>
                        </div>
                        <div>
                          <span>Resource: </span>
                          <span className="text-slate-300 font-mono">{block.targetResource}</span>
                        </div>
                      </div>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* TAB 3: ACCESS GOVERNANCE & APPROVALS                      */}
        {/* ======================================================== */}
        {activeTab === 'governance' && (
          <div className="space-y-6">
            <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5 flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
              <div>
                <h2 className="text-lg font-bold text-white tracking-tight flex items-center gap-2">
                  <Key className="w-5 h-5 text-cyan-400" />
                  <span>Time-Bound Zero-Trust Access Governance</span>
                </h2>
                <p className="text-xs text-slate-400 mt-1">
                  Just-in-time, temporary access grants with automatic expiration and instantaneous administrative revocation.
                </p>
              </div>
              <div className="text-xs text-slate-400 bg-slate-900 px-3 py-1.5 rounded-lg border border-slate-800">
                Pending Decisions: <strong>{accessRequests.filter((r) => r.status === 'pending').length}</strong>
              </div>
            </div>

            {/* Access Requests Table */}
            <div className="bg-[#0d1424] border border-slate-800 rounded-xl overflow-hidden">
              <div className="overflow-x-auto">
                <table className="w-full text-left text-xs sm:text-sm">
                  <thead className="bg-slate-900/80 text-slate-400 text-xs uppercase tracking-wider border-b border-slate-800 font-semibold">
                    <tr>
                      <th className="py-3 px-4">Document Title</th>
                      <th className="py-3 px-4">Requester</th>
                      <th className="py-3 px-4">Business Justification</th>
                      <th className="py-3 px-4">Duration</th>
                      <th className="py-3 px-4">Status</th>
                      <th className="py-3 px-4 text-right">Policy Action</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800/60">
                    {accessRequests.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-8 text-center text-slate-500 text-sm">
                          No access requests recorded.
                        </td>
                      </tr>
                    ) : (
                      accessRequests.map((req) => (
                        <tr key={req.id} className="hover:bg-slate-800/30 transition">
                          <td className="py-3.5 px-4 font-medium text-white">
                            {req.documentTitle}
                            <div className="text-[11px] text-slate-500 font-mono mt-0.5">{req.documentId}</div>
                          </td>
                          <td className="py-3.5 px-4 font-mono text-xs text-slate-300">
                            {req.requesterEmail}
                          </td>
                          <td className="py-3.5 px-4 text-xs text-slate-300 max-w-xs truncate" title={req.justification}>
                            "{req.justification}"
                          </td>
                          <td className="py-3.5 px-4 font-mono text-xs text-slate-400">
                            {req.durationHours}h
                          </td>
                          <td className="py-3.5 px-4">
                            {req.status === 'pending' && (
                              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-amber-950 text-amber-300 border border-amber-800">
                                Pending Review
                              </span>
                            )}
                            {req.status === 'approved' && (
                              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-emerald-950 text-emerald-300 border border-emerald-800">
                                Approved
                              </span>
                            )}
                            {req.status === 'rejected' && (
                              <span className="px-2 py-0.5 rounded text-[11px] font-semibold bg-rose-950 text-rose-300 border border-rose-800">
                                Denied
                              </span>
                            )}
                          </td>
                          <td className="py-3.5 px-4 text-right">
                            {req.status === 'pending' && (currentUser.role === 'admin' || currentUser.role === 'security_officer') ? (
                              <div className="flex items-center justify-end gap-2">
                                <button
                                  onClick={() => handleDecideRequest(req.id, 'approved')}
                                  className="px-2.5 py-1 rounded bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold transition"
                                >
                                  Grant
                                </button>
                                <button
                                  onClick={() => handleDecideRequest(req.id, 'rejected')}
                                  className="px-2.5 py-1 rounded bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-700 text-xs font-semibold transition"
                                >
                                  Deny
                                </button>
                              </div>
                            ) : (
                              <span className="text-xs text-slate-500 italic">
                                {req.status === 'approved' ? `by ${req.approvedBy}` : 'Completed'}
                              </span>
                            )}
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </div>
          </div>
        )}

        {/* ======================================================== */}
        {/* TAB 4: SECURITY COMMAND CENTER                            */}
        {/* ======================================================== */}
        {activeTab === 'command' && (
          <div className="space-y-6">
            {/* KPI Cards Grid */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-medium uppercase tracking-wider">Vaulted Objects</span>
                  <FileText className="w-5 h-5 text-cyan-400" />
                </div>
                <div className="mt-2 text-2xl font-bold text-white">{stats?.totalDocuments ?? 0}</div>
                <div className="mt-1 text-xs text-emerald-400 flex items-center gap-1">
                  <span>{stats?.activeDocuments ?? 0} active envelopes</span>
                </div>
              </div>

              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-medium uppercase tracking-wider">Instant Revocations</span>
                  <Ban className="w-5 h-5 text-rose-400" />
                </div>
                <div className="mt-2 text-2xl font-bold text-rose-400">{stats?.revokedDocuments ?? 0}</div>
                <div className="mt-1 text-xs text-slate-400">100% token kill-switch SLA</div>
              </div>

              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-medium uppercase tracking-wider">Ledger Blocks</span>
                  <Layers className="w-5 h-5 text-blue-400" />
                </div>
                <div className="mt-2 text-2xl font-bold text-white">{stats?.totalAuditBlocks ?? 0}</div>
                <div className="mt-1 text-xs text-cyan-400 font-mono">SHA-256 Chained</div>
              </div>

              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-5">
                <div className="flex items-center justify-between text-slate-400">
                  <span className="text-xs font-medium uppercase tracking-wider">Integrity Proof</span>
                  <ShieldCheck className="w-5 h-5 text-emerald-400" />
                </div>
                <div className="mt-2 text-2xl font-bold text-emerald-400">
                  {stats?.chainIntegrityValid ? '100% Valid' : 'Compromised'}
                </div>
                <div className="mt-1 text-xs text-slate-400">Mathematically proven</div>
              </div>
            </div>

            {/* Architecture & Zero-Trust Principles Panel */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-6">
                <h3 className="text-base font-bold text-white flex items-center gap-2 mb-3">
                  <Shield className="w-5 h-5 text-cyan-400" />
                  <span>Zero-Trust Policy Core</span>
                </h3>
                <ul className="space-y-2.5 text-xs text-slate-300">
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Never Trust, Always Verify:</strong> Implicit trust is eliminated regardless of network perimeter or user credentials.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Instantaneous Revocation:</strong> Immediate termination of bearer credentials and encryption session keys.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Tamper-Evident Chaining:</strong> Audit blocks form a sequential SHA-256 blockchain preventing retroactive log forgery.</span>
                  </li>
                  <li className="flex items-start gap-2">
                    <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                    <span><strong>Dual-Control Governance:</strong> High-classification documents require dual-clearance time-bound grants.</span>
                  </li>
                </ul>
              </div>

              <div className="bg-[#0d1424] border border-slate-800 rounded-xl p-6 flex flex-col justify-between">
                <div>
                  <h3 className="text-base font-bold text-white flex items-center gap-2 mb-3">
                    <Database className="w-5 h-5 text-blue-400" />
                    <span>System Administration &amp; Demo Tools</span>
                  </h3>
                  <p className="text-xs text-slate-400 mb-4">
                    Reset demo states, inspect active sessions, or test platform resiliency across cloud environments.
                  </p>
                </div>
                <div className="flex flex-wrap gap-3">
                  <button
                    onClick={handleResetDemo}
                    className="flex items-center gap-2 px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 rounded-lg text-xs font-semibold transition"
                  >
                    <RefreshCw className="w-4 h-4 text-cyan-400" />
                    <span>Reset Seed Data</span>
                  </button>
                  <button
                    onClick={handleToggleLockdown}
                    className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-bold transition ${
                      stats?.emergencyLockdown
                        ? 'bg-red-600 hover:bg-red-500 text-white'
                        : 'bg-rose-950 hover:bg-rose-900 text-rose-300 border border-rose-700'
                    }`}
                  >
                    <Flame className="w-4 h-4" />
                    <span>{stats?.emergencyLockdown ? 'Deactivate Lockdown' : 'Trigger Global Lockdown'}</span>
                  </button>
                </div>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* ======================================================== */}
      {/* MODAL 1: ZERO-TRUST SECURE VIEWPORT (VIEW ENVELOPE)      */}
      {/* ======================================================== */}
      {viewingDoc && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1424] border border-slate-700 rounded-2xl max-w-2xl w-full p-6 shadow-2xl relative overflow-hidden">
            {/* Dynamic Confidentiality Watermark Simulation */}
            <div className="absolute inset-0 pointer-events-none watermark-pattern opacity-40"></div>

            <div className="relative z-10">
              <div className="flex items-start justify-between border-b border-slate-800 pb-4">
                <div>
                  <span className={`inline-block px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider border mb-1.5 ${getClassificationBadge(viewingDoc.classification)}`}>
                    {viewingDoc.classification} CLEARANCE
                  </span>
                  <h3 className="text-lg font-bold text-white">{viewingDoc.title}</h3>
                  <p className="text-xs text-slate-400 font-mono mt-0.5">
                    {viewingDoc.filename} • Enclave View Session #{(viewingDoc.accessCount || 0) + 1}
                  </p>
                </div>
                <button
                  onClick={() => setViewingDoc(null)}
                  className="text-slate-400 hover:text-white p-1 rounded-lg transition"
                >
                  <XCircle className="w-6 h-6" />
                </button>
              </div>

              {/* Security Warning if Revoked */}
              {viewingDoc.status === 'revoked' ? (
                <div className="my-6 p-4 rounded-xl bg-rose-950/80 border border-rose-700 text-rose-200 text-xs sm:text-sm">
                  <div className="flex items-center gap-2 font-bold mb-1 text-rose-300">
                    <Ban className="w-5 h-5" />
                    <span>ACCESS DENIED: DOCUMENT REVOKED</span>
                  </div>
                  <p>
                    This object’s bearer tokens and decryption keys have been terminated by policy enforcement. Reason: {viewingDoc.revocationReason || 'Administrative revocation'}.
                  </p>
                </div>
              ) : (
                <div className="my-6 space-y-4">
                  {/* Dynamic Watermark Banner */}
                  <div className="bg-slate-900/90 border border-slate-800 rounded-lg p-3 text-center text-[11px] font-mono text-cyan-400/90">
                    ACCESS WATERMARK: {currentUser.email} • IP: 10.240.11.89 • TS: {new Date().toISOString()} • VIEW ONLY
                  </div>

                  {/* Content Payload preview */}
                  <div className="bg-[#070b14] border border-slate-800 rounded-xl p-4 font-mono text-xs text-slate-300 leading-relaxed max-h-60 overflow-y-auto">
                    {viewingDoc.contentSnippet || 'Encrypted binary content protected under Zero-Trust Envelope.'}
                  </div>

                  {/* Cryptographic Footprint */}
                  <div className="bg-slate-900/60 rounded-lg p-3 text-xs space-y-1.5 border border-slate-800/80">
                    <div className="flex justify-between">
                      <span className="text-slate-400">Integrity Fingerprint:</span>
                      <span className="text-cyan-400 font-mono text-[11px] truncate max-w-[280px]">
                        {viewingDoc.sha256Hash}
                      </span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-400">Cipher Specification:</span>
                      <span className="text-slate-300">{viewingDoc.encryptionAlgorithm}</span>
                    </div>
                  </div>
                </div>
              )}

              <div className="flex items-center justify-end gap-3 pt-4 border-t border-slate-800">
                <button
                  onClick={() => setViewingDoc(null)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
                >
                  Close Secure Viewport
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL 2: INSTANT REVOCATION KILL-SWITCH CONFIRMATION     */}
      {/* ======================================================== */}
      {isRevokeOpen && selectedDocForRevoke && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1424] border border-rose-800/80 rounded-2xl max-w-lg w-full p-6 shadow-2xl animate-in fade-in zoom-in-95">
            <div className="flex items-center gap-3 text-rose-400 mb-4">
              <div className="w-10 h-10 rounded-xl bg-rose-950 border border-rose-700 flex items-center justify-center">
                <Ban className="w-6 h-6 text-rose-400" />
              </div>
              <div>
                <h3 className="text-base font-bold text-white">Execute Instant Revocation</h3>
                <p className="text-xs text-rose-300">Terminates all current and future access globally</p>
              </div>
            </div>

            <p className="text-xs text-slate-300 leading-relaxed">
              You are about to sever all token grants for:
              <br />
              <strong className="text-white text-sm mt-1 inline-block">
                {selectedDocForRevoke.title}
              </strong>
            </p>

            <div className="my-4">
              <label className="block text-xs font-semibold text-slate-400 mb-1.5">
                Revocation Justification (Immutable Audit Block Record):
              </label>
              <textarea
                rows={3}
                value={revokeReason}
                onChange={(e) => setRevokeReason(e.target.value)}
                className="w-full bg-[#070b14] border border-slate-800 rounded-lg p-2.5 text-xs text-slate-200 focus:outline-none focus:border-rose-500"
                placeholder="State the security rationale for revoking access..."
              />
            </div>

            <div className="flex items-center justify-end gap-3 pt-3 border-t border-slate-800">
              <button
                onClick={() => {
                  setIsRevokeOpen(false);
                  setSelectedDocForRevoke(null);
                }}
                className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition"
              >
                Cancel
              </button>
              <button
                onClick={handleInstantRevoke}
                className="px-4 py-2 bg-rose-600 hover:bg-rose-500 text-white text-xs font-bold rounded-lg shadow-lg shadow-rose-600/30 transition flex items-center gap-1.5"
              >
                <Ban className="w-4 h-4" />
                <span>Confirm Instant Revocation</span>
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL 3: INGEST & ENCRYPT NEW DOCUMENT                   */}
      {/* ======================================================== */}
      {isUploadOpen && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1424] border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2.5">
                <ShieldCheck className="w-5 h-5 text-cyan-400" />
                <h3 className="text-base font-bold text-white">Ingest &amp; Vault Encrypted Object</h3>
              </div>
              <button onClick={() => setIsUploadOpen(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <form onSubmit={handleUploadSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Document Title *
                </label>
                <input
                  type="text"
                  required
                  placeholder="e.g. Q4 Master Key Rotation Procedure"
                  value={uploadTitle}
                  onChange={(e) => setUploadTitle(e.target.value)}
                  className="w-full bg-[#070b14] border border-slate-800 rounded-lg px-3 py-2 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Security Classification *
                </label>
                <select
                  aria-label="Security Classification"
                  value={uploadClassification}
                  onChange={(e) => setUploadClassification(e.target.value as Classification)}
                  className="w-full bg-[#070b14] border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-cyan-500"
                >
                  <option value="Top Secret">Top Secret (Highest Restricted Enclave)</option>
                  <option value="Restricted">Restricted (Controlled Personnel Only)</option>
                  <option value="Confidential">Confidential (Company Sensitive)</option>
                  <option value="Internal">Internal (General Internal Use)</option>
                </select>
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Encrypted Payload / Confidential Text
                </label>
                <textarea
                  rows={3}
                  placeholder="Enter confidential text or instructions..."
                  value={uploadContent}
                  onChange={(e) => setUploadContent(e.target.value)}
                  className="w-full bg-[#070b14] border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Or Attach Binary File
                </label>
                <input
                  type="file"
                  onChange={(e) => setUploadFile(e.target.files ? e.target.files[0] : null)}
                  className="w-full text-xs text-slate-400 file:mr-4 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:text-xs file:font-semibold file:bg-slate-800 file:text-cyan-400 hover:file:bg-slate-700 cursor-pointer"
                />
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsUploadOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white text-xs font-bold rounded-lg shadow-md transition"
                >
                  Compute Hash &amp; Encrypt
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ======================================================== */}
      {/* MODAL 4: REQUEST ZERO-TRUST ACCESS                       */}
      {/* ======================================================== */}
      {isRequestOpen && selectedDocForRequest && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-sm flex items-center justify-center p-4">
          <div className="bg-[#0d1424] border border-slate-700 rounded-2xl max-w-lg w-full p-6 shadow-2xl">
            <div className="flex items-center justify-between border-b border-slate-800 pb-3 mb-4">
              <div className="flex items-center gap-2">
                <Key className="w-5 h-5 text-amber-400" />
                <h3 className="text-base font-bold text-white">Request Time-Bound Access</h3>
              </div>
              <button onClick={() => setIsRequestOpen(false)} className="text-slate-400 hover:text-white">
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            <p className="text-xs text-slate-300 mb-3">
              Requesting access grant for: <strong className="text-white">{selectedDocForRequest.title}</strong>
            </p>

            <form onSubmit={handleRequestSubmit} className="space-y-4">
              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Business Justification *
                </label>
                <textarea
                  required
                  rows={3}
                  placeholder="Specify why you require access to this high-security asset..."
                  value={requestJustification}
                  onChange={(e) => setRequestJustification(e.target.value)}
                  className="w-full bg-[#070b14] border border-slate-800 rounded-lg p-2.5 text-xs text-white placeholder-slate-500 focus:outline-none focus:border-amber-500"
                />
              </div>

              <div>
                <label className="block text-xs font-semibold text-slate-300 mb-1">
                  Required Duration (Hours)
                </label>
                <select
                  aria-label="Required Duration in Hours"
                  value={requestHours}
                  onChange={(e) => setRequestHours(Number(e.target.value))}
                  className="w-full bg-[#070b14] border border-slate-800 rounded-lg px-3 py-2 text-xs text-white focus:outline-none focus:border-amber-500"
                >
                  <option value={1}>1 Hour (Emergency Incident)</option>
                  <option value={8}>8 Hours (Standard Shift)</option>
                  <option value={24}>24 Hours (Daily Review)</option>
                  <option value={72}>72 Hours (Audit Lifecycle)</option>
                </select>
              </div>

              <div className="pt-3 border-t border-slate-800 flex items-center justify-end gap-3">
                <button
                  type="button"
                  onClick={() => setIsRequestOpen(false)}
                  className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-300 text-xs font-semibold rounded-lg transition"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 bg-amber-600 hover:bg-amber-500 text-white text-xs font-bold rounded-lg transition"
                >
                  Submit Request
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Footer */}
      <footer className="border-t border-slate-800/60 bg-[#0a0f1d] py-4 text-xs text-slate-500">
        <div className="max-w-7xl mx-auto px-4 flex flex-col sm:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-emerald-400"></span>
            <span>TrustVault Zero-Trust Architecture</span>
            <span>•</span>
            <span>SHA-256 Tamper-Evident Chaining</span>
          </div>
          <div className="font-mono text-[11px] text-slate-400">
            Active Session: {currentUser.name} ({currentUser.email})
          </div>
        </div>
      </footer>
    </div>
  );
}
