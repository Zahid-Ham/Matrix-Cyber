'use client';

import React from 'react';
import {
    CheckCircle, XCircle, AlertTriangle,
    Terminal, Cpu, FileCode, Globe, Clock,
    ExternalLink, Fingerprint, EyeOff, AlertCircle
} from 'lucide-react';
import { Scan, Vulnerability } from '@/lib/matrix_api';
import { ThreatIntelligencePanel } from './ThreatIntelligencePanel';
import { ExploitSimulator } from './ExploitSimulator';
import { XSSSimulator } from './XSSSimulator';
import { SeverityBadge } from './SeverityBadge';

interface RepoScanViewProps {
    scan: Scan;
    findings: Vulnerability[];
    activeTab: 'active' | 'suppressed' | 'incident';
}

export function RepoScanView({ scan, findings, activeTab }: RepoScanViewProps) {
    const [selectedSimVuln, setSelectedSimVuln] = React.useState<Vulnerability | null>(null);

    const counts = {
        critical: findings.filter(f => !f.is_suppressed && f.severity === 'critical').length,
        high: findings.filter(f => !f.is_suppressed && f.severity === 'high').length,
        medium: findings.filter(f => !f.is_suppressed && f.severity === 'medium').length,
        low: findings.filter(f => !f.is_suppressed && f.severity === 'low').length,
        suppressed: findings.filter(f => f.is_suppressed).length
    };

    const filteredFindings = findings.filter(f =>
        activeTab === 'active' ? !f.is_suppressed : f.is_suppressed
    );

    return (
        <div className="space-y-8 animate-fade-in">
            {/* Repo Summary Stats */}
            <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                <div className="glass-card p-6 border-l-4 border-l-red-500">
                    <div className="text-red-600 font-bold text-[10px] uppercase tracking-widest mb-1">Critical/High</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {(counts.critical + counts.high).toString().padStart(2, '0')}
                    </div>
                </div>
                <div className="glass-card p-6 border-l-4 border-l-amber-500">
                    <div className="text-amber-600 font-bold text-[10px] uppercase tracking-widest mb-1">Medium/Low</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {(counts.medium + counts.low).toString().padStart(2, '0')}
                    </div>
                </div>
                <div className="glass-card p-6 border-l-4 border-l-accent-primary">
                    <div className="text-accent-primary font-bold text-[10px] uppercase tracking-widest mb-1">Files Audited</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {(scan.scanned_files?.length || 0).toString().padStart(2, '0')}
                    </div>
                </div>
                <div className="glass-card p-6 border-l-4 border-l-gray-400">
                    <div className="text-gray-500 font-bold text-[10px] uppercase tracking-widest mb-1">Suppressed</div>
                    <div className="text-4xl font-serif-display font-medium text-text-primary">
                        {counts.suppressed.toString().padStart(2, '0')}
                    </div>
                </div>
            </div>

            {/* Findings List - Full Width */}
            <div className="space-y-6">
                <h3 className="text-2xl font-serif-display font-medium text-text-primary flex items-center gap-3 mb-4">
                    <FileCode className="w-6 h-6 text-accent-primary" />
                    Code Analysis Findings
                </h3>

                {filteredFindings.length === 0 ? (
                    <div className="glass-card p-20 text-center">
                        <CheckCircle className="w-16 h-16 text-green-500/30 mx-auto mb-4" />
                        <h4 className="text-xl font-medium text-text-primary">
                            {activeTab === 'active' ? 'No Vulnerabilities Detected' : 'No Suppressed Findings'}
                        </h4>
                        <p className="text-text-secondary mt-2 max-w-sm mx-auto italic">
                            {activeTab === 'active'
                                ? 'The AI SAST Auditor found no critical security flaws in the provided source files.'
                                : 'No findings were auto-suppressed by the integrity mesh.'}
                        </p>
                    </div>
                ) : (
                    filteredFindings.map((vuln) => (
                        <div key={vuln.id} className="glass-card overflow-hidden hover:border-accent-primary/20 transition-all duration-500 shadow-lg hover:shadow-2xl">
                            <div className="p-10">
                                <div className="flex items-center justify-between mb-8">
                                    <span className="text-xs font-mono font-extrabold text-accent-primary bg-accent-primary/10 px-4 py-2 rounded-lg shadow-sm">
                                        SAST-{String(scan.id).padStart(3, '0')}-{String(vuln.id).padStart(4, '0')}
                                    </span>
                                    <SeverityBadge severity={vuln.severity} size="lg" />
                                </div>

                                <div className="space-y-6">
                                    <div>
                                        <h4 className="text-3xl font-extrabold text-text-primary uppercase tracking-tight mb-3">
                                            {vuln.vulnerability_type.replace(/_/g, ' ')}
                                        </h4>
                                        <div className="flex items-center gap-2 mt-2">
                                            <div className="p-1.5 rounded-md bg-warm-100/50">
                                                <FileCode className="w-4 h-4 text-text-muted" />
                                            </div>
                                            <span className="text-sm font-mono text-text-secondary">{vuln.file_path || 'Repository Logic'}</span>
                                        </div>
                                    </div>

                                    {vuln.description.includes('- ') ? (
                                        <ul className="list-disc pl-5 space-y-2 text-sm text-text-secondary leading-relaxed max-w-3xl marker:text-accent-primary">
                                            {vuln.description.split('- ').filter(part => part.trim().length > 0).map((part, idx) => (
                                                <li key={idx} className="pl-1">
                                                    {part.trim()}
                                                </li>
                                            ))}
                                        </ul>
                                    ) : (
                                        <p className="text-sm text-text-secondary leading-loose max-w-3xl">{vuln.description}</p>
                                    )}

                                    {/* Live Threat Intelligence Panel Integration */}
                                    {!vuln.is_suppressed && (
                                        <div className="mt-6 pt-6 border-t border-warm-100">
                                            <ThreatIntelligencePanel
                                                vulnerability={vuln}
                                                onSimulateExploit={() => setSelectedSimVuln(vuln)}
                                            />
                                        </div>
                                    )}

                                    {/* Evidence Snippet */}
                                    <div className="bg-gray-900 rounded-xl p-4 overflow-hidden mt-6">
                                        <div className="flex items-center gap-2 text-[10px] text-gray-400 uppercase tracking-widest mb-2">
                                            <Terminal className="w-3 h-3" />
                                            Vulnerable Code Snippet
                                        </div>
                                        <pre className="text-xs font-mono text-gray-200 overflow-x-auto whitespace-pre-wrap">
                                            {vuln.evidence || '// No code snippet captured for this finding'}
                                        </pre>
                                    </div>

                                    {/* AI Analysis & Remediation */}
                                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-4 border-t border-warm-100">
                                        <div className="space-y-4">
                                            <div className="text-[10px] font-bold uppercase tracking-widest text-text-muted flex items-center gap-2">
                                                <Cpu className="w-3 h-3" /> AI Context
                                            </div>
                                            {(() => {
                                                let analysis: any = {};
                                                let extraNote = '';
                                                const raw = vuln.ai_analysis || '{}';

                                                try {
                                                    analysis = JSON.parse(raw);
                                                } catch (e) {
                                                    // Attempt extraction if JSON is mixed with text
                                                    const jsonMatch = raw.match(/(\{[\s\S]*\})/);
                                                    if (jsonMatch) {
                                                        try {
                                                            analysis = JSON.parse(jsonMatch[1]);
                                                            extraNote = raw.replace(jsonMatch[1], '').trim();
                                                        } catch (e2) {
                                                            // Fallback to raw display
                                                        }
                                                    }
                                                }

                                                if (Object.keys(analysis).length === 0 && !extraNote) {
                                                    // Only return raw if we couldn't parse ANYTHING
                                                    return (
                                                        <p className="text-xs text-text-secondary italic leading-relaxed">
                                                            {vuln.ai_analysis || 'Automated logic analysis identifies potential reachability to sinks.'}
                                                        </p>
                                                    );
                                                }

                                                return (
                                                    <div className="space-y-3">
                                                        <div>
                                                            <span className="text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-1">Analysis</span>
                                                            <p className="text-xs text-text-secondary leading-relaxed">
                                                                {analysis.description || analysis.summary || 'No detailed analysis available.'}
                                                            </p>
                                                        </div>
                                                        {analysis.root_cause && (
                                                            <div>
                                                                <span className="text-[10px] font-bold text-text-muted uppercase tracking-wider block mb-1">Root Cause</span>
                                                                <p className="text-xs text-text-secondary leading-relaxed italic">
                                                                    "{analysis.root_cause}"
                                                                </p>
                                                            </div>
                                                        )}
                                                        {analysis.compliance_mapping && (
                                                            <div className="flex flex-wrap gap-2 mt-2">
                                                                {Object.entries(analysis.compliance_mapping).map(([standard, id]) => (
                                                                    <span key={standard} className="px-2 py-0.5 bg-warm-100 text-warm-700 rounded text-[10px] font-bold uppercase tracking-wider border border-warm-200">
                                                                        {standard}: {String(id)}
                                                                    </span>
                                                                ))}
                                                            </div>
                                                        )}
                                                        {extraNote && (
                                                            <div className="pt-2 mt-2 border-t border-warm-200/50">
                                                                <span className="text-[10px] font-bold text-amber-600 uppercase tracking-wider block mb-1 flex items-center gap-1">
                                                                    <AlertTriangle className="w-3 h-3" />
                                                                    Security Gate
                                                                </span>
                                                                <p className="text-xs text-text-secondary leading-relaxed italic">
                                                                    {extraNote}
                                                                </p>
                                                            </div>
                                                        )}
                                                    </div>
                                                );
                                            })()}
                                        </div>
                                        {!vuln.is_suppressed && (
                                            <div className="space-y-2">
                                                <div className="text-[10px] font-bold uppercase tracking-widest text-green-600 flex items-center gap-2">
                                                    <Fingerprint className="w-3 h-3" /> Remediation
                                                </div>
                                                <p className="text-xs text-text-secondary leading-relaxed">
                                                    {(() => {
                                                        try {
                                                            const analysis = JSON.parse(vuln.ai_analysis || '{}');
                                                            return analysis.fix || vuln.remediation || 'Refer to secure coding standards for input sanitization.';
                                                        } catch (e) {
                                                            return vuln.remediation || 'Refer to secure coding standards for input sanitization.';
                                                        }
                                                    })()}
                                                </p>
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                        </div>
                    ))
                )}
            </div>

            {/* Simulator Overlay - Conditional based on vulnerability type */}
            {selectedSimVuln && (
                <>
                    {selectedSimVuln.vulnerability_type.toLowerCase().includes('xss') ? (
                        <XSSSimulator onClose={() => setSelectedSimVuln(null)} />
                    ) : (
                        <ExploitSimulator
                            vulnerability={selectedSimVuln}
                            onClose={() => setSelectedSimVuln(null)}
                        />
                    )}
                </>
            )}
        </div>
    );
}
