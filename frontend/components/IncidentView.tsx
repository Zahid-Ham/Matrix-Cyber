import React, { useMemo } from 'react';
import {
    Map, Route, Link2, Database, ShieldAlert,
    Clock, Activity, ArrowRight, Crosshair
} from 'lucide-react';
import { Scan, Vulnerability } from '@/lib/matrix_api';
import Link from 'next/link';
import { ExecutiveInsightModal } from './ExecutiveInsightModal';
import { Cpu } from 'lucide-react';

interface IncidentViewProps {
    scan: Scan;
    findings: Vulnerability[];
}

const severityOrder = ['critical', 'high', 'medium', 'low'];

export function IncidentView({ scan, findings }: IncidentViewProps) {
    const [explanationVulnId, setExplanationVulnId] = React.useState<number | null>(null);
    const [showScanExplanation, setShowScanExplanation] = React.useState(false);

    const activeFindings = useMemo(
        () => findings.filter(f => !f.is_suppressed),
        [findings]
    );

    const attackSurface = useMemo(() => {
        const surface = new Set<string>();
        activeFindings.forEach(f => {
            if (f.url) surface.add(f.url);
            if (f.file_path) surface.add(f.file_path);
        });
        if (scan.target_url) surface.add(scan.target_url);
        return Array.from(surface).slice(0, 6);
    }, [activeFindings, scan.target_url]);

    const chainedVulns = useMemo(() => {
        return [...activeFindings]
            .sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity))
            .slice(0, 5);
    }, [activeFindings]);

    const probableExposure = useMemo(() => {
        const exposure = new Set<string>();
        activeFindings.forEach(f => {
            const type = f.vulnerability_type?.toLowerCase() || '';
            if (type.includes('sql')) exposure.add('Customer records & PII');
            if (type.includes('xss')) exposure.add('Session tokens & browser state');
            if (type.includes('auth')) exposure.add('Credentials & access tokens');
            if (type.includes('ssrf')) exposure.add('Internal metadata & services');
            if (type.includes('csrf')) exposure.add('User actions & account settings');
            if (type.includes('api')) exposure.add('Partner integrations & API keys');
        });
        if (exposure.size === 0) {
            exposure.add('Application metadata & audit traces');
        }
        return Array.from(exposure).slice(0, 5);
    }, [activeFindings]);

    const timelineStages = [
        { label: 'Recon', detail: 'Target enumeration', tone: 'bg-warm-100', active: true },
        { label: 'Entry', detail: 'Initial foothold', tone: 'bg-accent-primary/10', active: activeFindings.length > 0 },
        { label: 'Pivot', detail: 'Chained exploit', tone: 'bg-accent-primary/10', active: activeFindings.length > 2 },
        { label: 'Impact', detail: 'Data exposure', tone: 'bg-red-500/10', active: activeFindings.some(f => f.severity === 'critical' || f.severity === 'high') },
        { label: 'Contain', detail: 'Mitigation steps', tone: 'bg-green-500/10', active: scan.status === 'completed' },
    ];

    const exploitationPath = [
        'Surface discovery → endpoint fingerprinting',
        'Entry point compromise via high-risk vector',
        'Privilege escalation through chained weakness',
        'Data access & potential exfiltration',
        'Containment & remediation actions',
    ];

    const totalMarketValue = useMemo(() => {
        return activeFindings.reduce((sum, f) => sum + (f.marketplace_value_avg || 0), 0);
    }, [activeFindings]);

    const executiveSummary = useMemo(() => {
        if (activeFindings.length === 0) return "No active vulnerabilities were detected on the target infrastructure. The security posture appears stable.";

        const highestVuln = activeFindings[0]?.vulnerability_type?.replace(/_/g, ' ') || 'security weaknesses';

        return `Our automated security mesh has intercepted ${activeFindings.length} active vulnerabilities. The most significant threat is ${highestVuln}. If left unaddressed, these vectors represent a combined dark web market value of $${totalMarketValue.toLocaleString()}. An adversary could potentially chain these weaknesses to access ${probableExposure.join(' and ')}.`;
    }, [activeFindings, totalMarketValue, probableExposure]);

    return (
        <div className="space-y-10 animate-fade-in">
            {/* Header & Executive Summary */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div className="lg:col-span-2 glass-card p-10 bg-gradient-to-br from-white/80 to-accent-primary/5 border-l-4 border-l-accent-primary shadow-xl relative overflow-hidden">
                    <div className="absolute top-0 right-0 p-8 opacity-5">
                        <Activity className="w-32 h-32 text-accent-primary" />
                    </div>

                    <div className="relative z-10">
                        <div className="flex items-center gap-3 mb-6">
                            <span className="px-3 py-1 bg-accent-primary/10 text-accent-primary text-[10px] font-bold uppercase tracking-[0.2em] rounded-full">
                                Audit Intelligence
                            </span>
                            <span className="text-text-muted text-[10px] uppercase tracking-widest font-medium">
                                Scan #{scan.id}
                            </span>
                        </div>

                        <h3 className="text-4xl font-serif-display font-medium text-text-primary mb-6 flex items-center justify-between">
                            Executive Insight
                            <button
                                onClick={() => setShowScanExplanation(true)}
                                className="flex items-center gap-2 px-4 py-2 bg-accent-primary text-white text-xs font-bold uppercase tracking-widest rounded-xl hover:bg-accent-primary/90 transition-all shadow-md active:scale-95"
                            >
                                <Cpu className="w-4 h-4" /> Comprehensive Summary
                            </button>
                        </h3>

                        <div className="p-6 rounded-2xl bg-white/40 border border-white/60 shadow-inner">
                            <p className="text-lg text-text-primary leading-relaxed font-serif italic">
                                "{executiveSummary}"
                            </p>
                        </div>

                        <div className="mt-8 flex items-center gap-6">
                            <div className="flex -space-x-2">
                                {[1, 2, 3].map(i => (
                                    <div key={i} className="w-8 h-8 rounded-full border-2 border-white bg-warm-100 flex items-center justify-center text-[10px] font-bold text-accent-primary">
                                        AG
                                    </div>
                                ))}
                            </div>
                            <span className="text-xs text-text-secondary font-medium italic">Analyzed by Matrix AI Core</span>
                        </div>
                    </div>
                </div>

                <div className="glass-card p-10 bg-gradient-to-br from-emerald-900/10 to-emerald-900/5 border-t-4 border-t-emerald-500 shadow-xl flex flex-col justify-between">
                    <div>
                        <div className="flex items-center gap-3 mb-8">
                            <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 flex items-center justify-center shadow-sm">
                                <Database className="w-6 h-6 text-emerald-500" />
                            </div>
                            <div>
                                <h4 className="text-xl font-serif-display font-medium text-text-primary">Financial Risk</h4>
                                <p className="text-xs text-text-muted uppercase tracking-widest font-bold">Projected Impact</p>
                            </div>
                        </div>

                        <div className="space-y-6">
                            <div>
                                <div className="text-5xl font-serif-display font-medium text-emerald-500 mb-2">
                                    ${totalMarketValue.toLocaleString()}
                                </div>
                                <div className="h-2 w-full bg-warm-100 rounded-full overflow-hidden">
                                    <div
                                        className="h-full bg-emerald-500 shadow-[0_0_10px_rgba(16,185,129,0.5)]"
                                        style={{ width: totalMarketValue > 0 ? '75%' : '0%' }}
                                    />
                                </div>
                            </div>

                            <p className="text-sm text-text-secondary leading-relaxed">
                                This reflects the aggregated asking price for these specific attack vectors on major dark web marketplaces.
                            </p>
                        </div>
                    </div>

                    <Link href={`/marketplace/all?scan_id=${scan.id}`} className="mt-8 flex items-center justify-center gap-2 py-3 bg-emerald-500 text-white rounded-xl font-bold text-sm hover:bg-emerald-600 transition-all shadow-lg shadow-emerald-500/20">
                        Analyze Market Trends <ArrowRight className="w-4 h-4" />
                    </Link>
                </div>
            </div>

            {/* Path & Connectivity Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Attack Surface Map */}
                <div className="glass-card p-8 lg:col-span-2 shadow-lg">
                    <div className="flex items-center justify-between mb-8">
                        <div className="flex items-center gap-4">
                            <div className="w-12 h-12 rounded-2xl bg-accent-primary/10 flex items-center justify-center">
                                <Map className="w-6 h-6 text-accent-primary" />
                            </div>
                            <div>
                                <h4 className="text-2xl font-serif-display font-medium text-text-primary">Infiltration Vectors</h4>
                                <p className="text-sm text-text-muted">High-probability entry points identified</p>
                            </div>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {attackSurface.map((surface, idx) => (
                            <div
                                key={surface}
                                className="group p-5 rounded-2xl border border-warm-200 bg-white/40 hover:bg-white hover:border-accent-primary/40 hover:shadow-md transition-all duration-300"
                            >
                                <div className="flex items-center justify-between mb-3">
                                    <div className="flex items-center gap-2">
                                        <div className="w-2 h-2 rounded-full bg-accent-primary group-hover:animate-ping" />
                                        <span className="text-[10px] uppercase tracking-[0.2em] font-bold text-text-muted">Node {idx + 1}</span>
                                    </div>
                                    <Crosshair className="w-4 h-4 text-accent-primary/30 group-hover:text-accent-primary transition-colors" />
                                </div>
                                <div className="text-sm font-mono text-text-primary break-all mb-1 font-bold">{surface}</div>
                                <div className="text-[10px] text-text-muted uppercase tracking-widest">Target Surface Engagement</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Exploitation Chain */}
                <div className="glass-card p-8 shadow-lg border-r-4 border-r-amber-500/20">
                    <div className="flex items-center gap-4 mb-8">
                        <div className="w-12 h-12 rounded-2xl bg-amber-500/10 flex items-center justify-center">
                            <Route className="w-6 h-6 text-amber-500" />
                        </div>
                        <div>
                            <h4 className="text-xl font-serif-display font-medium text-text-primary">Exploit Chain</h4>
                            <p className="text-sm text-text-muted">Projected adversary sequence</p>
                        </div>
                    </div>

                    <div className="relative pl-8 border-l-2 border-dashed border-warm-200 space-y-8">
                        {exploitationPath.map((step, idx) => (
                            <div key={step} className="relative">
                                <div className="absolute -left-[41px] top-0 w-4 h-4 rounded-full bg-white border-4 border-accent-primary shadow-sm z-10" />
                                <div>
                                    <div className="text-[10px] font-bold text-accent-primary uppercase tracking-[0.2em] mb-1">
                                        Step {idx + 1}
                                    </div>
                                    <div className="text-sm font-medium text-text-primary leading-tight hover:text-accent-primary transition-colors cursor-default">
                                        {step}
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Secondary Intel Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* High-Value Findings */}
                <div className="glass-card p-8 shadow-lg bg-matrix-pattern/5">
                    <div className="flex items-center gap-4 mb-8">
                        <div className="w-12 h-12 rounded-2xl bg-red-500/10 flex items-center justify-center">
                            <Link2 className="w-6 h-6 text-red-500" />
                        </div>
                        <div>
                            <h4 className="text-xl font-serif-display font-medium text-text-primary">Chained Values</h4>
                            <p className="text-sm text-text-muted">Vulnerabilities with market demand</p>
                        </div>
                    </div>

                    <div className="space-y-4">
                        {chainedVulns.length === 0 ? (
                            <div className="p-8 text-center border-2 border-dashed border-warm-200 rounded-2xl">
                                <p className="text-sm text-text-muted italic">No high-risk chains identified.</p>
                            </div>
                        ) : (
                            chainedVulns.map((vuln) => (
                                <Link key={vuln.id} href={`/marketplace/vulnerability/${vuln.id}`}>
                                    <div className="group p-5 rounded-2xl border border-warm-200 bg-white/60 hover:border-emerald-500/40 hover:bg-white hover:shadow-lg transition-all cursor-pointer relative overflow-hidden">
                                        {vuln.marketplace_value_avg && (
                                            <div className="absolute top-0 right-0 px-3 py-1 bg-emerald-500 text-white text-[9px] font-bold uppercase tracking-widest rounded-bl-xl shadow-sm">
                                                ${vuln.marketplace_value_avg.toLocaleString()}
                                            </div>
                                        )}
                                        <div className="flex items-center justify-between mb-2">
                                            <span className={`text-[9px] font-bold px-2 py-0.5 rounded uppercase tracking-widest border ${vuln.severity === 'critical' ? 'border-red-200 text-red-600 bg-red-50' :
                                                vuln.severity === 'high' ? 'border-orange-200 text-orange-600 bg-orange-50' :
                                                    'border-amber-200 text-amber-600 bg-amber-50'
                                                }`}>
                                                {vuln.severity}
                                            </span>
                                            <button
                                                onClick={(e) => {
                                                    e.preventDefault();
                                                    e.stopPropagation();
                                                    setExplanationVulnId(vuln.id);
                                                }}
                                                className="text-[9px] font-bold text-accent-primary hover:underline uppercase tracking-widest"
                                            >
                                                Explain This
                                            </button>
                                        </div>
                                        <div className="text-sm font-bold text-text-primary group-hover:text-emerald-600 transition-colors uppercase tracking-tight mb-1">
                                            {vuln.vulnerability_type.replace(/_/g, ' ')}
                                        </div>
                                        <div className="flex items-center justify-between">
                                            <div className="text-[10px] text-text-muted truncate max-w-[150px] font-mono">
                                                {vuln.url || vuln.file_path || "Root Endpoint"}
                                            </div>
                                            <div className="text-[10px] font-bold text-emerald-500 flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                                                Deep Dive <ArrowRight className="w-3 h-3" />
                                            </div>
                                        </div>
                                    </div>
                                </Link>
                            ))
                        )}
                    </div>
                </div>

                {/* Impact Radius */}
                <div className="glass-card p-8 shadow-lg">
                    <div className="flex items-center gap-4 mb-8">
                        <div className="w-12 h-12 rounded-2xl bg-amber-500/10 flex items-center justify-center">
                            <ShieldAlert className="w-6 h-6 text-amber-500" />
                        </div>
                        <div>
                            <h4 className="text-xl font-serif-display font-medium text-text-primary">Impact Radius</h4>
                            <p className="text-sm text-text-muted">Estimated asset compromise zone</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        {probableExposure.map((item) => (
                            <div key={item} className="p-4 rounded-xl bg-warm-100/50 border border-warm-200 flex items-start gap-4">
                                <div className="mt-1 w-2 h-2 rounded-full bg-amber-500 shadow-[0_0_8px_rgba(245,158,11,0.5)]" />
                                <div>
                                    <div className="text-sm font-bold text-text-primary">{item}</div>
                                    <div className="text-[10px] text-text-muted uppercase tracking-widest mt-1">Direct Exposure Risk</div>
                                </div>
                            </div>
                        ))}
                    </div>

                    <div className="mt-8 p-6 rounded-2xl bg-gradient-to-br from-red-500/5 to-transparent border border-red-500/10">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-[0.2em] text-red-600 mb-4">
                            <ShieldAlert className="w-4 h-4" /> Threat Criticality
                        </div>
                        <div className="flex items-center gap-4">
                            <div className="text-3xl font-serif-display font-medium text-text-primary">High</div>
                            <div className="flex-1 h-3 rounded-full bg-warm-100 overflow-hidden shadow-inner">
                                <div className="h-full bg-gradient-to-r from-orange-500 to-red-600 w-[85%]" />
                            </div>
                        </div>
                    </div>
                </div>

                {/* Timeline & Signal Strength */}
                <div className="glass-card p-8 shadow-lg">
                    <div className="flex items-center gap-4 mb-8">
                        <div className="w-12 h-12 rounded-2xl bg-accent-primary/10 flex items-center justify-center">
                            <Clock className="w-6 h-6 text-accent-primary" />
                        </div>
                        <div>
                            <h4 className="text-xl font-serif-display font-medium text-text-primary">Investigation Signal</h4>
                            <p className="text-sm text-text-muted">Audit reliability reconstruction</p>
                        </div>
                    </div>

                    <div className="space-y-6">
                        {timelineStages.map((stage, idx) => (
                            <div key={stage.label} className="flex items-center gap-4">
                                <div className={`relative w-4 h-4 rounded-full ${stage.active ? 'bg-accent-primary' : 'bg-warm-200'} z-10`}>
                                    {stage.active && <div className="absolute inset-0 rounded-full bg-accent-primary animate-ping opacity-20" />}
                                </div>
                                <div className="flex-1">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className={`text-sm font-bold ${stage.active ? 'text-text-primary' : 'text-text-muted'}`}>{stage.label}</span>
                                        <span className="text-[10px] font-mono text-text-muted">T+{idx * 15}m</span>
                                    </div>
                                    <div className={`h-1.5 w-full rounded-full ${stage.active ? 'bg-accent-primary/20' : 'bg-warm-100'} overflow-hidden`}>
                                        <div className={`h-full bg-accent-primary transition-all duration-1000`} style={{ width: stage.active ? '100%' : '0%' }} />
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>

                    <div className="mt-10 p-6 rounded-2xl bg-accent-primary/5 border border-accent-primary/20 text-center">
                        <div className="text-[10px] font-bold uppercase tracking-[0.3em] text-accent-primary mb-2">Confidence Matrix</div>
                        <div className="text-4xl font-serif-display font-medium text-text-primary">
                            {Math.min(100, 30 + activeFindings.length * 10)}%
                        </div>
                        <div className="text-[10px] text-text-muted uppercase tracking-widest mt-1">Sensor Correlation Strength</div>
                    </div>
                </div>
            </div>

            <ExecutiveInsightModal
                isOpen={explanationVulnId !== null}
                onClose={() => setExplanationVulnId(null)}
                vulnerabilityId={explanationVulnId || undefined}
            />

            <ExecutiveInsightModal
                isOpen={showScanExplanation}
                onClose={() => setShowScanExplanation(false)}
                scanId={scan.id}
                title="Consolidated Strategic Brief"
            />
        </div>
    );
}
