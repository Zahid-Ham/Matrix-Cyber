'use client';

import React, { useMemo } from 'react';
import {
    Map, Route, Link2, Database, ShieldAlert,
    Clock, Activity, ArrowRight, Crosshair
} from 'lucide-react';
import { Scan, Vulnerability } from '@/lib/matrix_api';

interface IncidentViewProps {
    scan: Scan;
    findings: Vulnerability[];
}

const severityOrder = ['critical', 'high', 'medium', 'low'];

export function IncidentView({ scan, findings }: IncidentViewProps) {
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

    return (
        <div className="space-y-10 animate-fade-in">
            {/* Header */}
            <div className="glass-card p-8">
                <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-6">
                    <div>
                        <div className="text-xs uppercase tracking-[0.3em] text-text-muted font-bold mb-2">Incident Reconstruction</div>
                        <h3 className="text-3xl font-serif-display font-medium text-text-primary">Investigation Flow</h3>
                        <p className="text-text-secondary mt-2 max-w-2xl">
                            A synthesized storyline of the attack path derived from scan telemetry, chained vulnerabilities, and impact indicators.
                        </p>
                    </div>
                    <div className="flex items-center gap-3">
                        <div className="px-4 py-2 rounded-xl bg-accent-primary/10 text-accent-primary text-xs font-bold uppercase tracking-widest">
                            Incident View
                        </div>
                        <div className="px-4 py-2 rounded-xl bg-warm-100 text-text-secondary text-xs font-bold uppercase tracking-widest">
                            Scan #{scan.id}
                        </div>
                    </div>
                </div>
            </div>

            {/* Primary Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Attack Surface Map */}
                <div className="glass-card p-6 lg:col-span-2">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center">
                            <Map className="w-5 h-5 text-accent-primary" />
                        </div>
                        <div>
                            <h4 className="text-lg font-serif-display font-medium text-text-primary">Attack Surface Map</h4>
                            <p className="text-sm text-text-muted">Primary access points and observed vectors</p>
                        </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        {attackSurface.map((surface, idx) => (
                            <div
                                key={surface}
                                className="p-4 rounded-2xl border border-warm-200 bg-white/60 hover:border-accent-primary/30 transition-all"
                            >
                                <div className="flex items-center gap-2 mb-2">
                                    <Crosshair className="w-4 h-4 text-accent-primary" />
                                    <span className="text-xs uppercase tracking-[0.2em] font-bold text-text-muted">Vector {idx + 1}</span>
                                </div>
                                <div className="text-sm font-medium text-text-primary break-all">{surface}</div>
                                <div className="text-xs text-text-muted mt-1">Observed in telemetry</div>
                            </div>
                        ))}
                    </div>
                </div>

                {/* Exploitation Path */}
                <div className="glass-card p-6">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center">
                            <Route className="w-5 h-5 text-accent-primary" />
                        </div>
                        <div>
                            <h4 className="text-lg font-serif-display font-medium text-text-primary">Exploitation Path</h4>
                            <p className="text-sm text-text-muted">How the adversary moved</p>
                        </div>
                    </div>
                    <div className="space-y-4">
                        {exploitationPath.map((step, idx) => (
                            <div key={step} className="flex items-start gap-3">
                                <div className="mt-1 w-6 h-6 rounded-full bg-accent-primary/10 text-accent-primary text-xs font-bold flex items-center justify-center">
                                    {idx + 1}
                                </div>
                                <div>
                                    <div className="text-sm font-medium text-text-primary">{step}</div>
                                    <div className="text-xs text-text-muted">Stage {idx + 1}</div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            </div>

            {/* Secondary Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
                {/* Chained Vulnerabilities */}
                <div className="glass-card p-6">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="w-10 h-10 rounded-xl bg-red-500/10 flex items-center justify-center">
                            <Link2 className="w-5 h-5 text-red-600" />
                        </div>
                        <div>
                            <h4 className="text-lg font-serif-display font-medium text-text-primary">Chained Vulnerabilities</h4>
                            <p className="text-sm text-text-muted">Likely exploit sequence</p>
                        </div>
                    </div>

                    <div className="space-y-3">
                        {chainedVulns.length === 0 ? (
                            <div className="text-sm text-text-muted italic">No active vulnerabilities to chain.</div>
                        ) : (
                            chainedVulns.map((vuln) => (
                                <div key={vuln.id} className="p-3 rounded-xl border border-warm-200 bg-white/60">
                                    <div className="flex items-center justify-between mb-1">
                                        <span className="text-[10px] uppercase tracking-[0.2em] text-text-muted font-bold">{vuln.severity}</span>
                                        <ArrowRight className="w-4 h-4 text-text-muted" />
                                    </div>
                                    <div className="text-sm font-medium text-text-primary">
                                        {vuln.vulnerability_type.replace(/_/g, ' ')}
                                    </div>
                                    <div className="text-xs text-text-muted truncate">
                                        {vuln.url || vuln.file_path || scan.target_url}
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>

                {/* Probable Data Exposure */}
                <div className="glass-card p-6">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="w-10 h-10 rounded-xl bg-amber-500/10 flex items-center justify-center">
                            <Database className="w-5 h-5 text-amber-600" />
                        </div>
                        <div>
                            <h4 className="text-lg font-serif-display font-medium text-text-primary">Probable Data Exposure</h4>
                            <p className="text-sm text-text-muted">Impact radius estimation</p>
                        </div>
                    </div>

                    <ul className="space-y-3">
                        {probableExposure.map((item) => (
                            <li key={item} className="flex items-start gap-3">
                                <ShieldAlert className="w-4 h-4 text-amber-600 mt-0.5" />
                                <div>
                                    <div className="text-sm font-medium text-text-primary">{item}</div>
                                    <div className="text-xs text-text-muted">Derived from vulnerability class</div>
                                </div>
                            </li>
                        ))}
                    </ul>
                </div>

                {/* Attack Timeline Graph */}
                <div className="glass-card p-6">
                    <div className="flex items-center gap-3 mb-6">
                        <div className="w-10 h-10 rounded-xl bg-accent-primary/10 flex items-center justify-center">
                            <Clock className="w-5 h-5 text-accent-primary" />
                        </div>
                        <div>
                            <h4 className="text-lg font-serif-display font-medium text-text-primary">Attack Timeline</h4>
                            <p className="text-sm text-text-muted">Timeline reconstruction</p>
                        </div>
                    </div>

                    <div className="space-y-4">
                        {timelineStages.map((stage, idx) => (
                            <div key={stage.label} className="flex items-center gap-3">
                                <div className={`w-3 h-3 rounded-full ${stage.active ? 'bg-accent-primary' : 'bg-warm-200'}`} />
                                <div className="flex-1">
                                    <div className="flex items-center justify-between">
                                        <span className="text-sm font-medium text-text-primary">{stage.label}</span>
                                        <span className="text-[10px] uppercase tracking-[0.2em] text-text-muted">T{idx + 1}</span>
                                    </div>
                                    <div className="text-xs text-text-muted">{stage.detail}</div>
                                </div>
                                <div className={`w-16 h-2 rounded-full ${stage.active ? 'bg-accent-primary/60' : 'bg-warm-100'}`} />
                            </div>
                        ))}
                    </div>

                    <div className="mt-6 p-4 rounded-xl bg-accent-primary/5 border border-accent-primary/10">
                        <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-widest text-accent-primary mb-2">
                            <Activity className="w-4 h-4" /> Incident Signal Strength
                        </div>
                        <div className="flex items-center gap-3">
                            <div className="flex-1 h-2 rounded-full bg-warm-100 overflow-hidden">
                                <div
                                    className="h-full bg-gradient-to-r from-accent-primary via-amber-500 to-red-500"
                                    style={{ width: `${Math.min(100, 30 + activeFindings.length * 10)}%` }}
                                />
                            </div>
                            <span className="text-sm font-bold text-text-primary">
                                {Math.min(100, 30 + activeFindings.length * 10)}%
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    );
}
