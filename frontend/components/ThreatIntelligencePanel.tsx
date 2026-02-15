'use client';

import React, { useState, useEffect } from 'react';
import {
    Zap, AlertTriangle, Flame, ShieldAlert,
    ArrowUpRight, Info, Activity, Globe,
    ChevronRight, PlayCircle
} from 'lucide-react';
import { Vulnerability, api } from '@/lib/matrix_api';

import { AttackFlowVisualizer } from './AttackFlowVisualizer';

interface ThreatIntelligencePanelProps {
    vulnerability: Vulnerability;
    onSimulateExploit: () => void;
}

export function ThreatIntelligencePanel({ vulnerability, onSimulateExploit }: ThreatIntelligencePanelProps) {
    const [intelligence, setIntelligence] = useState(vulnerability.threat_intelligence);
    const [loading, setLoading] = useState(!vulnerability.threat_intelligence);
    const [error, setError] = useState<string | null>(null);
    const [showAttackFlow, setShowAttackFlow] = useState(false);

    useEffect(() => {
        const fetchIntel = async () => {
            if (intelligence) return;
            setLoading(true);
            try {
                const data = await api.getVulnerabilityIntelligence(vulnerability.id);
                setIntelligence(data);
            } catch (err: any) {
                setError(err.message || "Failed to fetch threat intelligence");
            } finally {
                setLoading(false);
            }
        };

        fetchIntel();
    }, [vulnerability.id, intelligence]);

    if (loading) {
        return (
            <div className="glass-card p-8 animate-pulse">
                <div className="flex items-center gap-3 mb-6">
                    <Activity className="w-5 h-5 text-accent-primary animate-spin" />
                    <div className="h-6 w-48 bg-warm-200 rounded"></div>
                </div>
                <div className="space-y-4">
                    <div className="h-20 bg-warm-100 rounded-xl"></div>
                    <div className="grid grid-cols-2 gap-4">
                        <div className="h-16 bg-warm-50 rounded-lg"></div>
                        <div className="h-16 bg-warm-50 rounded-lg"></div>
                    </div>
                </div>
            </div>
        );
    }

    if (error || !intelligence) {
        return (
            <div className="glass-card p-6 border-l-4 border-l-red-400">
                <div className="flex items-center gap-2 text-red-600 mb-2">
                    <AlertTriangle className="w-4 h-4" />
                    <span className="text-xs font-bold uppercase tracking-widest">Intelligence Error</span>
                </div>
                <p className="text-sm text-text-secondary">{error || "Intelligence data unavailable"}</p>
            </div>
        );
    }

    const getTrendColor = (score: number) => {
        if (score > 80) return 'text-red-500';
        if (score > 60) return 'text-orange-500';
        if (score > 40) return 'text-amber-500';
        return 'text-green-500';
    };

    const getTrendBg = (score: number) => {
        if (score > 80) return 'bg-red-500/10';
        if (score > 60) return 'bg-orange-500/10';
        if (score > 40) return 'bg-amber-500/10';
        return 'bg-green-500/10';
    };

    return (
        <div className="space-y-6 animate-fade-in text-left">
            {/* Header / Trend Score Gauge Area */}
            <div className="glass-card overflow-hidden group border border-warm-200 shadow-xl bg-white/50">
                <div className="p-1 bg-gradient-to-r from-accent-primary/20 via-orange-500/20 to-red-500/20"></div>
                <div className="p-8">
                    <div className="flex flex-col md:flex-row justify-between items-center gap-6 mb-8">
                        <div>
                            <div className="flex items-center gap-2 mb-2">
                                <Zap className="w-4 h-4 text-accent-primary" />
                                <h3 className="text-xs font-bold uppercase tracking-[0.2em] text-text-muted">Live Threat Intelligence</h3>
                            </div>
                            <h4 className="text-3xl font-serif-display font-medium text-text-primary">
                                {vulnerability.vulnerability_type.replace(/_/g, ' ')} Analysis
                            </h4>
                        </div>

                        <div className="flex items-center gap-4 h-12">
                            {intelligence.actively_exploited && (
                                <div className="h-10 flex items-center gap-2 px-4 bg-red-500 text-white rounded-xl text-xs font-bold uppercase tracking-widest shadow-lg shadow-red-500/30 animate-pulse border border-red-400">
                                    <Flame className="w-3.5 h-3.5" />
                                    Actively Exploited
                                </div>
                            )}
                            <button
                                onClick={() => setShowAttackFlow(true)}
                                className="h-10 px-6 bg-white hover:bg-theme-bg shadow-sm hover:shadow text-text-primary font-bold rounded-xl border border-warm-200 transition-all duration-300 flex items-center gap-2 group"
                            >
                                <Activity className="w-4 h-4 text-accent-primary group-hover:scale-110 transition-transform" />
                                <span className="text-sm">View Attack Flow</span>
                            </button>
                            <button
                                onClick={onSimulateExploit}
                                className="h-10 px-6 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-bold rounded-xl shadow-lg hover:shadow-xl hover:-translate-y-0.5 transition-all duration-300 flex items-center gap-2 group border border-emerald-500/20"
                            >
                                <PlayCircle className="w-4 h-4 group-hover:scale-110 transition-transform" />
                                <span className="text-sm">Simulate Exploit</span>
                            </button>
                        </div>
                    </div>
                    {showAttackFlow && <AttackFlowVisualizer onClose={() => setShowAttackFlow(false)} vulnerabilityType={vulnerability.vulnerability_type} />}

                    <div className="space-y-6">
                        {/* Metrics Row */}
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                            {/* Trend Score */}
                            <div className="flex flex-col items-center justify-between p-6 rounded-2xl bg-white border border-warm-200 shadow-sm hover:shadow-md transition-all duration-300 h-full">
                                <div className="w-full flex justify-between items-center mb-4">
                                    <div className="text-xs font-bold uppercase tracking-wider text-text-muted">Trend Score</div>
                                    <div className={`p-1.5 rounded-full ${getTrendBg(intelligence.trend_score)}`}>
                                        <ArrowUpRight className={`w-4 h-4 ${getTrendColor(intelligence.trend_score)}`} />
                                    </div>
                                </div>

                                <div className="text-center w-full">
                                    <div className={`text-6xl font-serif-display font-black leading-none mb-2 ${getTrendColor(intelligence.trend_score)}`}>
                                        {intelligence.trend_score}
                                    </div>
                                    <div className="w-full h-1.5 bg-warm-100 rounded-full overflow-hidden">
                                        <div
                                            className={`h-full rounded-full transition-all duration-1000 ${getTrendColor(intelligence.trend_score).replace('text-', 'bg-')}`}
                                            style={{ width: `${intelligence.trend_score}%` }}
                                        ></div>
                                    </div>
                                </div>

                                <div className="mt-4 text-xs font-medium text-text-secondary w-full text-center bg-warm-50 py-2 rounded-lg">
                                    {intelligence.disclosure_count_30d} Disclosures (30d)
                                </div>
                            </div>

                            {/* Activity Level */}
                            <div className="flex flex-col justify-between p-6 rounded-2xl bg-white border border-warm-200 shadow-sm hover:shadow-md transition-all duration-300 h-full">
                                <div className="flex justify-between items-start mb-4">
                                    <div className="flex flex-col">
                                        <div className="text-xs font-bold uppercase tracking-wider text-text-muted mb-1">Activity Level</div>
                                        <div className={`text-3xl font-black ${getTrendColor(intelligence.trend_score)}`}>
                                            {intelligence.activity_level}
                                        </div>
                                    </div>
                                    <div className="p-2 rounded-lg bg-orange-50">
                                        <ShieldAlert className="w-5 h-5 text-orange-500" />
                                    </div>
                                </div>
                                <p className="text-xs text-text-secondary leading-relaxed border-t border-warm-100 pt-3 mt-auto">
                                    Global occurrence frequency based on sensor data.
                                </p>
                            </div>

                            {/* Avg. CVSS */}
                            <div className="flex flex-col justify-between p-6 rounded-2xl bg-white border border-warm-200 shadow-sm hover:shadow-md transition-all duration-300 h-full">
                                <div className="flex justify-between items-start mb-4">
                                    <div className="flex flex-col">
                                        <div className="text-xs font-bold uppercase tracking-wider text-text-muted mb-1">Avg. CVSS</div>
                                        <div className="text-3xl font-black text-text-primary">
                                            {intelligence.avg_cvss}
                                        </div>
                                    </div>
                                    <div className="p-2 rounded-lg bg-blue-50">
                                        <Globe className="w-5 h-5 text-blue-500" />
                                    </div>
                                </div>
                                <p className="text-xs text-text-secondary leading-relaxed border-t border-warm-100 pt-3 mt-auto">
                                    Market trend severity averaged across major vendors.
                                </p>
                            </div>
                        </div>

                        {/* AI Analysis Row */}
                        <div className="p-6 rounded-2xl bg-gradient-to-br from-warm-900 to-warm-800 text-white shadow-lg relative overflow-hidden group">
                            <div className="relative z-10 flex flex-col md:flex-row gap-6 items-start md:items-center">
                                <div className="p-3 rounded-xl bg-white/10 backdrop-blur-sm border border-white/10 shrink-0">
                                    <Zap className="w-6 h-6 text-emerald-300" />
                                </div>
                                <div>
                                    <div className="text-xs font-bold text-emerald-300 uppercase tracking-widest mb-2 flex items-center gap-2">
                                        AI Analysis Insight
                                    </div>
                                    <p className="text-sm font-medium leading-relaxed opacity-95 text-warm-50 italic max-w-3xl">
                                        "{intelligence.why_trending}"
                                    </p>
                                </div>
                            </div>
                            {/* Decorative Elements Removed */}
                        </div>
                    </div>
                </div>
            </div>

            {/* AI Insights - Horizontal Cards */}
            <div className="space-y-4">
                {/* Attack Summary Card - Special Layout */}
                <div className="glass-card p-0 border-l-4 border-l-accent-primary shadow-sm hover:shadow-md transition-all duration-300 overflow-hidden relative group">
                    {/* Background Pattern */}
                    <div className="absolute inset-0 opacity-[0.03] pointer-events-none bg-[radial-gradient(#2D5A4A_1px,transparent_1px)] [background-size:24px_24px]"></div>

                    <div className="grid grid-cols-1 md:grid-cols-3">
                        {/* Left: Description */}
                        <div className="md:col-span-1 p-8 bg-gradient-to-b from-warm-50/50 to-transparent relative border-b md:border-b-0 md:border-r border-warm-100/50">
                            <h5 className="text-xs font-black uppercase tracking-[0.2em] text-accent-primary mb-6 flex items-center gap-2">
                                <Activity className="w-5 h-5" />
                                Attack Path
                            </h5>
                            <p className="text-sm text-text-secondary leading-loose font-medium relative z-10">
                                {intelligence.attack_summary}
                            </p>
                            <div className="absolute bottom-0 right-0 w-24 h-24 bg-accent-primary/5 blur-2xl rounded-full -translate-y-1/2 translate-x-1/2"></div>
                        </div>

                        {/* Right: Steps */}
                        <div className="md:col-span-2 p-8 bg-white/40">
                            <div className="flex items-center justify-between mb-6">
                                <div className="text-[10px] font-black uppercase tracking-widest text-text-muted">Execution Flow</div>
                                <div className="h-px flex-grow mx-4 bg-warm-200/60"></div>
                            </div>

                            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                                {intelligence.real_world_exploit_flow.map((step, idx) => (
                                    <div key={idx} className="p-5 bg-white border-[3px] border-[#323232] rounded-[20px] shadow-[8px_8px_0px_0px_rgba(50,50,50,1)] hover:shadow-[12px_12px_0px_0px_rgba(50,50,50,1)] hover:-translate-y-1 transition-all duration-300">
                                        <div className="flex items-center mb-4">
                                            <div className="relative w-8 h-8 rounded-full bg-emerald-500 flex items-center justify-center shrink-0">
                                                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1792 1792" fill="currentColor" className="w-4 h-4 text-white">
                                                    <path d="M1362 1185q0 153-99.5 263.5t-258.5 136.5v175q0 14-9 23t-23 9h-135q-13 0-22.5-9.5t-9.5-22.5v-175q-66-9-127.5-31t-101.5-44.5-74-48-46.5-37.5-17.5-18q-17-21-2-41l103-135q7-10 23-12 15-2 24 9l2 2q113 99 243 125 37 8 74 8 81 0 142.5-43t61.5-122q0-28-15-53t-33.5-42-58.5-37.5-66-32-80-32.5q-39-16-61.5-25t-61.5-26.5-62.5-31-56.5-35.5-53.5-42.5-43.5-49-35.5-58-21-66.5-8.5-78q0-138 98-242t255-134v-180q0-13 9.5-22.5t22.5-9.5h135q14 0 23 9t9 23v176q57 6 110.5 23t87 33.5 63.5 37.5 39 29 15 14q17 18 5 38l-81 146q-8 15-23 16-14 3-27-7-3-3-14.5-12t-39-26.5-58.5-32-74.5-26-85.5-11.5q-95 0-155 43t-60 111q0 26 8.5 48t29.5 41.5 39.5 33 56 31 60.5 27 70 27.5q53 20 81 31.5t76 35 75.5 42.5 62 50 53 63.5 31.5 76.5 13 94z" />
                                                </svg>
                                            </div>
                                            <div className="ml-3 text-[#374151] font-bold text-lg">Step {idx + 1}</div>
                                            <div className="ml-auto flex items-center gap-1 text-emerald-600 font-bold text-sm">
                                                <svg width="16" height="16" fill="currentColor" viewBox="0 0 1792 1792" xmlns="http://www.w3.org/2000/svg">
                                                    <path d="M1408 1216q0 26-19 45t-45 19h-896q-26 0-45-19t-19-45 19-45l448-448q19-19 45-19t45 19l448 448q19 19 19 45z" />
                                                </svg>
                                                <span>Active</span>
                                            </div>
                                        </div>

                                        <div className="flex flex-col justify-between min-h-[8rem]">
                                            <p className="text-[#1F2937] text-lg font-bold leading-tight">
                                                {step}
                                            </p>

                                            <div className="relative bg-gray-200 w-full h-2 rounded overflow-hidden mt-4">
                                                <div
                                                    className="absolute top-0 left-0 bg-emerald-500 h-full rounded"
                                                    style={{ width: `${((idx + 1) / intelligence.real_world_exploit_flow.length) * 100}%` }}
                                                ></div>
                                            </div>
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>
                    </div>
                </div>

                {/* Impact Cards - Grid Layout */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="glass-card p-6 border-l-4 border-l-orange-500 shadow-sm hover:shadow-md transition-all duration-300 flex flex-col">
                        <h5 className="text-xs font-bold uppercase tracking-widest text-text-primary mb-3 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4 text-orange-500" />
                            Technical Impact
                        </h5>
                        <p className="text-sm text-text-secondary leading-relaxed flex-grow">
                            {intelligence.technical_impact}
                        </p>
                    </div>

                    <div className="glass-card p-6 border-l-4 border-l-red-500 shadow-sm hover:shadow-md transition-all duration-300 flex flex-col">
                        <h5 className="text-xs font-bold uppercase tracking-widest text-text-primary mb-3 flex items-center gap-2">
                            <ShieldAlert className="w-4 h-4 text-red-500" />
                            Business Impact
                        </h5>
                        <p className="text-sm text-text-secondary leading-relaxed flex-grow">
                            {intelligence.business_impact}
                        </p>
                    </div>
                </div>

                <div className="flex flex-wrap gap-2 pt-2 justify-end">
                    {intelligence.data_sources.map(source => (
                        <span key={source} className="text-[10px] font-bold uppercase tracking-widest px-3 py-1 bg-warm-100 text-warm-600 rounded-full border border-warm-200">
                            {source}
                        </span>
                    ))}
                </div>
            </div>
        </div>
    );
}
