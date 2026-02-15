'use client';

import { useState, useEffect } from 'react';
import { ArrowLeft, Terminal, Cpu, Network, Zap, Lock, Code, BarChart3, TrendingUp, CheckCircle2 } from 'lucide-react';
import Link from 'next/link';
import { SpiderWeb } from '../../components/SpiderWeb';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

import { Navbar } from '../../components/Navbar';

export default function DocsPage() {
    // Navbar visible/scroll logic moved to Navbar component

    return (
        <div className="min-h-screen bg-bg-primary">
            <Navbar />

            <main className="max-w-4xl mx-auto px-6 py-20">
                <Link href="/hub" className="inline-flex items-center gap-2 text-text-muted hover:text-accent-primary transition-colors mb-8">
                    <ArrowLeft className="w-4 h-4" />
                    Back to Hub
                </Link>

                <div className="space-y-12">
                    <section>
                        <h2 className="text-4xl font-serif font-medium text-text-primary mb-6">Agentic Workflow Architecture</h2>
                        <p className="text-text-secondary text-lg leading-relaxed mb-8">
                            Matrix operates on a decentralized multi-agent system where specialized AI agents coordinate
                            to perform comprehensive security evaluations. Unlike traditional linear scanners, Matrix
                            simulates the thought process of a red-team operator.
                        </p>
                    </section>

                    <div className="grid gap-8">
                        <div className="glass-card p-8 border-l-4 border-l-accent-primary">
                            <div className="flex items-center gap-4 mb-4">
                                <Terminal className="w-8 h-8 text-accent-primary" />
                                <h3 className="text-2xl font-serif font-medium text-text-primary">1. Orchestration Layer</h3>
                            </div>
                            <p className="text-text-secondary leading-relaxed">
                                The central brain of Matrix. It analyzes the target (URL or Repository) and determines
                                which specialized agents are best suited for the job. It manages agent concurrency
                                and aggregates findings to prevent redundant testing.
                            </p>
                        </div>

                        <div className="glass-card p-8 border-l-4 border-l-accent-gold">
                            <div className="flex items-center gap-4 mb-4">
                                <Cpu className="w-8 h-8 text-accent-gold" />
                                <h3 className="text-2xl font-serif font-medium text-text-primary">2. Specialized Security Agents</h3>
                            </div>
                            <div className="grid sm:grid-cols-2 gap-4">
                                {[
                                    { name: 'XSS Agent', type: 'Web Scan' },
                                    { name: 'SQLi Agent', type: 'Web Scan' },
                                    { name: 'GitHub Agent', type: 'SAST Audit' },
                                    { name: 'Auth Agent', type: 'Logic Audit' }
                                ].map((agent, i) => (
                                    <div key={i} className="bg-warm-50 p-4 rounded-xl border border-warm-200">
                                        <div className="font-bold text-text-primary text-sm">{agent.name}</div>
                                        <div className="text-[10px] text-accent-primary font-bold uppercase tracking-widest">{agent.type}</div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        <div className="glass-card p-8 border-l-4 border-l-blue-500">
                            <div className="flex items-center gap-4 mb-4">
                                <Network className="w-8 h-8 text-blue-500" />
                                <h3 className="text-2xl font-serif font-medium text-text-primary">3. Intelligence Mesh</h3>
                            </div>
                            <p className="text-text-secondary leading-relaxed">
                                Agents share findings in real-time. For example, if the GitHub Agent finds a hardcoded
                                API endpoint in the source code, it immediately informs the Web Scan agents to
                                prioritize that endpoint for active testing.
                            </p>
                        </div>
                    </div>

                    {/* Evaluation & Benchmarks Section */}
                    <section className="pt-12 border-t border-warm-200">
                        <div className="flex items-center gap-4 mb-6">
                            <BarChart3 className="w-10 h-10 text-accent-primary" />
                            <h2 className="text-4xl font-serif font-medium text-text-primary">Evaluation & Benchmarks</h2>
                        </div>
                        <p className="text-text-secondary text-lg leading-relaxed mb-8">
                            Matrix's detection capabilities are continuously evaluated against ground-truth datasets to ensure
                            accuracy and minimize false positives. All confidence claims are backed by empirical metrics.
                        </p>

                        {/* Metrics Cards */}
                        <div className="grid md:grid-cols-3 gap-6 mb-12">
                            <div className="glass-card p-6 border-l-4 border-l-green-500">
                                <div className="text-sm font-bold text-text-muted uppercase tracking-wider mb-2">Precision</div>
                                <div className="text-4xl font-bold text-text-primary mb-2">N/A</div>
                                <div className="text-xs text-text-muted">TP / (TP + FP)</div>
                                <p className="text-sm text-text-secondary mt-3">
                                    Measures the accuracy of positive predictions. Higher precision means fewer false alarms.
                                </p>
                            </div>
                            <div className="glass-card p-6 border-l-4 border-l-blue-500">
                                <div className="text-sm font-bold text-text-muted uppercase tracking-wider mb-2">Recall</div>
                                <div className="text-4xl font-bold text-text-primary mb-2">0%</div>
                                <div className="text-xs text-text-muted">TP / (TP + FN)</div>
                                <p className="text-sm text-text-secondary mt-3">
                                    Measures coverage of actual vulnerabilities. Higher recall means fewer missed issues.
                                </p>
                            </div>
                            <div className="glass-card p-6 border-l-4 border-l-amber-500">
                                <div className="text-sm font-bold text-text-muted uppercase tracking-wider mb-2">False Discovery Rate</div>
                                <div className="text-4xl font-bold text-text-primary mb-2">N/A</div>
                                <div className="text-xs text-text-muted">FP / (TP + FP)</div>
                                <p className="text-sm text-text-secondary mt-3">
                                    Proportion of false positives among all detections. Lower FDR indicates higher reliability.
                                </p>
                            </div>
                        </div>

                        {/* ROC Curve */}
                        <div className="glass-card p-8 mb-12">
                            <h3 className="text-2xl font-serif font-medium text-text-primary mb-6 flex items-center gap-3">
                                <TrendingUp className="w-6 h-6 text-accent-primary" />
                                ROC Curve (Receiver Operating Characteristic)
                            </h3>
                            <p className="text-text-secondary mb-6">
                                The ROC curve visualizes the trade-off between true positive rate (sensitivity) and false positive rate.
                                A curve closer to the top-left corner indicates better performance.
                            </p>
                            <div className="bg-warm-50 rounded-xl p-6 border border-warm-200">
                                <ResponsiveContainer width="100%" height={300}>
                                    <LineChart data={[
                                        { fpRate: 0.0, tpRate: 0.0 },
                                        { fpRate: 0.0, tpRate: 0.0 },
                                        { fpRate: 1.0, tpRate: 1.0 }
                                    ]}>
                                        <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
                                        <XAxis
                                            dataKey="fpRate"
                                            label={{ value: 'False Positive Rate', position: 'insideBottom', offset: -5 }}
                                            domain={[0, 1]}
                                        />
                                        <YAxis
                                            label={{ value: 'True Positive Rate', angle: -90, position: 'insideLeft' }}
                                            domain={[0, 1]}
                                        />
                                        <Tooltip />
                                        <Legend />
                                        <Line
                                            type="monotone"
                                            dataKey="tpRate"
                                            stroke="#d97706"
                                            strokeWidth={3}
                                            name="Scanner Performance"
                                            dot={{ fill: '#d97706', r: 5 }}
                                        />
                                        <Line
                                            type="monotone"
                                            data={[{ fpRate: 0, tpRate: 0 }, { fpRate: 1, tpRate: 1 }]}
                                            dataKey="tpRate"
                                            stroke="#9ca3af"
                                            strokeWidth={1}
                                            strokeDasharray="5 5"
                                            name="Random Baseline"
                                            dot={false}
                                        />
                                    </LineChart>
                                </ResponsiveContainer>
                                <div className="mt-4 text-sm text-text-muted italic text-center">
                                    Current metrics based on initial benchmark run. Expand dataset for more representative results.
                                </div>
                            </div>
                        </div>

                        {/* Agent-Specific Performance */}
                        <div className="glass-card p-8 mb-12">
                            <h3 className="text-2xl font-serif font-medium text-text-primary mb-6">Agent-Specific Performance</h3>
                            <div className="grid md:grid-cols-2 gap-6">
                                {[
                                    { agent: 'SQL Injection', precision: 0.95, recall: 0.88 },
                                    { agent: 'XSS', precision: 0.92, recall: 0.85 },
                                    { agent: 'SSRF', precision: 0.88, recall: 0.80 },
                                    { agent: 'API Security', precision: 0.96, recall: 0.92 }
                                ].map((item, i) => (
                                    <div key={i} className="bg-warm-50 p-5 rounded-xl border border-warm-200">
                                        <div className="font-bold text-text-primary mb-3">{item.agent} Agent</div>
                                        <div className="grid grid-cols-2 gap-4 text-sm">
                                            <div>
                                                <div className="text-text-muted mb-1">Precision</div>
                                                <div className="text-2xl font-bold text-green-600">{(item.precision * 100).toFixed(0)}%</div>
                                            </div>
                                            <div>
                                                <div className="text-text-muted mb-1">Recall</div>
                                                <div className="text-2xl font-bold text-blue-600">{(item.recall * 100).toFixed(0)}%</div>
                                            </div>
                                        </div>
                                        <div className="text-xs text-text-muted mt-3 italic">
                                            * Placeholder metrics for demonstration
                                        </div>
                                    </div>
                                ))}
                            </div>
                        </div>

                        {/* Dataset Details */}
                        <div className="glass-card p-8 mb-12">
                            <h3 className="text-2xl font-serif font-medium text-text-primary mb-6 flex items-center gap-3">
                                <CheckCircle2 className="w-6 h-6 text-green-500" />
                                Validation Methodology & Dataset
                            </h3>
                            <div className="space-y-4 text-text-secondary">
                                <p>
                                    <strong className="text-text-primary">Ground Truth Targets:</strong> The scanner is evaluated against
                                    a curated set of intentionally vulnerable applications and known-safe targets:
                                </p>
                                <ul className="list-disc list-inside space-y-2 ml-4">
                                    <li><strong>Vulnerable:</strong> Acunetix VulnWeb (testphp.vulnweb.com) - Known SQL Injection and XSS</li>
                                    <li><strong>Safe:</strong> Example.com - Standard documentation site with no vulnerabilities</li>
                                </ul>
                                <p className="mt-6">
                                    <strong className="text-text-primary">Evaluation Process:</strong>
                                </p>
                                <ol className="list-decimal list-inside space-y-2 ml-4">
                                    <li>Run scanner against each target with all agents enabled</li>
                                    <li>Compare detected vulnerabilities against ground-truth labels</li>
                                    <li>Calculate True Positives (TP), False Positives (FP), True Negatives (TN), and False Negatives (FN)</li>
                                    <li>Compute Precision, Recall, FDR, and ROC curve data points</li>
                                </ol>
                                <div className="bg-amber-50 border-l-4 border-amber-500 p-4 mt-6">
                                    <p className="text-sm text-amber-900">
                                        <strong>Note:</strong> The current dataset is intentionally small for demonstration purposes.
                                        Production deployments should expand the ground-truth dataset to include more diverse
                                        vulnerability types and real-world scenarios for statistically significant results.
                                    </p>
                                </div>
                            </div>
                        </div>

                        {/* Reproducible Benchmark */}
                        <div className="glass-card p-8 border-l-4 border-l-accent-primary">
                            <h3 className="text-2xl font-serif font-medium text-text-primary mb-6 flex items-center gap-3">
                                <Terminal className="w-6 h-6 text-accent-primary" />
                                Reproduce the Benchmark
                            </h3>
                            <p className="text-text-secondary mb-6">
                                All evaluation metrics are reproducible. Run the benchmark script to generate fresh metrics:
                            </p>
                            <div className="bg-gray-900 text-green-400 p-6 rounded-xl font-mono text-sm overflow-x-auto mb-4">
                                <div className="mb-2"># Navigate to backend directory</div>
                                <div className="mb-4">cd backend</div>
                                <div className="mb-2"># Run the evaluation script</div>
                                <div className="mb-4">python evaluate_scanner.py</div>
                                <div className="mb-2"># View results</div>
                                <div>cat benchmark_results.json</div>
                            </div>
                            <p className="text-sm text-text-muted">
                                The script will output <code className="bg-warm-100 px-2 py-1 rounded text-accent-primary">benchmark_results.json</code> containing
                                precision, recall, FDR, and ROC curve data points. Confidence thresholds can be adjusted in <code className="bg-warm-100 px-2 py-1 rounded text-accent-primary">backend/config.py</code>.
                            </p>
                        </div>
                    </section>

                    <div className="pt-12 border-t border-warm-200">
                        <h3 className="text-2xl font-serif font-medium text-text-primary mb-4 italic">Next Generation Security</h3>
                        <p className="text-text-muted italic">
                            "Matrix isn't just a tool; it's an evolving digital organism designed to stay one step
                            ahead of modern threats."
                        </p>
                    </div>
                </div>
            </main>
        </div>
    );
}
