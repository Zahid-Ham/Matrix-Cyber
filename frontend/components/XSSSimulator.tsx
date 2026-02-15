'use client';

import React, { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
    Shield, ShieldOff, Terminal, AlertTriangle, CheckCircle, XCircle, Lock, Unlock,
    ArrowRight, User, Globe, Database, Zap, Info, BookOpen
} from 'lucide-react';
import { createPortal } from 'react-dom';

interface XSSSimulatorProps {
    onClose: () => void;
}

// Step-by-step attack flow stages
const ATTACK_STAGES = [
    {
        id: 1,
        title: "User Input",
        icon: User,
        description: "Attacker submits malicious script through form field",
        example: '<script>steal()</script>',
        color: 'text-blue-400',
        bgColor: 'bg-blue-500/10',
        borderColor: 'border-blue-500/30'
    },
    {
        id: 2,
        title: "Server Processing",
        icon: Database,
        description: "Server accepts input without validation/sanitization",
        example: 'No input filtering applied',
        color: 'text-yellow-400',
        bgColor: 'bg-yellow-500/10',
        borderColor: 'border-yellow-500/30'
    },
    {
        id: 3,
        title: "Page Rendered",
        icon: Globe,
        description: "Browser receives page with malicious script embedded",
        example: 'HTML includes raw script',
        color: 'text-orange-400',
        bgColor: 'bg-orange-500/10',
        borderColor: 'border-orange-500/30'
    },
    {
        id: 4,
        title: "Script Execution",
        icon: Zap,
        description: "Browser executes the injected JavaScript code",
        example: 'Cookies stolen, session hijacked',
        color: 'text-red-400',
        bgColor: 'bg-red-500/10',
        borderColor: 'border-red-500/30'
    }
];

export function XSSSimulator({ onClose }: XSSSimulatorProps) {
    const [payload, setPayload] = useState('');
    const [isProtected, setIsProtected] = useState(true);
    const [submittedPayload, setSubmittedPayload] = useState('');
    const [showHackerOverlay, setShowHackerOverlay] = useState(false);
    const [attackStage, setAttackStage] = useState(0);
    const [logs, setLogs] = useState<string[]>([]);
    const [hackerText, setHackerText] = useState('');
    const [showExplanation, setShowExplanation] = useState(true);
    const logEndRef = useRef<HTMLDivElement>(null);

    // Hacker overlay messages
    const hackerMessages = [
        '[ SYSTEM BREACH DETECTED ]',
        '[+] Malicious <script> tag injected',
        '[+] Bypassing input validation...',
        '[+] JavaScript execution context acquired',
        '[+] Accessing document.cookie...',
        '[+] SessionID=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
        '[+] Accessing localStorage...',
        '[+] Extracting authToken...',
        '[+] Hooking into DOM...',
        '[+] Injecting invisible iframe...',
        '[+] Capturing user keystrokes...',
        '[+] Overriding login form action...',
        '[+] Sending data to attacker.com...',
        '[+] Awaiting remote command...',
        '[+] Remote payload received',
        '[+] Page content modified',
        '[+] Session Hijack Complete',
        '⚠ USER DATA COMPROMISED'
    ];

    // Auto-scroll logs
    useEffect(() => {
        logEndRef.current?.scrollIntoView({ behavior: 'smooth' });
    }, [logs]);

    // Animate attack stages when vulnerable and submitted
    useEffect(() => {
        if (!isProtected && submittedPayload && detectXSSPayload(submittedPayload)) {
            let stage = 0;
            const interval = setInterval(() => {
                if (stage < ATTACK_STAGES.length) {
                    setAttackStage(stage + 1);
                    stage++;
                } else {
                    clearInterval(interval);
                }
            }, 1500);
            return () => clearInterval(interval);
        } else {
            setAttackStage(0);
        }
    }, [submittedPayload, isProtected]);

    // Typing animation for hacker overlay
    useEffect(() => {
        if (!showHackerOverlay) {
            setHackerText('');
            return;
        }

        let currentLine = 0;
        let currentChar = 0;
        let text = '';
        let typingInterval: NodeJS.Timeout;

        const typeNextChar = () => {
            if (currentLine >= hackerMessages.length) {
                clearInterval(typingInterval);
                setTimeout(() => {
                    setShowHackerOverlay(false);
                }, 3000);
                return;
            }

            const currentMessage = hackerMessages[currentLine];

            if (currentChar < currentMessage.length) {
                text += currentMessage[currentChar];
                setHackerText(text);
                currentChar++;
            } else {
                text += '\n';
                setHackerText(text);
                currentLine++;
                currentChar = 0;

                clearInterval(typingInterval);
                setTimeout(() => {
                    typingInterval = setInterval(typeNextChar, 50);
                }, 300);
                return;
            }
        };

        typingInterval = setInterval(typeNextChar, 50);
        return () => clearInterval(typingInterval);
    }, [showHackerOverlay]);

    const addLog = (message: string, type: 'info' | 'success' | 'error' | 'warning' = 'info') => {
        const timestamp = new Date().toLocaleTimeString('en-US', { hour12: false });
        const icon = type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠' : '🔵';
        setLogs(prev => [...prev, `[${timestamp}] ${icon} ${message}`]);
    };

    const sanitizeHTML = (html: string): string => {
        return html
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#x27;');
    };

    const detectXSSPayload = (input: string): boolean => {
        const xssPatterns = [
            /<script[^>]*>.*?<\/script>/gi,
            /javascript:/gi,
            /onerror\s*=/gi,
            /onload\s*=/gi,
            /onclick\s*=/gi,
            /<iframe/gi,
            /<img[^>]+src/gi
        ];
        return xssPatterns.some(pattern => pattern.test(input));
    };

    const handleSubmit = () => {
        if (!payload.trim()) {
            addLog('Empty payload detected', 'warning');
            return;
        }

        const isXSSDetected = detectXSSPayload(payload);

        if (isProtected) {
            addLog('Payload received', 'info');

            if (isXSSDetected) {
                addLog('🛡️ XSS payload detected!', 'error');
                addLog('⚙️ Applying HTML entity encoding...', 'info');
                addLog('✂️ Script tags neutralized (<script> → &lt;script&gt;)', 'success');
                addLog('✂️ Event handlers stripped (onerror, onclick, etc.)', 'success');
                addLog('🔒 Content Security Policy blocks inline scripts', 'success');
                addLog('✅ Attack prevented - payload rendered as harmless text', 'success');
            }

            const sanitized = sanitizeHTML(payload);
            setSubmittedPayload(sanitized);
        } else {
            addLog('⚠ VULNERABLE MODE: No input validation', 'warning');

            if (isXSSDetected) {
                addLog('🚨 XSS detected but protection is OFF!', 'error');
                addLog('💣 Server accepting raw HTML without sanitization', 'error');
                addLog('📄 Injecting malicious script into page DOM', 'error');
                addLog('⚡ Browser will execute the script...', 'error');

                setTimeout(() => {
                    setShowHackerOverlay(true);
                }, 2000);
            }

            setSubmittedPayload(payload);
        }
    };

    const toggleProtection = () => {
        setIsProtected(!isProtected);
        setLogs([]);
        setSubmittedPayload('');
        setAttackStage(0);

        if (!isProtected) {
            addLog('🔐 XSS Protection ENABLED', 'success');
            addLog('✅ Content Security Policy: Active', 'success');
            addLog('✅ Input sanitization: ON', 'success');
            addLog('✅ HTML entity encoding: Enabled', 'success');
        } else {
            addLog('⚠ XSS Protection DISABLED (Demo Mode)', 'error');
            addLog('⚠ Vulnerable to script injection attacks', 'error');
            addLog('📚 Educational demonstration only', 'warning');
        }
    };

    const [mounted, setMounted] = useState(false);

    useEffect(() => {
        setMounted(true);
        return () => setMounted(false);
    }, []);

    if (!mounted) return null;

    return createPortal(
        <>
            <div className="fixed inset-0 z-[9999] overflow-y-auto bg-black/90 backdrop-blur-xl">
                <div className="flex min-h-screen items-center justify-center p-2 sm:p-4">
                    <motion.div
                        initial={{ scale: 0.95, opacity: 0 }}
                        animate={{ scale: 1, opacity: 1 }}
                        className="w-full max-w-7xl relative bg-slate-900 rounded-2xl border-2 border-emerald-500/30 shadow-2xl shadow-emerald-500/20 overflow-hidden my-6"
                    >
                        {/* Header */}
                        <div className="p-6 bg-gradient-to-r from-slate-800 to-slate-900 border-b border-emerald-500/30">
                            <div className="flex justify-between items-start">
                                <div className="flex items-start gap-4 flex-1">
                                    <div className="w-12 h-12 rounded-xl bg-emerald-500/20 flex items-center justify-center border border-emerald-500/40 flex-shrink-0">
                                        <Terminal className="w-6 h-6 text-emerald-400" />
                                    </div>
                                    <div className="flex-1">
                                        <h3 className="text-2xl font-bold text-white mb-1">XSS Attack Simulator</h3>
                                        <p className="text-sm text-gray-400 mb-3">Interactive Educational Demonstration</p>
                                        <div className="flex items-center gap-2 text-xs text-gray-500">
                                            <Info className="w-4 h-4" />
                                            <span>Watch how XSS attacks work step-by-step. Toggle protection to see the difference.</span>
                                        </div>
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



                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 p-6">
                            {/* Left Column: Controls */}
                            <div className="space-y-6">
                                {/* Security Toggle */}
                                <div className="p-6 bg-slate-800/50 rounded-xl border border-slate-700">
                                    <div className="flex items-center justify-between mb-4">
                                        <div>
                                            <label className="text-sm font-bold text-gray-300 uppercase tracking-wider block mb-1">
                                                Security Mode
                                            </label>
                                            <p className="text-xs text-gray-500">Toggle to compare protected vs vulnerable</p>
                                        </div>
                                        <motion.button
                                            onClick={toggleProtection}
                                            className={`relative w-16 h-8 rounded-full transition-colors ${isProtected ? 'bg-emerald-500' : 'bg-red-500'
                                                }`}
                                            whileTap={{ scale: 0.95 }}
                                        >
                                            <motion.div
                                                className="absolute top-1 left-1 w-6 h-6 bg-white rounded-full shadow-lg flex items-center justify-center"
                                                animate={{ x: isProtected ? 0 : 32 }}
                                                transition={{ type: 'spring', stiffness: 500, damping: 30 }}
                                            >
                                                {isProtected ? (
                                                    <Lock className="w-3 h-3 text-emerald-600" />
                                                ) : (
                                                    <Unlock className="w-3 h-3 text-red-600" />
                                                )}
                                            </motion.div>
                                        </motion.button>
                                    </div>
                                    <div className={`flex items-center gap-3 p-3 rounded-lg ${isProtected ? 'bg-emerald-500/10 border border-emerald-500/30' : 'bg-red-500/10 border border-red-500/30'
                                        }`}>
                                        {isProtected ? (
                                            <>
                                                <Shield className="w-5 h-5 text-emerald-400" />
                                                <div className="flex-1">
                                                    <span className="text-sm font-medium text-emerald-300 block">Protected Mode</span>
                                                    <span className="text-xs text-emerald-400/70">Input sanitization active</span>
                                                </div>
                                            </>
                                        ) : (
                                            <>
                                                <ShieldOff className="w-5 h-5 text-red-400 animate-pulse" />
                                                <div className="flex-1">
                                                    <span className="text-sm font-medium text-red-300 block">⚠ Vulnerable Mode</span>
                                                    <span className="text-xs text-red-400/70">Scripts will execute!</span>
                                                </div>
                                            </>
                                        )}
                                    </div>
                                </div>

                                {/* Payload Input */}
                                <div className="p-6 bg-slate-800/50 rounded-xl border border-slate-700">
                                    <label className="block text-sm font-bold text-gray-300 uppercase tracking-wider mb-1">
                                        Test Payload
                                    </label>
                                    <p className="text-xs text-gray-500 mb-3">Enter malicious code to see how the system responds</p>
                                    <textarea
                                        value={payload}
                                        onChange={(e) => setPayload(e.target.value)}
                                        placeholder="Try: <script>alert('XSS Attack!')</script>"
                                        className="w-full h-32 px-4 py-3 bg-black/50 border border-slate-600 rounded-lg text-gray-200 font-mono text-sm focus:outline-none focus:border-emerald-500 focus:ring-2 focus:ring-emerald-500/20 resize-none placeholder:text-gray-600"
                                    />
                                    <div className="mt-3 flex gap-2">
                                        <motion.button
                                            onClick={handleSubmit}
                                            whileHover={{ scale: 1.02 }}
                                            whileTap={{ scale: 0.98 }}
                                            className="flex-1 px-6 py-3 bg-gradient-to-r from-emerald-600 to-emerald-500 hover:from-emerald-500 hover:to-emerald-400 text-white font-bold rounded-lg shadow-lg shadow-emerald-500/30 transition-all"
                                        >
                                            Submit & Test
                                        </motion.button>
                                    </div>

                                    {/* Quick Test Buttons */}
                                    <div className="mt-4 pt-4 border-t border-slate-700">
                                        <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Quick Tests:</p>
                                        <div className="flex flex-wrap gap-2">
                                            <button
                                                onClick={() => setPayload("<script>alert('XSS')</script>")}
                                                className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-gray-300 text-xs rounded transition-colors"
                                                title="Classic script tag injection"
                                            >
                                                💉 Script Tag
                                            </button>
                                            <button
                                                onClick={() => setPayload('<img src=x onerror="alert(\'XSS\')">')}
                                                className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-gray-300 text-xs rounded transition-colors"
                                                title="Image tag with error handler"
                                            >
                                                🖼️ Image XSS
                                            </button>
                                            <button
                                                onClick={() => setPayload('<iframe src="javascript:alert(\'XSS\')">')}
                                                className="px-3 py-1.5 bg-slate-700 hover:bg-slate-600 text-gray-300 text-xs rounded transition-colors"
                                                title="Iframe with JavaScript protocol"
                                            >
                                                📺 iFrame XSS
                                            </button>
                                            <button
                                                onClick={() => setPayload("Hello, this is safe text!")}
                                                className="px-3 py-1.5 bg-emerald-700 hover:bg-emerald-600 text-gray-300 text-xs rounded transition-colors"
                                                title="Normal, safe input"
                                            >
                                                ✅ Safe Input
                                            </button>
                                        </div>
                                    </div>
                                </div>

                                {/* Output Display */}
                                <div className="p-6 bg-slate-800/50 rounded-xl border border-slate-700">
                                    <label className="block text-sm font-bold text-gray-300 uppercase tracking-wider mb-1">
                                        Rendered Output
                                    </label>
                                    <p className="text-xs text-gray-500 mb-3">How the browser displays your input</p>
                                    <div className="min-h-[100px] p-4 bg-black/50 border border-slate-600 rounded-lg text-gray-300 text-sm">
                                        {submittedPayload ? (
                                            <div>
                                                {isProtected ? (
                                                    <div>
                                                        <div className="text-xs text-emerald-400 mb-2">✅ Sanitized Output:</div>
                                                        <div className="text-gray-400 font-mono break-all">{submittedPayload}</div>
                                                        <div className="mt-3 p-2 bg-emerald-500/10 border border-emerald-500/20 rounded text-xs text-emerald-300">
                                                            💡 Script tags have been converted to harmless text. The browser sees literal characters, not executable code.
                                                        </div>
                                                    </div>
                                                ) : (
                                                    <div>
                                                        <div className="text-xs text-red-400 mb-2 animate-pulse">⚠ Vulnerable Mode - Simulation Active:</div>
                                                        <div className="text-gray-400 font-mono break-all bg-red-500/5 p-2 rounded border border-red-500/20">{submittedPayload}</div>
                                                        <div className="mt-3 p-2 bg-red-500/10 border border-red-500/20 rounded text-xs text-red-300">
                                                            🚨 In a real vulnerable app, this code would execute in the victim's browser! Watch the simulated attack below.
                                                        </div>
                                                    </div>
                                                )}
                                            </div>
                                        ) : (
                                            <span className="text-gray-600 italic">Submit a payload to see output...</span>
                                        )}
                                    </div>
                                </div>
                            </div>

                            {/* Right Column: Console & Explanation */}
                            <div className="space-y-6">
                                {/* Security Console */}
                                <div className="p-6 bg-slate-800/50 rounded-xl border border-slate-700 flex flex-col">
                                    <div className="flex items-center gap-3 mb-4">
                                        <Terminal className="w-5 h-5 text-emerald-400" />
                                        <label className="text-sm font-bold text-gray-300 uppercase tracking-wider flex-1">
                                            Security Event Log
                                        </label>
                                        <div className="flex items-center gap-2">
                                            <div className={`w-2 h-2 rounded-full ${isProtected ? 'bg-emerald-400' : 'bg-red-400'} animate-pulse`} />
                                            <span className="text-xs text-gray-500 font-mono">
                                                {isProtected ? 'PROTECTED' : 'VULNERABLE'}
                                            </span>
                                        </div>
                                    </div>

                                    <div className="flex-1 bg-black/70 rounded-lg p-4 font-mono text-xs overflow-y-auto min-h-[250px] max-h-[350px] border border-slate-700">
                                        {logs.length === 0 ? (
                                            <div className="text-gray-600 italic">
                                                <div className="mb-2">System ready. Waiting for input...</div>
                                                <div className="text-[10px] text-gray-700">
                                                    Tip: Submit a payload to see security processing in real-time
                                                </div>
                                            </div>
                                        ) : (
                                            <div className="space-y-1">
                                                {logs.map((log, idx) => (
                                                    <motion.div
                                                        key={idx}
                                                        initial={{ opacity: 0, x: -10 }}
                                                        animate={{ opacity: 1, x: 0 }}
                                                        className="text-emerald-400"
                                                    >
                                                        {log}
                                                    </motion.div>
                                                ))}
                                                <div ref={logEndRef} />
                                            </div>
                                        )}
                                    </div>
                                </div>

                                {/* Educational Info */}
                                <div className="p-6 bg-gradient-to-br from-blue-500/10 to-purple-500/10 rounded-xl border border-blue-500/30">
                                    <div className="flex items-start gap-3">
                                        <BookOpen className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
                                        <div>
                                            <h4 className="text-sm font-bold text-blue-300 mb-2">How XSS Works</h4>
                                            <div className="text-xs text-gray-300 space-y-2 leading-relaxed">
                                                <p><strong className="text-blue-400">Without Protection:</strong> Malicious scripts are injected into web pages and executed by victims' browsers, stealing cookies, sessions, or redirecting users to phishing sites.</p>
                                                <p><strong className="text-emerald-400">With Protection:</strong> Input is sanitized by converting special characters (&lt;, &gt;, etc.) into HTML entities, preventing script execution. CSP headers block inline scripts.</p>
                                                <p className="text-gray-400 pt-2 border-t border-gray-700">💡 Always sanitize user input and use Content Security Policy headers in production!</p>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </motion.div>
                </div>

                {/* Hacker Overlay */}
                <AnimatePresence>
                    {showHackerOverlay && (
                        <motion.div
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            exit={{ opacity: 0 }}
                            className="fixed inset-0 z-[10000] bg-black flex items-center justify-center"
                        >
                            {/* Glitch effect background */}
                            <motion.div
                                className="absolute inset-0"
                                animate={{
                                    opacity: [0.1, 0.2, 0.1],
                                }}
                                transition={{ duration: 0.3, repeat: Infinity }}
                                style={{
                                    backgroundImage: 'repeating-linear-gradient(0deg, rgba(0, 255, 0, 0.03) 0px, transparent 1px, transparent 2px, rgba(0, 255, 0, 0.03) 3px)',
                                }}
                            />

                            <div className="relative z-10 w-full max-w-4xl p-12">
                                <motion.pre
                                    className="text-emerald-400 font-mono text-xl leading-relaxed whitespace-pre-wrap"
                                    style={{ textShadow: '0 0 10px rgba(16, 185, 129, 0.5)' }}
                                >
                                    {hackerText}
                                    <motion.span
                                        animate={{ opacity: [1, 0, 1] }}
                                        transition={{ duration: 0.5, repeat: Infinity }}
                                        className="inline-block ml-1"
                                    >
                                        █
                                    </motion.span>
                                </motion.pre>

                                <motion.button
                                    initial={{ opacity: 0 }}
                                    animate={{ opacity: 1 }}
                                    transition={{ delay: 2 }}
                                    onClick={() => setShowHackerOverlay(false)}
                                    className="mt-8 px-6 py-3 bg-red-600 hover:bg-red-500 text-white font-bold rounded-lg transition-colors"
                                >
                                    Close Simulation
                                </motion.button>
                            </div>

                            {/* Scanlines effect */}
                            <div
                                className="absolute inset-0 pointer-events-none opacity-10"
                                style={{
                                    backgroundImage: 'repeating-linear-gradient(0deg, transparent, transparent 2px, rgba(255, 255, 255, 0.1) 2px, rgba(255, 255, 255, 0.1) 4px)',
                                }}
                            />
                        </motion.div>
                    )}
                </AnimatePresence>
            </div>
        </>,
        document.body
    );
}
