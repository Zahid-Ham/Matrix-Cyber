"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/matrix_api";
import { Navbar } from "@/components/Navbar";
import GitHubTokenGuide from "@/components/GitHubTokenGuide";
import { CheckCircle, XCircle, Loader2, Trash2, RefreshCw, Key } from "lucide-react";

export default function SettingsPage() {
    const { user } = useAuth();
    const [token, setToken] = useState("");
    const [tokenStatus, setTokenStatus] = useState<{
        configured: boolean;
        username?: string;
        valid: boolean;
        last_validated?: string;
    } | null>(null);
    const [loading, setLoading] = useState(false);
    const [validating, setValidating] = useState(false);
    const [message, setMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

    useEffect(() => {
        loadTokenStatus();
    }, []);

    const loadTokenStatus = async () => {
        try {
            const status = await api.getGitHubTokenStatus();
            setTokenStatus(status);
        } catch (error: any) {
            console.error("Failed to load token status:", error);
        }
    };

    const handleSaveToken = async (e: React.FormEvent) => {
        e.preventDefault();
        if (!token.trim()) {
            setMessage({ type: "error", text: "Please enter a GitHub token" });
            return;
        }

        setLoading(true);
        setMessage(null);

        try {
            const result = await api.saveGitHubToken(token);
            setMessage({ type: "success", text: `Token saved successfully! Connected as ${result.username}` });
            setToken("");
            await loadTokenStatus();
        } catch (error: any) {
            setMessage({ type: "error", text: error.message || "Failed to save token" });
        } finally {
            setLoading(false);
        }
    };

    const handleDeleteToken = async () => {
        if (!confirm("Are you sure you want to delete your GitHub token? Self-healing features will fall back to the system token.")) {
            return;
        }

        setLoading(true);
        setMessage(null);

        try {
            await api.deleteGitHubToken();
            setMessage({ type: "success", text: "Token deleted successfully" });
            await loadTokenStatus();
        } catch (error: any) {
            setMessage({ type: "error", text: error.message || "Failed to delete token" });
        } finally {
            setLoading(false);
        }
    };

    const handleValidateToken = async () => {
        setValidating(true);
        setMessage(null);

        try {
            const result = await api.validateGitHubToken();
            if (result.valid) {
                setMessage({ type: "success", text: `Token is valid! Connected as ${result.username}` });
            } else {
                setMessage({ type: "error", text: result.message || "Token is invalid" });
            }
            await loadTokenStatus();
        } catch (error: any) {
            setMessage({ type: "error", text: error.message || "Failed to validate token" });
        } finally {
            setValidating(false);
        }
    };

    return (
        <div className="min-h-screen bg-bg-primary">
            <Navbar />

            <main className="max-w-4xl mx-auto px-6 py-20">
                <div className="mb-12 text-center">
                    <h1 className="text-5xl font-serif font-medium text-text-primary tracking-tight mb-4">
                        Settings
                    </h1>
                    <p className="text-text-secondary text-lg">
                        Manage your Matrix configuration and integrations
                    </p>
                </div>

                {/* GitHub Integration Section */}
                <div className="glass-card p-8 border-2 border-accent-primary/20 shadow-xl">
                    <div className="flex items-center gap-3 mb-8">
                        <div className="w-14 h-14 rounded-2xl bg-accent-primary/10 flex items-center justify-center">
                            <Key className="w-7 h-7 text-accent-primary" />
                        </div>
                        <div>
                            <h2 className="text-2xl font-serif font-medium text-text-primary">GitHub Integration</h2>
                            <p className="text-sm text-text-secondary">Configure your Personal Access Token for self-healing features</p>
                        </div>
                    </div>

                    {/* Token Status */}
                    {tokenStatus && tokenStatus.configured && (
                        <div className="mb-6 p-5 glass-card border-2 border-warm-200/50">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    {tokenStatus.valid ? (
                                        <CheckCircle className="w-6 h-6 text-green-500" />
                                    ) : (
                                        <XCircle className="w-6 h-6 text-red-500" />
                                    )}
                                    <div>
                                        <p className="text-sm font-semibold text-text-primary">
                                            {tokenStatus.valid ? "Token Active" : "Token Invalid"}
                                        </p>
                                        {tokenStatus.username && (
                                            <p className="text-xs text-text-secondary">Connected as: {tokenStatus.username}</p>
                                        )}
                                        {tokenStatus.last_validated && (
                                            <p className="text-xs text-text-muted">
                                                Last validated: {new Date(tokenStatus.last_validated).toLocaleString()}
                                            </p>
                                        )}
                                    </div>
                                </div>
                                <div className="flex gap-2">
                                    <button
                                        onClick={handleValidateToken}
                                        disabled={validating}
                                        className="flex items-center gap-2 px-4 py-2 text-sm bg-accent-primary/10 text-accent-primary rounded-lg hover:bg-accent-primary/20 disabled:opacity-50 transition-colors font-medium"
                                    >
                                        {validating ? (
                                            <Loader2 className="w-4 h-4 animate-spin" />
                                        ) : (
                                            <RefreshCw className="w-4 h-4" />
                                        )}
                                        Validate
                                    </button>
                                    <button
                                        onClick={handleDeleteToken}
                                        disabled={loading}
                                        className="flex items-center gap-2 px-4 py-2 text-sm bg-red-500/10 text-red-500 rounded-lg hover:bg-red-500/20 disabled:opacity-50 transition-colors font-medium"
                                    >
                                        <Trash2 className="w-4 h-4" />
                                        Delete
                                    </button>
                                </div>
                            </div>
                        </div>
                    )}

                    {/* Guide */}
                    <GitHubTokenGuide />

                    {/* Token Input Form */}
                    <form onSubmit={handleSaveToken} className="space-y-6">
                        <div>
                            <label htmlFor="github-token" className="block text-sm font-semibold text-text-primary mb-3">
                                GitHub Personal Access Token
                            </label>
                            <input
                                id="github-token"
                                type="password"
                                value={token}
                                onChange={(e) => setToken(e.target.value)}
                                placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                className="w-full px-4 py-3 bg-surface-primary/50 border-2 border-warm-300/50 rounded-lg focus:outline-none focus:ring-2 focus:ring-accent-primary focus:border-accent-primary text-text-primary placeholder-text-muted transition-all"
                                disabled={loading}
                            />
                            <p className="mt-2 text-xs text-text-muted">
                                Your token will be encrypted before storage and only used for creating issues and pull requests on your behalf.
                            </p>
                        </div>

                        {/* Message Display */}
                        {message && (
                            <div
                                className={`p-4 rounded-lg border-2 ${message.type === "success"
                                    ? "bg-green-500/10 border-green-500/30 text-green-600"
                                    : "bg-red-500/10 border-red-500/30 text-red-600"
                                    }`}
                            >
                                <p className="text-sm font-medium">{message.text}</p>
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loading || !token.trim()}
                            className="w-full flex items-center justify-center gap-2 px-6 py-4 bg-accent-primary text-white rounded-lg hover:bg-accent-primary/90 disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-lg transition-all shadow-lg hover:shadow-xl hover:-translate-y-0.5"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                    Saving Token...
                                </>
                            ) : (
                                <>
                                    <Key className="w-5 h-5" />
                                    {tokenStatus?.configured ? "Update Token" : "Save Token"}
                                </>
                            )}
                        </button>
                    </form>

                    {/* Info Box */}
                    <div className="mt-8 p-6 glass-card border-2 border-accent-gold/20">
                        <h3 className="text-sm font-bold uppercase tracking-widest text-accent-gold mb-3">Why configure a GitHub token?</h3>
                        <ul className="text-sm text-text-secondary space-y-2">
                            <li className="flex items-start gap-2">
                                <span className="text-accent-gold mt-1">•</span>
                                <span>Enable self-healing features to create pull requests on your repositories</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-accent-gold mt-1">•</span>
                                <span>Report security findings as GitHub issues automatically</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-accent-gold mt-1">•</span>
                                <span>Your token is used instead of the system token, giving you full control</span>
                            </li>
                            <li className="flex items-start gap-2">
                                <span className="text-accent-gold mt-1">•</span>
                                <span>All actions are performed under your GitHub account for better audit trails</span>
                            </li>
                        </ul>
                    </div>
                </div>
            </main>
        </div>
    );
}
