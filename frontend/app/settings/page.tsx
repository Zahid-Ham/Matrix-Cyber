"use client";

import { useState, useEffect } from "react";
import { useAuth } from "@/context/AuthContext";
import { api } from "@/lib/matrix_api";
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
        <div className="min-h-screen bg-background-primary">
            <div className="max-w-4xl mx-auto px-6 py-8">
                <div className="mb-8">
                    <h1 className="text-3xl font-bold text-text-primary mb-2">Settings</h1>
                    <p className="text-text-secondary">Manage your Matrix configuration and integrations</p>
                </div>

                {/* GitHub Integration Section */}
                <div className="bg-surface-primary border border-warm-200 rounded-lg p-6 shadow-sm">
                    <div className="flex items-center gap-3 mb-6">
                        <Key className="w-6 h-6 text-primary-600" />
                        <div>
                            <h2 className="text-xl font-semibold text-text-primary">GitHub Integration</h2>
                            <p className="text-sm text-text-secondary">Configure your Personal Access Token for self-healing features</p>
                        </div>
                    </div>

                    {/* Token Status */}
                    {tokenStatus && tokenStatus.configured && (
                        <div className="mb-6 p-4 bg-warm-50 border border-warm-200 rounded-lg">
                            <div className="flex items-center justify-between">
                                <div className="flex items-center gap-3">
                                    {tokenStatus.valid ? (
                                        <CheckCircle className="w-5 h-5 text-success-600" />
                                    ) : (
                                        <XCircle className="w-5 h-5 text-error-600" />
                                    )}
                                    <div>
                                        <p className="text-sm font-medium text-text-primary">
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
                                        className="flex items-center gap-2 px-3 py-1.5 text-sm bg-primary-50 text-primary-700 rounded-md hover:bg-primary-100 disabled:opacity-50"
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
                                        className="flex items-center gap-2 px-3 py-1.5 text-sm bg-error-50 text-error-700 rounded-md hover:bg-error-100 disabled:opacity-50"
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
                    <form onSubmit={handleSaveToken} className="space-y-4">
                        <div>
                            <label htmlFor="github-token" className="block text-sm font-medium text-text-primary mb-2">
                                GitHub Personal Access Token
                            </label>
                            <input
                                id="github-token"
                                type="password"
                                value={token}
                                onChange={(e) => setToken(e.target.value)}
                                placeholder="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
                                className="w-full px-4 py-2 bg-white border border-warm-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent text-text-primary placeholder-text-muted"
                                disabled={loading}
                            />
                            <p className="mt-1 text-xs text-text-muted">
                                Your token will be encrypted before storage and only used for creating issues and pull requests on your behalf.
                            </p>
                        </div>

                        {/* Message Display */}
                        {message && (
                            <div
                                className={`p-3 rounded-lg ${message.type === "success"
                                        ? "bg-success-50 border border-success-200 text-success-800"
                                        : "bg-error-50 border border-error-200 text-error-800"
                                    }`}
                            >
                                <p className="text-sm">{message.text}</p>
                            </div>
                        )}

                        <button
                            type="submit"
                            disabled={loading || !token.trim()}
                            className="w-full flex items-center justify-center gap-2 px-6 py-3 bg-primary-600 text-white rounded-lg hover:bg-primary-700 disabled:opacity-50 disabled:cursor-not-allowed font-medium transition-colors"
                        >
                            {loading ? (
                                <>
                                    <Loader2 className="w-5 h-5 animate-spin" />
                                    Saving...
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
                    <div className="mt-6 p-4 bg-info-50 border border-info-200 rounded-lg">
                        <h3 className="text-sm font-semibold text-info-900 mb-2">Why configure a GitHub token?</h3>
                        <ul className="text-xs text-info-800 space-y-1 list-disc list-inside">
                            <li>Enable self-healing features to create pull requests on your repositories</li>
                            <li>Report security findings as GitHub issues automatically</li>
                            <li>Your token is used instead of the system token, giving you full control</li>
                            <li>All actions are performed under your GitHub account for better audit trails</li>
                        </ul>
                    </div>
                </div>
            </div>
        </div>
    );
}
