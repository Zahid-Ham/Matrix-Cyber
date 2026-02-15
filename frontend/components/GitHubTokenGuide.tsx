"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, ExternalLink, Shield, Key, CheckCircle2, AlertTriangle } from "lucide-react";

export default function GitHubTokenGuide() {
    const [isExpanded, setIsExpanded] = useState(false);

    return (
        <div className="mb-6">
            <button
                onClick={() => setIsExpanded(!isExpanded)}
                className="w-full flex items-center justify-between p-4 bg-info-50 border border-info-200 rounded-lg hover:bg-info-100 transition-colors"
            >
                <div className="flex items-center gap-3">
                    <Key className="w-5 h-5 text-info-700" />
                    <span className="font-semibold text-info-900">
                        How to get a GitHub Personal Access Token
                    </span>
                </div>
                {isExpanded ? (
                    <ChevronUp className="w-5 h-5 text-info-700" />
                ) : (
                    <ChevronDown className="w-5 h-5 text-info-700" />
                )}
            </button>

            {isExpanded && (
                <div className="mt-2 p-6 bg-white border border-info-200 rounded-lg space-y-6 animate-fade-in">
                    <div className="space-y-4">
                        <h3 className="font-semibold text-text-primary flex items-center gap-2">
                            <Shield className="w-5 h-5 text-primary-600" />
                            Step-by-Step Guide
                        </h3>

                        <ol className="space-y-4 text-sm text-text-secondary">
                            <li className="flex gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-xs font-bold">
                                    1
                                </span>
                                <div className="flex-1">
                                    <p className="font-medium text-text-primary mb-1">Go to GitHub Settings</p>
                                    <p>Navigate to your GitHub account settings</p>
                                    <a
                                        href="https://github.com/settings/tokens"
                                        target="_blank"
                                        rel="noopener noreferrer"
                                        className="inline-flex items-center gap-1 mt-2 text-primary-600 hover:text-primary-700 font-medium"
                                    >
                                        Open GitHub Token Settings
                                        <ExternalLink className="w-4 h-4" />
                                    </a>
                                </div>
                            </li>

                            <li className="flex gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-xs font-bold">
                                    2
                                </span>
                                <div className="flex-1">
                                    <p className="font-medium text-text-primary mb-1">Generate New Token</p>
                                    <p>Click <strong>"Generate new token"</strong> → <strong>"Generate new token (fine-grained)"</strong></p>
                                    <p className="mt-1 text-xs text-text-muted italic">Note: Use fine-grained tokens for better security and granular permissions</p>
                                </div>
                            </li>

                            <li className="flex gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-xs font-bold">
                                    3
                                </span>
                                <div className="flex-1">
                                    <p className="font-medium text-text-primary mb-1">Configure Token Details</p>
                                    <ul className="mt-2 space-y-1 text-xs">
                                        <li>• <strong>Token name:</strong> "Matrix Security Scanner" (or any descriptive name)</li>
                                        <li>• <strong>Expiration:</strong> Choose your preferred expiration (30, 60, 90 days, or custom)</li>
                                        <li>• <strong>Repository access:</strong> Select repositories you want to scan</li>
                                    </ul>
                                </div>
                            </li>

                            <li className="flex gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-xs font-bold">
                                    4
                                </span>
                                <div className="flex-1">
                                    <p className="font-medium text-text-primary mb-2">Select Repository Permissions</p>
                                    <div className="bg-warm-50 border border-warm-200 rounded-md p-3 space-y-2">
                                        <div className="flex items-start gap-2">
                                            <CheckCircle2 className="w-4 h-4 text-success-600 mt-0.5 flex-shrink-0" />
                                            <div>
                                                <p className="font-semibold text-text-primary text-xs">Contents (Read and write)</p>
                                                <p className="text-xs text-text-muted">Required - Access repository files and content</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <CheckCircle2 className="w-4 h-4 text-success-600 mt-0.5 flex-shrink-0" />
                                            <div>
                                                <p className="font-semibold text-text-primary text-xs">Metadata (Read-only)</p>
                                                <p className="text-xs text-text-muted">Required - Access repository metadata</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <CheckCircle2 className="w-4 h-4 text-success-600 mt-0.5 flex-shrink-0" />
                                            <div>
                                                <p className="font-semibold text-text-primary text-xs">Workflows (Read and write)</p>
                                                <p className="text-xs text-text-muted">Required - Update GitHub Action workflows</p>
                                            </div>
                                        </div>
                                        <div className="flex items-start gap-2">
                                            <CheckCircle2 className="w-4 h-4 text-success-600 mt-0.5 flex-shrink-0" />
                                            <div>
                                                <p className="font-semibold text-text-primary text-xs">Pull requests (Read and write)</p>
                                                <p className="text-xs text-text-muted">Required - Create and manage pull requests</p>
                                            </div>
                                        </div>
                                    </div>
                                    <div className="mt-2 flex items-start gap-2 text-xs text-warning-700 bg-warning-50 border border-warning-200 rounded p-2">
                                        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                        <p><strong>Important:</strong> Only select the permissions listed above. Do not grant additional permissions unless necessary.</p>
                                    </div>
                                </div>
                            </li>

                            <li className="flex gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-xs font-bold">
                                    5
                                </span>
                                <div className="flex-1">
                                    <p className="font-medium text-text-primary mb-1">Generate and Copy Token</p>
                                    <p>Click <strong>"Generate token"</strong> at the bottom of the page</p>
                                    <div className="mt-2 flex items-start gap-2 text-xs text-error-700 bg-error-50 border border-error-200 rounded p-2">
                                        <Shield className="w-4 h-4 flex-shrink-0 mt-0.5" />
                                        <p><strong>Copy immediately!</strong> GitHub will only show your token once. If you lose it, you'll need to generate a new one.</p>
                                    </div>
                                </div>
                            </li>

                            <li className="flex gap-3">
                                <span className="flex-shrink-0 w-6 h-6 rounded-full bg-primary-100 text-primary-700 flex items-center justify-center text-xs font-bold">
                                    6
                                </span>
                                <div className="flex-1">
                                    <p className="font-medium text-text-primary mb-1">Paste Token Below</p>
                                    <p>Paste your token in the input field and click "Save Token"</p>
                                    <p className="mt-1 text-xs text-success-700">Your token will be encrypted and stored securely</p>
                                </div>
                            </li>
                        </ol>
                    </div>

                    <div className="pt-4 border-t border-warm-200">
                        <h4 className="text-xs font-semibold text-text-primary mb-2">Security Best Practices</h4>
                        <ul className="text-xs text-text-secondary space-y-1">
                            <li>• Never share your token with anyone</li>
                            <li>• Use tokens with minimal required permissions</li>
                            <li>• Set an expiration date and rotate tokens regularly</li>
                            <li>• Revoke tokens immediately if compromised</li>
                        </ul>
                    </div>
                </div>
            )}
        </div>
    );
}
