'use client';

import React, { useState, useRef, useEffect, useMemo } from 'react';
import ReactMarkdown from 'react-markdown';
import { Send, Bot, User, Check, AlertTriangle, Code, X, ShieldAlert, Sparkles, AlertCircle, PanelRightClose, PanelRightOpen, FileDiff, Edit3, Save, RefreshCw } from 'lucide-react';
import { api } from '@/lib/matrix_api';
import { diffLines, Change } from 'diff';

interface HealChatProps {
  scanId: number; // Changed to number to match usage
  artifactId: string;
  artifactName: string;
  originalContent?: string; // Optional original content for diff
  isOpen: boolean;
  onClose: () => void;
  onApplyFix?: (fixCode: string) => void;
  isApplying?: boolean;
}

interface Message {
  role: 'user' | 'assistant';
  content: string;
  timestamp: Date;
}

type ViewMode = 'suggested' | 'diff' | 'edit';

// Optimization: Memoize code block renderer outside of the component to prevent re-renders
const CodeBlock = ({ className, children, onOpenPanel, ...props }: any) => {
  const match = /language-(\w+)/.exec(className || '');
  const content = String(children).replace(/\n$/, '');
  const isMultiLine = content.includes('\n');
  const shouldRenderInline = !isMultiLine && content.length < 80;

  if (shouldRenderInline) {
    return (
      <code className="bg-warm-200/50 text-accent-primary px-1.5 py-0.5 rounded-md font-mono text-[11px] font-bold border border-warm-200 mx-0.5" {...props}>
        {children}
      </code>
    );
  }

  // Check if this looks like a substantial code block that should be interactive
  if (content.length > 50) {
    return (
      <div
        onClick={() => onOpenPanel(content, match ? match[1] : 'text')}
        className="my-2 p-3 bg-warm-100 rounded-lg border border-warm-200 text-xs text-gray-500 italic flex items-center gap-2 cursor-pointer hover:bg-warm-200 transition-colors group"
      >
        <Code className="w-4 h-4 group-hover:text-accent-primary" />
        <span>
          Code snippet available in "Proposed Changes" panel.
          <span className="ml-2 font-bold text-accent-primary underline">Open Panel</span>
        </span>
      </div>
    );
  }

  return (
    <div className="relative group my-3">
      <pre className="bg-gray-50 text-gray-800 p-3 rounded-lg overflow-x-auto border border-warm-200 text-xs shadow-sm">
        <code className={className} {...props}>
          {children}
        </code>
      </pre>
    </div>
  );
};

// Utility to extract pure code from a potentially mixed AI response
const extractPureCode = (content: string) => {
  let clean = content;

  // 1. Remove Markdown code blocks if present
  if (content.includes('```')) {
    // Try to find the first large code block
    const match = content.match(/```(?:\w+)?\s*\n?([\s\S]*?)```/);
    if (match) clean = match[1];
  }

  // 2. Strip AI Reasoning headers if present (custom Matrix format)
  if (clean.includes('--- AI REASONING ---')) {
    const parts = clean.split(/--- AI REASONING ---|--- TECHNICAL EVIDENCE ---/);
    const potential = parts.find(p => p.trim().length > 50 && !p.trim().startsWith('{'));
    if (potential) clean = potential;
  }

  // 3. Last resort: If there are still "Proposed Fix:" style headers, trim them
  clean = clean.replace(/^(?:\*\*|#)?Proposed Fix:.*?\n/i, '');
  clean = clean.replace(/^(?:\*\*|#)?Corrected Code Block:.*?\n/i, '');

  return clean.trim();
};

export function HealChat({ scanId, artifactId, artifactName, originalContent, isOpen, onClose, onApplyFix, isApplying = false }: HealChatProps) {
  const [messages, setMessages] = useState<Message[]>([
    {
      role: 'assistant',
      content: `I'm ready to help you fix **${artifactName}**. You can ask me to explain the vulnerability or propose a fix.`,
      timestamp: new Date()
    }
  ]);
  const [input, setInput] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [suggestedFix, setSuggestedFix] = useState<string | null>(null);

  // New state for toggling code panel and active language
  const [isCodePanelOpen, setIsCodePanelOpen] = useState(false);
  const [activeLanguage, setActiveLanguage] = useState('python');

  // Advanced Code Interface State
  const [viewMode, setViewMode] = useState<ViewMode>('suggested');
  const [editContent, setEditContent] = useState('');
  const [diffChanges, setDiffChanges] = useState<Change[]>([]);

  const scrollRef = useRef<HTMLDivElement>(null);
  const messagesEndRef = useRef<HTMLDivElement>(null);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: "smooth" });
  };

  useEffect(() => {
    scrollToBottom();
  }, [messages, isLoading, isCodePanelOpen]);

  // When a suggested fix arrives, automatically open the panel
  useEffect(() => {
    if (suggestedFix) {
      setIsCodePanelOpen(true);

      const cleanFix = extractPureCode(suggestedFix);

      // AGGRESSIVE NORMALIZATION FOR COMPARISON
      const normalize = (str: string) => {
        if (!str) return '';
        return str
          .replace(/\r/g, '') // Normalize CRLF
          .split('\n')
          .map(line => {
            // Strip line numbers: "12: ", "12 | ", "12. ", "12  "
            let c = line.replace(/^\s*\d+[\s:|.]+\s*/, '');
            // Handle "12:code" (no space)
            c = c.replace(/^\s*\d+[:|]/, '');
            return c.trimEnd();
          })
          // Strip "file path" comments like "// extension/background.js" or "# path/to/file"
          // ONLY if they are at the very beginning of the string
          .filter((line, idx) => {
            const t = line.trim();
            if (idx < 3 && (t.startsWith('//') || t.startsWith('#')) && (t.includes('/') || t.includes('.'))) {
              return false;
            }
            return true;
          })
          .join('\n')
          .trim();
      };

      const normalizedFix = normalize(cleanFix);
      setEditContent(normalizedFix);

      if (originalContent) {
        let cleanOriginal = originalContent;
        try {
          if (originalContent.trim().startsWith('{')) {
            const parsed = JSON.parse(originalContent);
            cleanOriginal = parsed.evidence || parsed.code || parsed.source_code || parsed.raw_data || originalContent;
          }
        } catch (e) { }

        const normalizedOriginal = normalize(cleanOriginal);

        // Use diffLines with ignoreWhitespace: true for maximum tolerance
        const changes = diffLines(normalizedOriginal, normalizedFix, {
          ignoreWhitespace: true
        });
        setDiffChanges(changes);
      }
    }
  }, [suggestedFix, originalContent]);

  const handleSendMessage = async () => {
    if (!input.trim() || isLoading) return;

    const userMsg: Message = { role: 'user', content: input, timestamp: new Date() };
    // Optimistic update
    setMessages(prev => [...prev, userMsg]);
    setInput('');
    setIsLoading(true);

    try {
      const history = messages.map(m => ({ role: m.role, content: m.content }));
      const response = await api.chatAboutArtifact(scanId, artifactId, userMsg.content, history);

      const aiMsg: Message = { role: 'assistant', content: response.response, timestamp: new Date() };
      setMessages(prev => [...prev, aiMsg]);

      if (response.suggested_fix) {
        // Clean the fix before setting it to ensure side panel is code-only
        const pureCode = extractPureCode(response.suggested_fix);
        setSuggestedFix(pureCode);
        // Do NOT automatically open panel to keep flow smooth, let user choose
      }
    } catch (error) {
      console.error("Chat error:", error);
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "I encountered an error connecting to the Matrix engine. Please try again.",
        timestamp: new Date()
      }]);
    } finally {
      setIsLoading(false);
    }
  };

  const handleOpenCodePanel = (code: string, language: string) => {
    setSuggestedFix(code);
    setEditContent(code);
    setActiveLanguage(language);
    setIsCodePanelOpen(true);

    // Calculate Diff Immediately
    if (originalContent) {
      // ... (Same normalization logic as before, but consolidated)
      const normalize = (str: string) => str.replace(/\r/g, '').split('\n').map(l => l.trimEnd()).join('\n').trim();
      const changes = diffLines(normalize(originalContent), normalize(code), { ignoreWhitespace: true });
      setDiffChanges(changes);
    }
  };

  // Memoized Components for ReactMarkdown to prevent re-renders
  const markdownComponents = useMemo(() => ({
    code: ({ node, inline, className, children, ...props }: any) => (
      <CodeBlock
        className={className}
        inline={inline}
        onOpenPanel={handleOpenCodePanel}
        {...props}
      >
        {children}
      </CodeBlock>
    )
  }), [originalContent]); // Re-create only if originalContent changes (unlikely)

  const handleSaveEdit = () => {
    const newFix = editContent;
    setSuggestedFix(newFix);
    setViewMode('suggested');

    const normalize = (str: string) => {
      return str.replace(/\r/g, '').split('\n').map(l => l.trimEnd()).join('\n').trim();
    };

    const normalizedFix = normalize(newFix);

    if (originalContent) {
      let cleanOriginal = originalContent;
      try {
        if (originalContent.trim().startsWith('{')) {
          const parsed = JSON.parse(originalContent);
          cleanOriginal = parsed.evidence || parsed.code || originalContent;
        }
      } catch (e) { }

      const normalizedOriginal = normalize(cleanOriginal);
      const changes = diffLines(normalizedOriginal, normalizedFix, { ignoreWhitespace: true });
      setDiffChanges(changes);
    }
  };

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/60 backdrop-blur-sm p-4 animate-fade-in">
      <div className={`bg-white rounded-2xl w-full h-[85vh] flex overflow-hidden shadow-2xl animate-scale-in border border-warm-200 ring-4 ring-black/5 transition-all duration-500 ease-spring ${isCodePanelOpen ? 'max-w-[95vw]' : 'max-w-5xl'
        }`}>

        {/* Chat Section */}
        <div className={`flex flex-col ${isCodePanelOpen ? 'w-[45%] border-r border-warm-200 min-w-[400px]' : 'w-full'} transition-all duration-500 ease-spring relative`}>

          {/* Header */}
          <div className="px-6 py-4 border-b border-warm-200 flex justify-between items-center bg-gradient-to-r from-warm-50 to-white">
            <div className="flex items-center gap-4">
              <div className="relative">
                <div className="w-10 h-10 rounded-xl bg-accent-primary flex items-center justify-center shadow-lg shadow-accent-primary/20">
                  <Bot className="w-6 h-6 text-white" />
                </div>
                <div className="absolute -bottom-1 -right-1 w-4 h-4 bg-green-500 border-2 border-white rounded-full animate-pulse" />
              </div>
              <div>
                <h3 className="font-bold text-gray-900 text-lg flex items-center gap-2">
                  Remediation Assistant
                  <span className="px-2 py-0.5 bg-accent-primary/10 text-accent-primary text-[10px] font-bold uppercase tracking-wider rounded-full border border-accent-primary/20">Beta</span>
                </h3>
                <p className="text-xs text-gray-500 line-clamp-1 font-medium flex items-center gap-1.5">
                  <ShieldAlert className="w-3 h-3 text-red-500" />
                  {artifactName}
                </p>
              </div>
            </div>

            <div className="flex items-center gap-2">
              {/* Toggle Code Panel Button */}
              {suggestedFix && (
                <button
                  onClick={() => setIsCodePanelOpen(!isCodePanelOpen)}
                  className={`p-2 rounded-xl text-gray-400 hover:text-accent-primary hover:bg-accent-primary/5 transition-all duration-200 group flex items-center gap-2 ${isCodePanelOpen ? 'bg-accent-primary/5 text-accent-primary' : ''}`}
                  title={isCodePanelOpen ? "Close Code Panel" : "Open Code Panel"}
                >
                  {isCodePanelOpen ? <PanelRightClose className="w-5 h-5" /> : <PanelRightOpen className="w-5 h-5" />}
                  {!isCodePanelOpen && <span className="text-xs font-bold">Open Code</span>}
                </button>
              )}

              <button
                onClick={onClose}
                className="p-2 hover:bg-red-50 hover:text-red-500 rounded-xl text-gray-400 transition-all duration-200 group"
              >
                <X className="w-5 h-5 group-hover:scale-110 transition-transform" />
              </button>
            </div>
          </div>

          {/* Messages */}
          <div className="flex-1 overflow-y-auto p-6 space-y-6 bg-warm-50/30 scroll-smooth" ref={scrollRef}>
            {messages.map((msg, i) => (
              <div key={i} className={`flex ${msg.role === 'user' ? 'justify-end' : 'justify-start'} animate-fade-in-up`}>
                <div className={`flex gap-3 max-w-[90%] ${msg.role === 'user' ? 'flex-row-reverse' : ''}`}>
                  <div className={`w-8 h-8 rounded-lg flex-shrink-0 flex items-center justify-center shadow-sm ${msg.role === 'user' ? 'bg-warm-200' : 'bg-white border border-warm-200'
                    }`}>
                    {msg.role === 'user' ? <User className="w-4 h-4 text-warm-600" /> : <Bot className="w-4 h-4 text-accent-primary" />}
                  </div>
                  <div className={`p-4 rounded-2xl text-sm leading-relaxed shadow-sm ${msg.role === 'user'
                    ? 'bg-accent-primary text-white rounded-tr-none shadow-accent-primary/20'
                    : 'bg-white border border-warm-200 text-gray-700 rounded-tl-none'
                    }`}>
                    <div className={`prose prose-sm max-w-none break-words ${msg.role === 'user'
                      ? 'prose-invert prose-p:text-white prose-headings:text-white'
                      : 'prose-headings:text-gray-900 prose-p:text-gray-700'
                      }`}>
                      <ReactMarkdown components={markdownComponents}>
                        {msg.content}
                      </ReactMarkdown>
                    </div>
                    <div className={`text-[10px] mt-2 font-medium opacity-60 ${msg.role === 'user' ? 'text-blue-100' : 'text-gray-400'}`}>
                      {msg.timestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}
                    </div>
                  </div>
                </div>
              </div>
            ))}
            {isLoading && (
              <div className="flex justify-start animate-fade-in">
                <div className="flex gap-3">
                  <div className="w-8 h-8 rounded-lg bg-white border border-warm-200 flex items-center justify-center shadow-sm">
                    <Bot className="w-4 h-4 text-accent-primary animate-pulse" />
                  </div>
                  <div className="bg-white border border-warm-200 p-4 rounded-2xl rounded-tl-none shadow-sm flex items-center gap-2">
                    <div className="w-2 h-2 bg-accent-primary rounded-full animate-bounce" style={{ animationDelay: '0s' }} />
                    <div className="w-2 h-2 bg-accent-primary rounded-full animate-bounce" style={{ animationDelay: '0.15s' }} />
                    <div className="w-2 h-2 bg-accent-primary rounded-full animate-bounce" style={{ animationDelay: '0.3s' }} />
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          {/* Input */}
          <div className="p-4 bg-white border-t border-warm-200 shadow-[0_-4px_20px_-10px_rgba(0,0,0,0.05)]">
            <div className="relative flex items-center gap-2">
              <input
                type="text"
                value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleSendMessage()}
                placeholder="Message Matrix Security AI..."
                className="w-full pl-5 pr-12 py-4 bg-warm-50/50 border border-warm-200 rounded-xl focus:border-accent-primary focus:ring-4 focus:ring-accent-primary/5 outline-none transition-all placeholder:text-warm-400 text-gray-700"
                disabled={isLoading}
              />
              <button
                onClick={handleSendMessage}
                disabled={!input.trim() || isLoading}
                className="absolute right-2 p-2.5 bg-accent-primary text-white rounded-lg shadow-lg shadow-accent-primary/20 hover:scale-105 active:scale-95 disabled:opacity-50 disabled:hover:scale-100 disabled:shadow-none transition-all duration-200"
              >
                <Send className="w-4 h-4" />
              </button>
            </div>
            <div className="mt-2 text-center">
              <p className="text-[10px] text-warm-400 font-medium flex items-center justify-center gap-1.5">
                <Sparkles className="w-3 h-3" />
                AI-Generated responses may require verification
              </p>
            </div>
          </div>
        </div>

        {/* Code Preview Section (Visible when fix is suggested AND panel is open) */}
        {suggestedFix && isCodePanelOpen && (
          <div className="w-[55%] flex flex-col bg-[#0d1117] text-white animate-fade-in-right border-l border-warm-200/20">
            {/* Code Panel Header */}
            <div className="px-6 py-4 border-b border-white/10 flex justify-between items-center bg-[#161b22]">
              <div className="flex items-center gap-6">
                {/* View Toggles */}
                <div className="flex items-center bg-white/5 rounded-lg p-1 border border-white/10">
                  <button
                    onClick={() => setViewMode('suggested')}
                    className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2 ${viewMode === 'suggested' ? 'bg-accent-primary text-white shadow-lg' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}
                  >
                    <Code className="w-3 h-3" /> Code
                  </button>
                  <button
                    onClick={() => setViewMode('diff')}
                    disabled={!originalContent}
                    className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2 ${viewMode === 'diff' ? 'bg-accent-primary text-white shadow-lg' : 'text-gray-400 hover:text-white hover:bg-white/5 disabled:opacity-30 disabled:hover:bg-transparent'}`}
                    title={!originalContent ? "Original content not available for diff" : "View Changes"}
                  >
                    <FileDiff className="w-3 h-3" /> Diff
                  </button>
                  <button
                    onClick={() => setViewMode('edit')}
                    className={`px-3 py-1.5 rounded-md text-xs font-bold transition-all flex items-center gap-2 ${viewMode === 'edit' ? 'bg-accent-primary text-white shadow-lg' : 'text-gray-400 hover:text-white hover:bg-white/5'}`}
                  >
                    <Edit3 className="w-3 h-3" /> Edit
                  </button>
                </div>
              </div>

              <div className="flex items-center gap-2">
                <button
                  onClick={() => setIsCodePanelOpen(false)}
                  className="p-2 hover:bg-white/10 rounded-lg text-gray-400 transition-colors"
                  title="Close Panel"
                >
                  <PanelRightClose className="w-4 h-4" />
                </button>
                <button
                  onClick={() => onApplyFix && onApplyFix(suggestedFix)}
                  disabled={isApplying}
                  className={`px-5 py-2.5 rounded-lg text-xs font-bold flex items-center gap-2 transition-all shadow-lg ring-1 ring-white/10 ${isApplying
                    ? 'bg-green-700 cursor-not-allowed opacity-80'
                    : 'bg-green-600 hover:bg-green-500 hover:ring-white/30 shadow-green-900/20'
                    }`}
                >
                  {isApplying ? (
                    <>
                      <RefreshCw className="w-4 h-4 animate-spin" />
                      APPLYING...
                    </>
                  ) : (
                    <>
                      <Check className="w-4 h-4" />
                      APPLY FIX
                    </>
                  )}
                </button>
              </div>
            </div>

            {/* Code Content Area */}
            <div className="flex-1 overflow-auto p-0 scrollbar-dark bg-[#0d1117] relative">

              {/* SUGGESTED VIEW */}
              {viewMode === 'suggested' && (
                <pre className="p-6 font-mono text-sm leading-relaxed tab-4 text-gray-300">
                  <code className={`language-${activeLanguage} block w-full`}>{suggestedFix}</code>
                </pre>
              )}

              {/* DIFF VIEW */}
              {viewMode === 'diff' && (
                <div className="font-mono text-[11px] leading-tight flex flex-col min-w-full">
                  {(() => {
                    let leftLine = 1;
                    let rightLine = 1;
                    return diffChanges.map((part, i) => {
                      const lines = part.value.split('\n');
                      // Handle the case where the last line is empty due to a trailing newline
                      const displayLines = lines.length > 1 && lines[lines.length - 1] === '' ? lines.slice(0, -1) : lines;

                      return displayLines.map((line, j) => {
                        const isAdded = part.added;
                        const isRemoved = part.removed;

                        const curLeft = isAdded ? '' : leftLine++;
                        const curRight = isRemoved ? '' : rightLine++;
                        const sign = isAdded ? '+' : isRemoved ? '-' : ' ';

                        const bgClass = isAdded ? 'bg-green-500/10 text-green-200' : isRemoved ? 'bg-red-500/10 text-red-300 opacity-70' : 'text-gray-400 hover:bg-white/5';
                        const indicatorClass = isAdded ? 'text-green-500' : isRemoved ? 'text-red-500' : 'text-gray-600';

                        return (
                          <div key={`${i}-${j}`} className={`flex w-full border-b border-white/[0.02] group ${bgClass}`}>
                            <div className="w-[40px] shrink-0 text-right pr-3 py-1 select-none opacity-30 border-r border-white/10 text-[10px]">
                              {curLeft}
                            </div>
                            <div className="w-[40px] shrink-0 text-right pr-3 py-1 select-none opacity-30 border-r border-white/10 text-[10px]">
                              {curRight}
                            </div>
                            <div className={`w-[24px] shrink-0 text-center py-1 select-none font-bold ${indicatorClass}`}>
                              {sign}
                            </div>
                            <div className="flex-1 py-1 px-4 whitespace-pre overflow-x-auto custom-scrollbar-mini">
                              {line || ' '}
                            </div>
                          </div>
                        );
                      });
                    });
                  })()}
                  {!originalContent && (
                    <div className="p-10 text-center text-gray-500 italic">
                      Original content not available for diff comparison.
                    </div>
                  )}
                </div>
              )}

              {/* EDIT VIEW */}
              {viewMode === 'edit' && (
                <div className="h-full flex flex-col">
                  <textarea
                    value={editContent}
                    onChange={(e) => setEditContent(e.target.value)}
                    className="flex-1 w-full bg-[#0d1117] text-gray-300 p-6 font-mono text-sm leading-relaxed resize-none focus:outline-none focus:ring-0 border-none"
                    spellCheck={false}
                  />
                  <div className="p-4 border-t border-white/10 bg-[#161b22] flex justify-end gap-3 sticky bottom-0">
                    <button
                      onClick={() => {
                        setEditContent(suggestedFix); // Reset
                      }}
                      className="px-4 py-2 text-xs font-bold text-gray-400 hover:text-white hover:bg-white/10 rounded-lg transition-all flex items-center gap-2"
                    >
                      <RefreshCw className="w-3 h-3" /> Reset
                    </button>
                    <button
                      onClick={handleSaveEdit}
                      className="px-4 py-2 text-xs font-bold bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-all shadow-lg shadow-blue-900/20 flex items-center gap-2"
                    >
                      <Save className="w-3 h-3" /> Save Changes
                    </button>
                  </div>
                </div>
              )}

            </div>

            {/* Footer / Context Info */}
            {viewMode !== 'edit' && (
              <div className="p-4 bg-blue-500/10 border-t border-blue-500/20 text-xs text-blue-200/90 flex items-start gap-3 backdrop-blur-sm">
                <AlertCircle className="w-5 h-5 shrink-0 text-blue-400" />
                <div className="space-y-1">
                  <p className="font-bold text-blue-100">Review Required</p>
                  <p className="leading-relaxed opacity-80">
                    This code was generated by Matrix AI. Clicking "Apply Fix" will create a new branch, push this code, and open a Pull Request for peer review.
                  </p>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
