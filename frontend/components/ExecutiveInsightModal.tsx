'use client';

import React, { useState, useEffect } from 'react';
import { createPortal } from 'react-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Info, X, Loader2 } from 'lucide-react';
import ReactMarkdown from 'react-markdown';
import { api } from '@/lib/matrix_api';

interface ExecutiveInsightModalProps {
  isOpen: boolean;
  onClose: () => void;
  vulnerabilityId?: number;
  scanId?: number;
  title?: string;
}

export function ExecutiveInsightModal({
  isOpen,
  onClose,
  vulnerabilityId,
  scanId,
  title = "Executive Insight"
}: ExecutiveInsightModalProps) {
  const [explanation, setExplanation] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
    if (isOpen) {
      document.body.style.overflow = 'hidden';
      fetchExplanation();
    } else {
      document.body.style.overflow = 'unset';
      setExplanation(null);
      setError(null);
    }
    return () => {
      document.body.style.overflow = 'unset';
    };
  }, [isOpen, vulnerabilityId, scanId]);

  const fetchExplanation = async () => {
    setLoading(true);
    setError(null);
    try {
      let response;
      if (vulnerabilityId) {
        response = await api.getMarketplaceExplanation(vulnerabilityId);
        setExplanation(response.explanation);
      } else if (scanId) {
        const res = await api.getScanExplanation(scanId);
        setExplanation(res.explanation);
      }
    } catch (err: any) {
      console.error("Failed to fetch explanation", err);
      setError("I'm sorry, I couldn't generate an architectural explanation right now. Please verify service connectivity and try again.");
    } finally {
      setLoading(false);
    }
  };

  if (!mounted) return null;

  const modalContent = (
    <AnimatePresence>
      {isOpen && (
        <div className="fixed inset-0 z-[9999] flex items-center justify-center p-4 bg-black/70 backdrop-blur-xl">
          <motion.div
            initial={{ opacity: 0, scale: 0.9, y: 20 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.95, y: 10 }}
            className="bg-white max-w-4xl w-full max-h-[90vh] flex flex-col relative shadow-[0_0_50px_rgba(0,0,0,0.3)] rounded-3xl overflow-hidden border border-warm-200"
          >
            {/* Header */}
            <div className="p-8 pb-6 border-b border-warm-100 flex items-center justify-between bg-bg-secondary">
              <div className="flex items-center gap-4">
                <div className="w-12 h-12 rounded-2xl bg-accent-primary/10 flex items-center justify-center shadow-inner">
                  <Info className="w-7 h-7 text-accent-primary" />
                </div>
                <div>
                  <h2 className="text-2xl font-serif-display font-bold text-text-primary leading-tight">{title}</h2>
                  <p className="text-sm text-text-muted mt-0.5">Matrix AI Strategic Risk Analysis</p>
                </div>
              </div>
              <button
                onClick={onClose}
                className="text-text-muted hover:text-text-primary transition-colors p-2 hover:bg-warm-100 rounded-full"
              >
                <X className="w-6 h-6" />
              </button>
            </div>

            {/* Scrollable Content */}
            <div className="flex-1 overflow-y-auto p-8 custom-scrollbar bg-white">
              {loading ? (
                <div className="space-y-8 py-6">
                  <div className="flex items-center gap-3 text-accent-primary animate-pulse">
                    <div className="w-5 h-5 border-2 border-accent-primary border-t-transparent rounded-full animate-spin" />
                    <span className="font-medium text-lg">Synthesizing Security Intelligence...</span>
                  </div>

                  <div className="space-y-6">
                    <div className="h-7 bg-warm-200/60 rounded-lg animate-pulse w-2/3" />
                    <div className="space-y-3">
                      <div className="h-4 bg-warm-100/80 rounded animate-pulse w-full" />
                      <div className="h-4 bg-warm-100/80 rounded animate-pulse w-11/12" />
                      <div className="h-4 bg-warm-100/80 rounded animate-pulse w-4/5" />
                    </div>
                  </div>

                  <div className="space-y-6">
                    <div className="h-7 bg-warm-200/60 rounded-lg animate-pulse w-1/2" />
                    <div className="space-y-3">
                      <div className="h-4 bg-warm-100/80 rounded animate-pulse w-full" />
                      <div className="h-4 bg-warm-100/80 rounded animate-pulse w-11/12" />
                      <div className="h-4 bg-warm-100/80 rounded animate-pulse w-full" />
                    </div>
                  </div>
                </div>
              ) : error ? (
                <div className="p-12 text-center">
                  <X className="w-12 h-12 text-red-400 mx-auto mb-4 opacity-40" />
                  <p className="text-text-secondary italic">{error}</p>
                  <button
                    onClick={fetchExplanation}
                    className="mt-6 text-sm font-bold text-accent-primary hover:underline"
                  >
                    Try Reconnaissance Again
                  </button>
                </div>
              ) : (
                <motion.div
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: 0.2 }}
                  className="prose prose-slate prose-lg max-w-none 
                                        prose-headings:font-serif-display prose-headings:text-text-primary prose-headings:mb-4 prose-headings:mt-8
                                        prose-p:text-text-secondary prose-p:leading-relaxed prose-p:mb-6
                                        prose-strong:text-accent-primary prose-strong:font-bold
                                        prose-ul:list-disc prose-ul:pl-6 prose-ul:mb-6
                                        prose-li:text-text-secondary prose-li:mb-2
                                        prose-h3:text-xl prose-h3:border-b prose-h3:border-accent-primary/20 prose-h3:pb-2 prose-h3:text-accent-primary"
                >
                  <ReactMarkdown>{explanation || ''}</ReactMarkdown>
                </motion.div>
              )}
            </div>

            {/* Footer */}
            <div className="p-8 py-6 bg-bg-secondary border-t border-warm-100 flex justify-between items-center">
              <div className="flex items-center gap-2 text-sm text-text-muted">
                <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                Neural Engine Online
              </div>
              <button
                onClick={onClose}
                className="btn-primary px-12 py-3.5 rounded-2xl text-base font-bold shadow-xl shadow-accent-primary/20 hover:scale-[1.02] active:scale-[0.98] transition-all"
              >
                Understood
              </button>
            </div>
          </motion.div>
        </div>
      )}
    </AnimatePresence>
  );

  return createPortal(modalContent, document.body);
}
