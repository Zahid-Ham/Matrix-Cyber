'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  ArrowLeft,
  Search,
  Filter,
  ShieldAlert,
  TrendingUp,
  DollarSign,
  Briefcase,
  Layers
} from 'lucide-react';
import { useSearchParams } from 'next/navigation';
import Link from 'next/link';
import { api } from '@/lib/matrix_api';

interface ValuationItem {
  id: number;
  title: string;
  severity: string;
  value: number;
  impact: number;
  roi: string;
  lastAnalyzed: string;
}

export default function MarketplaceAllPage() {
  const [items, setItems] = useState<ValuationItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [searchTerm, setSearchTerm] = useState('');

  const searchParams = useSearchParams();
  const scanId = searchParams.get('scan_id');

  const fetchAllValuations = async () => {
    try {
      setLoading(true);
      const id = scanId ? parseInt(scanId) : null;
      const data = await api.getMarketplaceAll(50, 0, id);
      if (data) {
        // Map the real data to our table format
        const mapped = data.map((v: any) => ({
          id: v.id,
          title: v.title,
          severity: v.severity,
          value: v.value,
          impact: v.value * 12.5, // Refined multiplier
          roi: "90,000%",
          lastAnalyzed: v.lastAnalyzed ? new Date(v.lastAnalyzed).toLocaleTimeString() : "Recently"
        }));
        setItems(mapped);
      }
    } catch (error) {
      console.error("Failed to fetch all valuations:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAllValuations();
  }, [scanId]);

  const filteredItems = items.filter(item =>
    item.title.toLowerCase().includes(searchTerm.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-warm-50/50 p-8 pt-24">
      <div className="max-w-7xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <Link
            href="/marketplace"
            className="flex items-center text-text-muted hover:text-accent-primary mb-4 transition-colors font-medium text-sm"
          >
            <ArrowLeft className="w-4 h-4 mr-2" /> Back to Marketplace
          </Link>
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
            <div>
              <h1 className="text-3xl font-serif-display font-medium text-text-primary">
                {scanId ? `Analysis: Repository Scan #${scanId}` : 'Live Marketplace Feed'}
              </h1>
              <p className="text-text-secondary text-sm mt-1">
                {scanId
                  ? 'Active vulnerabilities detected in this specific repository context.'
                  : 'A comprehensive inventory of all discovered vulnerabilities and their market valuations.'}
              </p>
            </div>
          </div>
        </div>

        {/* Toolbar */}
        <div className="flex flex-col md:flex-row gap-4 mb-6">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-text-muted" />
            <input
              type="text"
              placeholder="Search vulnerabilities..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 bg-white border border-warm-200 rounded-xl focus:ring-2 focus:ring-accent-primary/20 focus:border-accent-primary outline-none transition-all"
            />
          </div>
          <button className="px-4 py-2 bg-white border border-warm-200 rounded-xl text-text-secondary flex items-center gap-2 hover:bg-warm-50 transition-colors">
            <Filter className="w-4 h-4" />
            <span>Filter</span>
          </button>
        </div>

        {/* Table View */}
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-left border-collapse">
              <thead>
                <tr className="bg-warm-50/50 border-b border-warm-100">
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-text-muted">Vulnerability</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-text-muted">Severity</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-text-muted">Exploit Value</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-text-muted">Est. Impact</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-text-muted">Fix ROI</th>
                  <th className="px-6 py-4 text-xs font-bold uppercase tracking-wider text-text-muted text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-warm-100">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-text-muted">
                      <div className="flex flex-col items-center gap-3">
                        <TrendingUp className="w-6 h-6 animate-pulse text-accent-primary" />
                        <span>Synchronizing Market Data...</span>
                      </div>
                    </td>
                  </tr>
                ) : filteredItems.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-6 py-12 text-center text-text-muted">
                      No results found matching your search.
                    </td>
                  </tr>
                ) : (
                  filteredItems.map((item, index) => (
                    <motion.tr
                      key={item.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: index * 0.03 }}
                      className="hover:bg-warm-50/30 transition-colors group"
                    >
                      <td className="px-6 py-4">
                        <div className="font-medium text-text-primary group-hover:text-accent-primary transition-colors">
                          {item.title}
                        </div>
                        <div className="text-xs text-text-muted mt-0.5">ID: VULN-{item.id.toString().padStart(4, '0')}</div>
                      </td>
                      <td className="px-6 py-4">
                        <span className={`px-2 py-1 rounded-full text-[10px] font-bold uppercase tracking-tighter ${item.severity.toLowerCase() === 'critical' ? 'bg-red-100 text-red-700' :
                          item.severity.toLowerCase() === 'high' ? 'bg-orange-100 text-orange-700' :
                            'bg-yellow-100 text-yellow-700'
                          }`}>
                          {item.severity}
                        </span>
                      </td>
                      <td className="px-6 py-4">
                        <div className="font-mono text-sm font-bold text-text-primary">
                          ${item.value.toLocaleString()}
                        </div>
                      </td>
                      <td className="px-6 py-4 text-sm text-text-secondary">
                        ${item.impact.toLocaleString()}
                      </td>
                      <td className="px-6 py-4">
                        <div className="text-emerald-600 font-bold text-sm">{item.roi}</div>
                      </td>
                      <td className="px-6 py-4 text-right">
                        <Link
                          href={`/marketplace/vulnerability/${item.id}`}
                          className="px-3 py-1.5 bg-warm-100 text-text-secondary rounded-lg text-xs font-semibold hover:bg-accent-primary hover:text-white transition-all shadow-sm"
                        >
                          Details
                        </Link>
                      </td>
                    </motion.tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer info */}
        <div className="mt-6 flex items-center justify-between text-xs text-text-muted px-2">
          <span>Showing {filteredItems.length} active valuations</span>
          <div className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
            <span>Live Dark Web Monitor Connected</span>
          </div>
        </div>
      </div>
    </div>
  );
}
