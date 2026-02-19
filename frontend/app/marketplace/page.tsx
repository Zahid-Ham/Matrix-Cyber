'use client';

import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import {
  DollarSign,
  TrendingUp,
  ShieldAlert,
  Activity,
  ArrowRight,
  Search,
  Filter,
  Download,
  Info
} from 'lucide-react';
import Link from 'next/link';
import { api } from '@/lib/matrix_api';
import { Navbar } from '../../components/Navbar';
import { ProtectedRoute } from '../../components/ProtectedRoute';

interface MarketStats {
  summary: {
    totalDarkWebValue: number;
    totalFinancialImpact: number;
    vulnerabilityCount: number;
    criticalCount: number;
    highestValueVuln: {
      id: number;
      title: string;
      severity: string;
      value: number;
    } | null;
  };
  top5ByValue: Array<{
    id: number;
    title: string;
    severity: string;
    value: number;
  }>;
}

export default function MarketplacePage() {
  const [stats, setStats] = useState<MarketStats | null>(null);
  const [loading, setLoading] = useState(true);

  const fetchStats = async () => {
    try {
      setLoading(true);
      const data = await api.getMarketplaceDashboard();
      setStats(data);
    } catch (error) {
      console.error("Failed to fetch marketplace stats:", error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchStats();
  }, []);

  // Comparison/Trend Logic (Simulated for Demo based on real values)
  const totalValue = stats?.summary.totalDarkWebValue || 0;
  const avgPrice = stats?.summary.vulnerabilityCount ? (totalValue / stats.summary.vulnerabilityCount) : 0;
  const highDemand = (stats?.summary.criticalCount || 0) + (stats?.summary.highestValueVuln ? 1 : 0); // Simplified metric

  const marketCards = [
    { label: 'Total Market Value', value: `$${totalValue.toLocaleString()}`, change: '+12%', trend: 'up' },
    { label: 'Avg. Exploit Price', value: `$${Math.round(avgPrice).toLocaleString()}`, change: '-5%', trend: 'down' },
    { label: 'High Demand Assets', value: highDemand.toString(), change: '+2', trend: 'up' },
    { label: 'Active Dark Web Agents', value: '156', change: '+8%', trend: 'up' }, // Simulated agent count
  ];

  return (
    <ProtectedRoute>
      <div className="min-h-screen bg-bg-primary pattern-bg">
        <Navbar />
        <div className="max-w-7xl mx-auto p-8 pt-32 space-y-12">
          {/* Header Section */}
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="max-w-7xl mx-auto"
          >
            <div className="flex flex-col md:flex-row md:items-end justify-between gap-6 mb-12">
              <div>
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse" />
                  <span className="text-[10px] uppercase tracking-[0.3em] text-emerald-600 font-bold">Live Data Stream Active</span>
                </div>
                <h1 className="text-5xl font-serif-display font-medium text-text-primary tracking-tight">Marketplace</h1>
                <p className="text-text-secondary mt-3 max-w-xl text-lg opacity-80 leading-relaxed">
                  Real-time monitoring of dark web trade activity, exploit pricing trends, and projected financial exposure for your infrastructure.
                </p>
              </div>
              <div className="flex items-center gap-4">
                <Link href="/marketplace/all" className="px-6 py-3 rounded-xl border border-warm-200 bg-white shadow-sm hover:shadow-md hover:border-accent-primary/30 transition-all font-bold text-sm text-text-secondary">
                  View Detailed Feed
                </Link>
                <div
                  onClick={fetchStats}
                  className="px-6 py-3 rounded-xl bg-accent-primary text-white shadow-lg shadow-accent-primary/20 font-bold text-sm flex items-center gap-2 cursor-pointer hover:scale-[1.02] transition-transform"
                >
                  Refresh Nodes <Activity className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
                </div>
              </div>
            </div>

            {/* Stats Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6 mb-12">
              <div className="glass-card p-8 bg-gradient-to-br from-white/80 to-accent-primary/5 border-l-4 border-l-accent-primary hover:shadow-xl transition-all group">
                <div className="flex items-center justify-between mb-6">
                  <div className="w-12 h-12 rounded-2xl bg-accent-primary/10 flex items-center justify-center group-hover:bg-accent-primary group-hover:text-white transition-colors">
                    <ShieldAlert className="w-6 h-6 text-accent-primary group-hover:text-white" />
                  </div>
                  <TrendingUp className="w-4 h-4 text-emerald-500" />
                </div>
                <div className="text-[10px] uppercase tracking-[0.2em] text-text-muted font-bold mb-1">Live Valuations</div>
                <div className="text-3xl font-serif-display font-medium text-text-primary">
                  {stats?.summary?.vulnerabilityCount || 0}
                </div>
              </div>

              <div className="glass-card p-8 bg-gradient-to-br from-white/80 to-emerald-500/5 border-l-4 border-l-emerald-500 hover:shadow-xl transition-all group">
                <div className="flex items-center justify-between mb-6">
                  <div className="w-12 h-12 rounded-2xl bg-emerald-500/10 flex items-center justify-center group-hover:bg-emerald-500 group-hover:text-white transition-colors">
                    <DollarSign className="w-6 h-6 text-emerald-500 group-hover:text-white" />
                  </div>
                  <TrendingUp className="w-4 h-4 text-emerald-500" />
                </div>
                <div className="text-[10px] uppercase tracking-[0.2em] text-text-muted font-bold mb-1">Market Exposure</div>
                <div className="text-3xl font-serif-display font-medium text-emerald-600">
                  ${(stats?.summary?.totalDarkWebValue || 0).toLocaleString()}
                </div>
              </div>

              <div className="glass-card p-8 bg-gradient-to-br from-white/80 to-red-500/5 border-l-4 border-l-red-500 hover:shadow-xl transition-all group">
                <div className="flex items-center justify-between mb-6">
                  <div className="w-12 h-12 rounded-2xl bg-red-500/10 flex items-center justify-center group-hover:bg-red-500 group-hover:text-white transition-colors">
                    <TrendingUp className="w-6 h-6 text-red-500 group-hover:text-white" />
                  </div>
                  <div className="text-[9px] font-bold text-red-600 uppercase tracking-widest bg-red-50 px-2 py-0.5 rounded">Risk Peak</div>
                </div>
                <div className="text-[10px] uppercase tracking-[0.2em] text-text-muted font-bold mb-1">Implied Impact</div>
                <div className="text-3xl font-serif-display font-medium text-red-600">
                  ${(stats?.summary?.totalFinancialImpact || 0).toLocaleString()}
                </div>
              </div>

              <div className="glass-card p-8 bg-gradient-to-br from-white/80 to-amber-500/5 border-l-4 border-l-amber-500 hover:shadow-xl transition-all group">
                <div className="flex items-center justify-between mb-6">
                  <div className="w-12 h-12 rounded-2xl bg-amber-500/10 flex items-center justify-center group-hover:bg-amber-500 group-hover:text-white transition-colors">
                    <Activity className="w-6 h-6 text-amber-500 group-hover:text-white" />
                  </div>
                  <div className="flex -space-x-1">
                    {[1, 2, 3].map(i => <div key={i} className="w-5 h-5 rounded-full border-2 border-white bg-warm-200" />)}
                  </div>
                </div>
                <div className="text-[10px] uppercase tracking-[0.2em] text-text-muted font-bold mb-1">Active Bidders</div>
                <div className="text-3xl font-serif-display font-medium text-text-primary">156</div>
              </div>
            </div>

            {/* Main Content Grid */}
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
              {/* Left Column: Recent Valuations */}
              <div className="lg:col-span-2 space-y-6">
                <div className="glass-card p-6">
                  <div className="flex items-center justify-between mb-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 bg-accent-primary/10 rounded-lg">
                        <DollarSign className="w-5 h-5 text-accent-primary" />
                      </div>
                      <h3 className="text-xl font-serif-display font-medium text-text-primary">Recent Valuations</h3>
                    </div>
                    {/* Search & Filter - keeping static for now as we just show top 5 */}
                  </div>

                  <div className="space-y-4">
                    {loading ? (
                      <div className="flex flex-col items-center justify-center p-20 gap-4">
                        <div className="w-10 h-10 rounded-full border-2 border-accent-primary/20 border-t-accent-primary animate-spin" />
                        <p className="text-sm text-text-muted font-serif italic">Synchronizing Marketplace Node...</p>
                      </div>
                    ) : stats?.top5ByValue.length === 0 ? (
                      <div className="p-12 text-center border-2 border-dashed border-warm-200 rounded-2xl">
                        <p className="text-text-muted italic">No active nodes identified for valuation. Initiate a high-fidelity scan to proceed.</p>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {stats?.top5ByValue.map((item, index) => (
                          <Link
                            key={item.id}
                            href={`/marketplace/vulnerability/${item.id}`}
                            className="group block"
                          >
                            <div className="glass-card p-6 bg-white/60 hover:bg-white hover:shadow-xl hover:-translate-y-1 transition-all duration-300 border border-warm-200/50 hover:border-emerald-500/30 relative overflow-hidden">
                              <div className="absolute left-0 top-0 bottom-0 w-1 bg-emerald-500/20 group-hover:bg-emerald-500 transition-colors" />
                              <div className="flex items-center justify-between mb-4">
                                <div className="flex items-center gap-4">
                                  <span className={`px-2 py-0.5 rounded text-[9px] font-bold uppercase tracking-widest border ${item.severity === 'critical' ? 'border-red-200 text-red-600 bg-red-50' :
                                    item.severity === 'high' ? 'border-orange-200 text-orange-600 bg-orange-50' :
                                      'border-amber-200 text-amber-600 bg-amber-50'
                                    }`}>
                                    {item.severity}
                                  </span>
                                  <span className="text-[10px] font-mono text-text-muted opacity-50 tracking-tighter">NODE_IDENTIFIER: {item.id}</span>
                                </div>
                                <div className="text-2xl font-serif-display font-medium text-emerald-600">
                                  ${item.value.toLocaleString()}
                                </div>
                              </div>
                              <div className="flex items-end justify-between">
                                <div>
                                  <h4 className="text-xl font-serif-display font-medium text-text-primary group-hover:text-emerald-700 transition-colors uppercase tracking-tight">
                                    {item.title}
                                  </h4>
                                  <p className="text-xs text-text-muted mt-1 font-mono">Status: ACTIVE_INFILTRATION_PROTOCOL</p>
                                </div>
                                <div className="flex items-center gap-2 text-[10px] font-bold text-emerald-500 uppercase tracking-widest opacity-0 group-hover:opacity-100 transition-all translate-x-4 group-hover:translate-x-0">
                                  Access Intel <ArrowRight className="w-3 h-3" />
                                </div>
                              </div>
                            </div>
                          </Link>
                        ))}

                        <Link href="/marketplace/all" className="block text-center py-6 glass-card border border-dashed border-warm-300 hover:border-accent-primary/50 group transition-all">
                          <span className="text-sm font-bold uppercase tracking-widest text-text-muted group-hover:text-accent-primary transition-colors">Connect to Full Repository Feed</span>
                        </Link>
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Sidebar Intel */}
              <div className="space-y-6">
                <div className="p-8 bg-zinc-950 border border-zinc-800 rounded-2xl text-white relative overflow-hidden group shadow-2xl">
                  <div className="absolute inset-0 bg-matrix-pattern/10 opacity-30 group-hover:opacity-50 transition-opacity" />
                  <div className="relative z-10">
                    <div className="flex items-center gap-3 mb-6">
                      <Activity className="w-5 h-5 text-emerald-400" />
                      <h4 className="text-xl font-serif-display font-medium">Market Pulse</h4>
                    </div>

                    <div className="space-y-6">
                      <div className="p-4 rounded-xl bg-white/5 border border-white/10 hover:bg-white/10 transition-colors cursor-default">
                        <div className="text-[10px] uppercase tracking-widest text-emerald-400 font-bold mb-1">Trend: Aggressive</div>
                        <div className="text-sm border-l-2 border-emerald-400 pl-3 leading-relaxed text-zinc-100 italic">
                          "Rising demand for zero-click infiltration vectors targeting financial service nodes."
                        </div>
                      </div>

                      <div className="space-y-4 pt-4 border-t border-white/5">
                        <div className="flex justify-between items-center text-sm">
                          <span className="opacity-60">Avg Sell-Through</span>
                          <span className="font-mono text-emerald-400">14.2m</span>
                        </div>
                        <div className="flex justify-between items-center text-sm">
                          <span className="opacity-60">Aggregated Bids</span>
                          <span className="font-mono text-emerald-400">$2.4M</span>
                        </div>
                      </div>
                    </div>
                  </div>
                </div>

                <div className="glass-card p-8 shadow-inner bg-warm-100/30">
                  <h4 className="text-sm uppercase tracking-[0.2em] font-bold text-text-primary mb-6">Top Buyers</h4>
                  <div className="space-y-4">
                    {[
                      { label: 'APT Groups', value: 65, color: 'bg-red-500' },
                      { label: 'Nation States', value: 25, color: 'bg-amber-500' },
                      { label: 'Brokers', value: 10, color: 'bg-emerald-500' }
                    ].map(buyer => (
                      <div key={buyer.label} className="space-y-2">
                        <div className="flex justify-between items-center text-xs font-bold uppercase tracking-widest">
                          <span>{buyer.label}</span>
                          <span className="text-text-muted">{buyer.value}%</span>
                        </div>
                        <div className="h-1.5 w-full bg-warm-200 rounded-full overflow-hidden">
                          <div className={`h-full ${buyer.color}`} style={{ width: `${buyer.value}%` }} />
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </ProtectedRoute>
  );
}
