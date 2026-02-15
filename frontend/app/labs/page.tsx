'use client';

import React from 'react';
import { Database, Code, Terminal, ShieldAlert, ArrowRight, Lock, Server } from 'lucide-react';
import { Navbar } from '../../components/Navbar';

export default function LabsPage() {
  const labs = [
    {
      id: 'sql_injection',
      title: 'SQL Injection Lab',
      subtitle: 'Database Exploitation',
      description: 'Practice exploiting authentication bypass vulnerabilities using SQL injection attacks.',
      icon: Database,
      // Using warm/elegant color adaptations while keeping semantic meaning
      iconColor: 'text-rose-600',
      badgeColor: 'bg-rose-100 text-rose-700 border-rose-200',
      difficulty: 'Beginner',
      port: 80,
      tech: 'Python/Flask + SQLite'
    },
    {
      id: 'xss',
      title: 'Reflected XSS Lab',
      subtitle: 'Client-Side Attacks',
      description: 'Learn how to inject malicious scripts into web pages to steal cookies or session data.',
      icon: Code,
      iconColor: 'text-amber-600',
      badgeColor: 'bg-amber-100 text-amber-700 border-amber-200',
      difficulty: 'Intermediate',
      port: 80,
      tech: 'Python/Flask + HTML'
    },
    {
      id: 'rce',
      title: 'Command Injection Lab',
      subtitle: 'Remote Code Execution',
      description: 'Execute arbitrary system commands on the server by exploiting unsanitized inputs.',
      icon: Terminal,
      iconColor: 'text-violet-600',
      badgeColor: 'bg-violet-100 text-violet-700 border-violet-200',
      difficulty: 'Advanced',
      port: 80,
      tech: 'Python/Flask + Subprocess'
    }
  ];

  return (
    <div className="min-h-screen">
      <Navbar />

      <main className="max-w-7xl mx-auto px-6 py-24 md:py-32">
        <div className="text-center mb-20 space-y-6 animate-slide-up">
          <div className="inline-flex items-center gap-2 px-4 py-1.5 rounded-full bg-accent-primary/5 border border-accent-primary/10 text-accent-primary text-xs font-bold tracking-wider mb-4">
            <span className="w-2 h-2 rounded-full bg-accent-primary animate-pulse"></span>
            LIVE ENVIRONMENT
          </div>
          <h1 className="text-5xl md:text-6xl font-serif text-text-primary tracking-tight">
            Security <span className="text-accent-primary font-medium">Exploit Labs</span>
          </h1>
          <p className="text-text-secondary text-lg md:text-xl max-w-2xl mx-auto leading-relaxed font-light">
            Safe, isolated Docker containers to practice real-world cyber attacks.
            Select a vulnerability to generate a target instance.
          </p>
        </div>

        <div className="grid md:grid-cols-3 gap-8">
          {labs.map((lab, index) => (
            <div
              key={lab.id}
              className={`group relative glass-card p-8 hover:-translate-y-2 transition-all duration-500 overflow-hidden flex flex-col h-full animate-slide-up`}
              style={{ animationDelay: `${index * 150}ms` }}
            >
              {/* Background Gradient Effect */}
              <div className="absolute top-0 right-0 -mt-16 -mr-16 w-64 h-64 bg-accent-primary/5 rounded-full blur-3xl opacity-0 group-hover:opacity-100 transition-opacity duration-700 pointer-events-none" />

              <div className="relative z-10 flex flex-col h-full">
                <div className="flex justify-between items-start mb-8">
                  <div className={`p-4 rounded-xl bg-bg-secondary border border-warm-200 shadow-sm group-hover:shadow-md transition-shadow duration-300`}>
                    <lab.icon className={`w-8 h-8 ${lab.iconColor}`} />
                  </div>
                  <span className={`text-[10px] font-bold px-3 py-1.5 rounded-full border uppercase tracking-wider ${lab.badgeColor}`}>
                    {lab.difficulty}
                  </span>
                </div>

                <div className="space-y-2 mb-6">
                  <h3 className="text-2xl font-serif font-medium text-text-primary group-hover:text-accent-primary transition-colors duration-300">
                    {lab.title}
                  </h3>
                  <p className={`text-sm font-semibold tracking-wide uppercase ${lab.iconColor} opacity-90`}>
                    {lab.subtitle}
                  </p>
                </div>

                <p className="text-text-secondary text-sm mb-8 leading-relaxed flex-1">
                  {lab.description}
                </p>

                <div className="flex items-center gap-5 text-xs text-text-muted mb-8 font-medium border-t border-warm-200/50 pt-6">
                  <div className="flex items-center gap-2">
                    <Server className="w-3.5 h-3.5" />
                    {lab.tech}
                  </div>
                  <div className="flex items-center gap-2">
                    <ShieldAlert className="w-3.5 h-3.5" />
                    Port {lab.port}
                  </div>
                </div>

                <button
                  onClick={() => window.open(`/sandbox?type=${lab.id}&id=${Math.floor(Math.random() * 1000)}`, '_blank')}
                  className="w-full py-4 rounded-xl font-semibold text-center flex items-center justify-center gap-2 transition-all duration-300 bg-text-primary text-bg-primary hover:bg-accent-primary hover:text-white shadow-lg hover:shadow-xl group-hover:scale-[1.02]"
                >
                  INITIALIZE LAB
                  <ArrowRight className="w-4 h-4" />
                </button>
              </div>
            </div>
          ))}
        </div>

        <div className="mt-24 p-8 md:p-10 rounded-2xl bg-bg-secondary/50 border border-warm-200/50 text-center max-w-3xl mx-auto backdrop-blur-sm">
          <div className="inline-flex items-center justify-center p-3 rounded-full bg-warm-100 mb-6">
            <Lock className="w-6 h-6 text-accent-primary" />
          </div>
          <h3 className="text-xl font-serif font-medium text-text-primary mb-3">
            Restricted Environment
          </h3>
          <p className="text-text-muted text-sm leading-relaxed max-w-xl mx-auto">
            These labs run in ephemeral Docker containers with no internet access.
            Any data created is destroyed upon session termination.
            Do not use these tools against real targets without authorization.
          </p>
        </div>
      </main>
    </div>
  );
}

