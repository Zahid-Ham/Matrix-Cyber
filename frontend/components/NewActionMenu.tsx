'use client';

import React, { useState, useRef, useEffect } from 'react';
import {
    ChevronDown,
    Plus,
    Monitor,
    Globe,
    Lock,
    Terminal,
    Clock,
    Database,
    Layers,
    Box,
    FileText
} from 'lucide-react';
import Link from 'next/link';

export function NewActionMenu() {
    const [isOpen, setIsOpen] = useState(false);
    const menuRef = useRef<HTMLDivElement>(null);

    useEffect(() => {
        const handleClickOutside = (event: MouseEvent) => {
            if (menuRef.current && !menuRef.current.contains(event.target as Node)) {
                setIsOpen(false);
            }
        };
        document.addEventListener('mousedown', handleClickOutside);
        return () => document.removeEventListener('mousedown', handleClickOutside);
    }, []);

    const menuItems = [
        { icon: Monitor, label: 'Static Site', href: '/new/static' },
        { icon: Globe, label: 'Web Service', href: '/new/web-service', active: true },
        { icon: Lock, label: 'Private Service', href: '/new/private' },
        { icon: Terminal, label: 'Background Worker', href: '/new/worker' },
        { icon: Clock, label: 'Cron Job', href: '/new/cron' },
        { divider: true },
        { icon: Database, label: 'Postgres', href: '/new/postgres' },
        { icon: Layers, label: 'Key Value', href: '/new/redis' },
        { divider: true },
        { icon: Box, label: 'Project', href: '/new/project' },
        { icon: FileText, label: 'Blueprint', href: '/new/blueprint' },
    ];

    return (
        <div className="relative" ref={menuRef}>
            <button
                onClick={() => setIsOpen(!isOpen)}
                className="flex items-center gap-1.5 px-4 py-2 bg-[#9333ea] hover:bg-[#a855f7] text-white rounded-md font-medium transition-colors shadow-sm"
            >
                <Plus className="w-4 h-4" />
                <span>New</span>
                <ChevronDown className={`w-4 h-4 transition-transform ${isOpen ? 'rotate-180' : ''}`} />
            </button>

            {isOpen && (
                <div className="absolute right-0 mt-2 w-64 bg-[#0a0a0a] border border-[#1f1f1f] rounded-lg shadow-2xl py-2 z-[100] animate-in fade-in zoom-in duration-200">
                    {menuItems.map((item, index) => (
                        item.divider ? (
                            <div key={index} className="my-2 border-t border-[#1f1f1f]" />
                        ) : (
                            <Link
                                key={index}
                                href={item.href || '#'}
                                onClick={() => setIsOpen(false)}
                                className={`flex items-center gap-3 px-4 py-2.5 transition-colors ${item.active
                                        ? 'bg-[#1a1a1a] text-white'
                                        : 'text-text-secondary hover:bg-[#1a1a1a] hover:text-white'
                                    }`}
                            >
                                {item.icon && <item.icon className="w-4 h-4" />}
                                <span className="text-sm font-medium">{item.label}</span>
                            </Link>
                        )
                    ))}
                </div>
            )}
        </div>
    );
}
