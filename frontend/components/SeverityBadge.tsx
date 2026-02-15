import React from 'react';

interface SeverityBadgeProps {
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    size?: 'sm' | 'md' | 'lg';
}

export function SeverityBadge({ severity, size = 'md' }: SeverityBadgeProps) {
    const sizeClasses = {
        sm: 'px-3 py-1 text-[10px]',
        md: 'px-5 py-2 text-xs',
        lg: 'px-6 py-3 text-sm'
    };

    const severityConfig = {
        critical: {
            bg: 'bg-red-500',
            text: 'text-white',
            ring: 'ring-red-500/30',
            glow: 'shadow-[0_0_20px_rgba(239,68,68,0.3)]'
        },
        high: {
            bg: 'bg-orange-500',
            text: 'text-white',
            ring: 'ring-orange-500/30',
            glow: 'shadow-[0_0_20px_rgba(249,115,22,0.3)]'
        },
        medium: {
            bg: 'bg-yellow-500',
            text: 'text-gray-900',
            ring: 'ring-yellow-500/30',
            glow: 'shadow-[0_0_20px_rgba(234,179,8,0.3)]'
        },
        low: {
            bg: 'bg-emerald-500',
            text: 'text-white',
            ring: 'ring-emerald-500/30',
            glow: 'shadow-[0_0_20px_rgba(16,185,129,0.3)]'
        },
        info: {
            bg: 'bg-blue-500',
            text: 'text-white',
            ring: 'ring-blue-500/30',
            glow: 'shadow-[0_0_20px_rgba(59,130,246,0.3)]'
        }
    };

    const config = severityConfig[severity];

    return (
        <span
            className={`
                ${sizeClasses[size]}
                ${config.bg}
                ${config.text}
                ${config.glow}
                ring-2 ${config.ring}
                rounded-full
                font-extrabold
                uppercase
                tracking-wider
                inline-flex
                items-center
                justify-center
                transition-all
                duration-300
                hover:scale-105
            `}
        >
            {severity}
        </span>
    );
}
