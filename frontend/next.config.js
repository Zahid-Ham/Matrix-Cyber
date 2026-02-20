/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  trailingSlash: true,
  typescript: {
    ignoreBuildErrors: true,
  },
  eslint: {
    ignoreDuringBuilds: true,
  },
  experimental: {
    serverActions: {
      allowedOrigins: ['35.226.18.153:3000', 'localhost:3000'],
    },
  },
  async rewrites() {
    // In production (Docker), always prefer the internal service name
    const backendUrl = process.env.NODE_ENV === 'production' 
      ? 'http://backend:8000' 
      : (process.env.BACKEND_URL || 'http://localhost:8000');
    
    console.log('[Proxy] Configuring rewrites with destination:', backendUrl);
    
    return [
      {
        source: '/api/:path*',
        destination: `${backendUrl}/api/:path*`,
      },
    ];
  },
  async headers() {
    return [
      {
        source: '/:path*',
        headers: [
          { key: 'Content-Security-Policy', value: "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self' data: https:; font-src 'self' https://fonts.gstatic.com; connect-src 'self' *; frame-ancestors 'none'; base-uri 'self'; form-action 'self'; frame-src 'self' http: https: data:" },
          { key: 'X-Frame-Options', value: 'DENY' },
          { key: 'X-Content-Type-Options', value: 'nosniff' },
          { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
          { key: 'Cache-Control', value: 'no-cache, no-store, must-revalidate' }
        ],
      },
    ];
  },
};

module.exports = nextConfig;
