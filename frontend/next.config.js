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
    // Priority: 1. Environment Variable, 2. Docker internal name, 3. Localhost fallback
    const backendUrl = process.env.BACKEND_URL || 'http://backend:8000';
    
    // Explicitly handle common production failure case
    const finalBackendUrl = backendUrl.includes('localhost') && process.env.NODE_ENV === 'production' 
      ? 'http://backend:8000' 
      : backendUrl;

    console.log('[Proxy] Configuring rewrites with backend:', finalBackendUrl);
    
    return [
      {
        source: '/api/:path*/',
        destination: `${finalBackendUrl}/api/:path*/`,
      },
      {
        source: '/api/:path*',
        destination: `${finalBackendUrl}/api/:path*`,
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
