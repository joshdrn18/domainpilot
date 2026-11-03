# DomainPilot

A premium, mobile-first domain management workspace.

## Stack
- React + Vite
- Cloudflare Pages-ready static build
- Lucide icons

## Local development
```bash
npm install
npm run dev
```

## Production build
```bash
npm run build
```

Deploy to Cloudflare Pages with:
- Build command: `npm run build`
- Build output directory: `dist`
- Root directory: `/`

## Current preview scope
The first UI milestone includes responsive navigation, portfolio overview, domain search/filtering, and an add-domain flow. Domain records are currently stored in browser localStorage and the seeded records are illustrative preview data. Registrar, DNS, SSL, expiry, uptime checks, authentication, and D1 persistence are not connected yet.
