# Secure P2P File Share (WebRTC + Firestore Signaling)

This project is a minimal Vite + React app that demonstrates peer-to-peer file transfer using WebRTC DataChannels, ECDH (P-256) for key exchange, AES-GCM for encryption, and Firestore for signaling.

## Quick start

1. Copy `.env.local.example` to `.env.local` and fill with your Firebase config values.
2. Install deps: `npm install`
3. Run dev server: `npm run dev`
4. Open two windows/devices and test generating/pasting Peer IDs and sending files.

## Deploy

Push to GitHub and deploy to Vercel (auto-detects Vite). Set the same environment variables in Vercel project settings.
