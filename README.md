# Secure P2P File Share (WebRTC + Firestore Signaling)

A minimal React app that transfers files peer-to-peer in the browser using WebRTC DataChannels. 
It establishes an end-to-end encrypted session using ECDH (P-256) to derive a shared secret and AES-GCM to encrypt file chunks. 
Firestore is used **only** for signaling (offer/answer/ICE) and a local history log.

## One-time setup

1. **Create a Firebase project** and enable:
   - Authentication → Sign-in method → Anonymous (enable).
   - Firestore Database → Create database (in test mode for dev).
2. **Create `.env.local`** at the project root with your Firebase config:
   ```env
   VITE_APP_ID=your-app-id-any-string

   VITE_FIREBASE_API_KEY=...
   VITE_FIREBASE_AUTH_DOMAIN=...
   VITE_FIREBASE_PROJECT_ID=...
   VITE_FIREBASE_STORAGE_BUCKET=...
   VITE_FIREBASE_MESSAGING_SENDER_ID=...
   VITE_FIREBASE_APP_ID=...
   ```
   You can find these values in your Firebase project settings.

## Run locally

```bash
npm i
npm run dev
```

Visit the printed local URL. Open in two tabs/devices:
- In one, click **Generate New ID** and share that ID with the other.
- In the other, paste the ID and click **Connect**.
- Choose a file and **Send File**.

## Deploy to Vercel

1. Push this repo to GitHub.
2. In Vercel, **Import Project** from GitHub.
3. Framework Preset: **Vite** (auto-detected).
4. Add the same **Environment Variables** from `.env.local` in Vercel (Project → Settings → Environment Variables).
5. Deploy.

## Notes

- This demo does not persist peer IDs server-side. A simple random ID is used and sent via Firestore subcollection paths. In production you might want a directory of active IDs or a QR/link share mechanism.
- WebRTC requires proper NAT traversal. This example relies on browser defaults for STUN. For tough NATs, configure your own STUN/TURN servers on the RTCPeerConnection.
- AES-GCM uses a fresh 96-bit IV per chunk; the IV is prepended to each chunk.
- Integrity is verified by computing SHA-256 hash of the full file and comparing on the receiver.
