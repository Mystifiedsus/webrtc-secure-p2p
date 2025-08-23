import { initializeApp } from 'firebase/app';
import { getAuth, onAuthStateChanged, signInAnonymously, signInWithCustomToken } from 'firebase/auth';
import { getFirestore } from 'firebase/firestore';

// Use Vite env vars. Create .env.local with VITE_FIREBASE_* values.
const firebaseConfig = {
  apiKey: import.meta.env.VITE_FIREBASE_API_KEY,
  authDomain: import.meta.env.VITE_FIREBASE_AUTH_DOMAIN,
  projectId: import.meta.env.VITE_FIREBASE_PROJECT_ID,
  storageBucket: import.meta.env.VITE_FIREBASE_STORAGE_BUCKET,
  messagingSenderId: import.meta.env.VITE_FIREBASE_MESSAGING_SENDER_ID,
  appId: import.meta.env.VITE_FIREBASE_APP_ID,
};

export const app = initializeApp(firebaseConfig);
export const auth = getAuth(app);
export const db = getFirestore(app);

export async function ensureSignedIn(initialToken) {
  return new Promise((resolve) => {
    onAuthStateChanged(auth, async (user) => {
      if (user) {
        resolve(user);
      } else {
        try {
          if (initialToken) {
            await signInWithCustomToken(auth, initialToken);
          } else {
            await signInAnonymously(auth);
          }
        } catch (e) {
          console.error('Auth error', e);
        } finally {
          // Wait for the state change to fire again
          // If it doesn't quickly, resolve null to avoid deadlocks
          resolve(auth.currentUser ?? null);
        }
      }
    });
  });
}
