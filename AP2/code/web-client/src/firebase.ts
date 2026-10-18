// Firebase app + auth init. Config comes from VITE_FIREBASE_* env vars.
// When no config is present (local dev), auth is disabled and the app runs
// without a sign-in gate.
import {type Auth, getAuth} from 'firebase/auth';
import {initializeApp} from 'firebase/app';

const env = (import.meta as {env?: Record<string, string | undefined>}).env ?? {};

export const firebaseEnabled = Boolean(env.VITE_FIREBASE_API_KEY);

export const firebaseApp = firebaseEnabled
  ? initializeApp({
      apiKey: env.VITE_FIREBASE_API_KEY,
      authDomain: env.VITE_FIREBASE_AUTH_DOMAIN,
      projectId: env.VITE_FIREBASE_PROJECT_ID,
      appId: env.VITE_FIREBASE_APP_ID,
    })
  : null;

export const auth: Auth | null = firebaseApp ? getAuth(firebaseApp) : null;
