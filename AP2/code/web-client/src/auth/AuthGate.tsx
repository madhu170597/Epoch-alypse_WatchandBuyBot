import {type ReactNode, useState} from 'react';
import {
  multiFactor,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator,
  RecaptchaVerifier,
  signOut,
} from 'firebase/auth';

import {auth, firebaseEnabled} from '../firebase';
import {registerPasskey, startTelegramLink} from './identityClient';
import {LoginPanel} from './LoginPanel';
import {useAuth} from './useAuth';
import {WalletPanel} from './WalletPanel';

function errText(e: unknown): string {
  const err = e as {code?: string; message?: string};
  return err.code ?? err.message ?? String(e);
}

/** Gate the app behind Firebase auth; add a small account toolbar when signed in. */
export function AuthGate({children}: {children: ReactNode}) {
  const {user, ready} = useAuth();
  const [note, setNote] = useState('');
  const [showWallet, setShowWallet] = useState(false);

  // SMS-MFA enrollment state.
  const [phone, setPhone] = useState('');
  const [enrollCode, setEnrollCode] = useState('');
  const [enrollId, setEnrollId] = useState('');

  // Local dev without Firebase configured: no auth gate.
  if (!firebaseEnabled) return <>{children}</>;
  if (!ready) return <div className="auth-loading">Loading…</div>;
  if (!user) return <LoginPanel />;

  async function addPasskey() {
    try {
      await registerPasskey();
      setNote('Passkey registered.');
    } catch (e) {
      setNote(errText(e));
    }
  }

  async function linkTelegram() {
    try {
      const {code, expires_in} = await startTelegramLink();
      setNote(`Telegram code: ${code} (send "/link ${code}" to the bot within ${expires_in}s)`);
    } catch (e) {
      setNote(errText(e));
    }
  }

  async function sendEnrollCode() {
    try {
      const session = await multiFactor(user!).getSession();
      const id = await new PhoneAuthProvider(auth!).verifyPhoneNumber(
        {phoneNumber: phone, session},
        new RecaptchaVerifier(auth!, 'recaptcha-enroll', {size: 'invisible'}),
      );
      setEnrollId(id);
      setNote('Code sent.');
    } catch (e) {
      setNote(errText(e));
    }
  }

  async function finishEnroll() {
    try {
      const cred = PhoneAuthProvider.credential(enrollId, enrollCode);
      await multiFactor(user!).enroll(
        PhoneMultiFactorGenerator.assertion(cred),
        'Phone',
      );
      setEnrollId('');
      setNote('SMS second factor enrolled.');
    } catch (e) {
      setNote(errText(e));
    }
  }

  return (
    <div className="auth-shell">
      <div className="account-bar">
        <span className="account-email">{user.email ?? user.uid}</span>
        <button onClick={() => setShowWallet((v) => !v)}>
          {showWallet ? 'Hide wallet' : 'Wallet'}
        </button>
        <button onClick={addPasskey}>Add passkey</button>
        <button onClick={linkTelegram}>Link Telegram</button>
        <button onClick={() => signOut(auth!)}>Sign out</button>
      </div>

      {showWallet && <WalletPanel />}

      <div className="enroll-bar">
        {enrollId ? (
          <>
            <input
              placeholder="SMS code"
              value={enrollCode}
              onChange={(e) => setEnrollCode(e.target.value)}
            />
            <button onClick={finishEnroll}>Enroll</button>
          </>
        ) : (
          <>
            <input
              placeholder="+15551234567"
              value={phone}
              onChange={(e) => setPhone(e.target.value)}
            />
            <button onClick={sendEnrollCode}>Add SMS 2FA</button>
          </>
        )}
      </div>

      {note && <div className="auth-note">{note}</div>}
      <div id="recaptcha-enroll" />
      {children}
    </div>
  );
}
