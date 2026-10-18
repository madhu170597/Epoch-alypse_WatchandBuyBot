import {useState} from 'react';
import {
  getMultiFactorResolver,
  PhoneAuthProvider,
  PhoneMultiFactorGenerator,
  RecaptchaVerifier,
  signInWithCustomToken,
  signInWithEmailAndPassword,
  type MultiFactorResolver,
} from 'firebase/auth';

import {auth} from '../firebase';
import {passkeyLogin} from './identityClient';

type Step = 'login' | 'mfa';

function errText(e: unknown): string {
  const err = e as {code?: string; message?: string};
  return err.code ?? err.message ?? String(e);
}

/** Email + SMS-MFA sign-in, plus passkey sign-in. */
export function LoginPanel() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [code, setCode] = useState('');
  const [step, setStep] = useState<Step>('login');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');

  const [resolver, setResolver] = useState<MultiFactorResolver | null>(null);
  const [verificationId, setVerificationId] = useState('');

  const recaptcha = () =>
    new RecaptchaVerifier(auth!, 'recaptcha-container', {size: 'invisible'});

  async function handleLogin() {
    setBusy(true);
    setError('');
    try {
      await signInWithEmailAndPassword(auth!, email, password);
      // onAuthStateChanged in useAuth picks it up.
    } catch (e) {
      if ((e as {code?: string}).code === 'auth/multi-factor-auth-required') {
        try {
          const res = getMultiFactorResolver(auth!, e as never);
          setResolver(res);
          const id = await new PhoneAuthProvider(auth!).verifyPhoneNumber(
            {multiFactorHint: res.hints[0], session: res.session},
            recaptcha(),
          );
          setVerificationId(id);
          setStep('mfa');
        } catch (inner) {
          setError(errText(inner));
        }
      } else {
        setError(errText(e));
      }
    } finally {
      setBusy(false);
    }
  }

  async function handleMfa() {
    if (!resolver) return;
    setBusy(true);
    setError('');
    try {
      const cred = PhoneAuthProvider.credential(verificationId, code);
      const assertion = PhoneMultiFactorGenerator.assertion(cred);
      await resolver.resolveSignIn(assertion);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function handlePasskey() {
    setBusy(true);
    setError('');
    try {
      const customToken = await passkeyLogin();
      await signInWithCustomToken(auth!, customToken);
    } catch (e) {
      setError(errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-panel">
      <h2>Sign in</h2>
      {step === 'login' ? (
        <>
          <input
            type="email"
            placeholder="Email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <button disabled={busy} onClick={handleLogin}>
            Sign in
          </button>
          <div className="divider">or</div>
          <button disabled={busy} onClick={handlePasskey}>
            Sign in with passkey
          </button>
        </>
      ) : (
        <>
          <p>Enter the code sent to your phone.</p>
          <input
            inputMode="numeric"
            placeholder="SMS code"
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
          <button disabled={busy} onClick={handleMfa}>
            Verify
          </button>
        </>
      )}
      {error && <div className="auth-error">{error}</div>}
      <div id="recaptcha-container" />
    </div>
  );
}
