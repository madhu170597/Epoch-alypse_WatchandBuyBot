import {useEffect, useState} from 'react';
import {onAuthStateChanged, type User} from 'firebase/auth';

import {auth} from '../firebase';

/** Tracks the current Firebase user. `ready` is false until the first callback. */
export function useAuth(): {user: User | null; ready: boolean} {
  const [user, setUser] = useState<User | null>(auth?.currentUser ?? null);
  const [ready, setReady] = useState(!auth);

  useEffect(() => {
    if (!auth) {
      setReady(true);
      return;
    }
    return onAuthStateChanged(auth, (u) => {
      setUser(u);
      setReady(true);
    });
  }, []);

  return {user, ready};
}
