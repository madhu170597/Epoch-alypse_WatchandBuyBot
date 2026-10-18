import {useEffect, useState} from 'react';

import {
  addAddress,
  addCard,
  type Address,
  type Card,
  deleteAddress,
  deleteCard,
  listAddresses,
  listCards,
} from './identityClient';

function errText(e: unknown): string {
  const err = e as {message?: string};
  return err.message ?? String(e);
}

/** Dummy wallet: add a test card + a shipping address. No real card data —
 *  use a test PAN like 4242 4242 4242 4242; only brand + last4 are stored. */
export function WalletPanel() {
  const [cards, setCards] = useState<Card[]>([]);
  const [addresses, setAddresses] = useState<Address[]>([]);
  const [note, setNote] = useState('');
  const [busy, setBusy] = useState(false);

  const [number, setNumber] = useState('4242 4242 4242 4242');
  const [exp, setExp] = useState('12/30');
  const [holder, setHolder] = useState('');

  const [addr, setAddr] = useState({
    name: '',
    line1: '',
    city: '',
    region: '',
    postal: '',
    country: 'US',
  });

  async function refresh() {
    try {
      const [c, a] = await Promise.all([listCards(), listAddresses()]);
      setCards(c);
      setAddresses(a);
    } catch (e) {
      setNote(errText(e));
    }
  }

  useEffect(() => {
    refresh();
  }, []);

  async function onAddCard() {
    setBusy(true);
    setNote('');
    try {
      const [mm, yy] = exp.split('/').map((s) => s.trim());
      await addCard({
        number,
        exp_month: Number(mm),
        exp_year: 2000 + Number(yy),
        holder,
      });
      setNote('Card added.');
      await refresh();
    } catch (e) {
      setNote(errText(e));
    } finally {
      setBusy(false);
    }
  }

  async function onAddAddress() {
    setBusy(true);
    setNote('');
    try {
      await addAddress(addr);
      setNote('Address added.');
      await refresh();
    } catch (e) {
      setNote(errText(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="wallet-panel">
      <h3>Wallet (demo — test cards only)</h3>

      <div className="wallet-section">
        <div className="wallet-list">
          {cards.length === 0 && <div className="muted">No card yet.</div>}
          {cards.map((c) => (
            <div key={c.id} className="wallet-row">
              <span>
                {c.brand} ••{c.last4} · {String(c.exp_month).padStart(2, '0')}/{c.exp_year}
              </span>
              <button onClick={() => deleteCard(c.id).then(refresh)}>Remove</button>
            </div>
          ))}
        </div>
        <div className="wallet-form">
          <input
            placeholder="Card number (test: 4242…)"
            value={number}
            onChange={(e) => setNumber(e.target.value)}
          />
          <input placeholder="MM/YY" value={exp} onChange={(e) => setExp(e.target.value)} />
          <input
            placeholder="Name on card"
            value={holder}
            onChange={(e) => setHolder(e.target.value)}
          />
          <button disabled={busy} onClick={onAddCard}>
            Add card
          </button>
        </div>
      </div>

      <div className="wallet-section">
        <div className="wallet-list">
          {addresses.length === 0 && <div className="muted">No address yet.</div>}
          {addresses.map((a) => (
            <div key={a.id} className="wallet-row">
              <span>
                {a.name}, {a.line1}, {a.city} {a.region} {a.postal}, {a.country}
              </span>
              <button onClick={() => deleteAddress(a.id).then(refresh)}>Remove</button>
            </div>
          ))}
        </div>
        <div className="wallet-form">
          <input
            placeholder="Full name"
            value={addr.name}
            onChange={(e) => setAddr({...addr, name: e.target.value})}
          />
          <input
            placeholder="Street address"
            value={addr.line1}
            onChange={(e) => setAddr({...addr, line1: e.target.value})}
          />
          <input
            placeholder="City"
            value={addr.city}
            onChange={(e) => setAddr({...addr, city: e.target.value})}
          />
          <input
            placeholder="State/Region"
            value={addr.region}
            onChange={(e) => setAddr({...addr, region: e.target.value})}
          />
          <input
            placeholder="Postal code"
            value={addr.postal}
            onChange={(e) => setAddr({...addr, postal: e.target.value})}
          />
          <input
            placeholder="Country"
            value={addr.country}
            onChange={(e) => setAddr({...addr, country: e.target.value})}
          />
          <button disabled={busy} onClick={onAddAddress}>
            Add address
          </button>
        </div>
      </div>

      {note && <div className="auth-note">{note}</div>}
    </div>
  );
}
