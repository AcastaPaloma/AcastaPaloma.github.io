/* Slide sync over a public relay (ntfy.sh), so a phone can drive every open copy of the deck.

   Roles, picked from the URL:
     solo    opened from disk (file://) or with ?solo: a plain local deck, no network
     follow  anyone on the website: the deck follows the presenter, local clicks do nothing
     lead    the URL carries the private key after #k= (the phone remote, or the presenter's laptop):
             local input moves everyone

   Every position is signed with ECDSA P-256. Followers only hold the public key, so viewers can
   watch but cannot move the slides. The private key lives only in the #fragment, which browsers
   never send to any server. Positions carry an increasing counter, so old messages can't be replayed. */
window.SYNC = (() => {
  const CFG = {
    topic: 'microbots-xH0llikZ7aqN',
    x: 'GATuIHaZNUAndJ3uiJHTQkIgejpbkggl7Gwb7eUUy7Y',
    y: 'YwKt8WJdMk1MgNQzm-WJ1DhwZzHZUUhEVgC3c_IArag',
    beats: [1, 3, 4, 2, 3, 4, 3, 1],   // steps per slide; keep in step with SCENES in index.html
  };
  const RELAY = 'https://ntfy.sh/' + CFG.topic;
  const ALG = { name: 'ECDSA', namedCurve: 'P-256' }, SIG = { name: 'ECDSA', hash: 'SHA-256' };
  const d = new URLSearchParams(location.hash.slice(1)).get('k');
  const solo = location.protocol === 'file:' || new URLSearchParams(location.search).has('solo') || !crypto.subtle;
  const role = solo ? 'solo' : d ? 'lead' : 'follow';

  const enc = new TextEncoder();
  const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const unb64u = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
  const jwk = { kty: 'EC', crv: 'P-256', x: CFG.x, y: CFG.y };
  const pubKey = solo ? null : crypto.subtle.importKey('jwk', jwk, ALG, false, ['verify']);
  const privKey = role === 'lead' ? crypto.subtle.importKey('jwk', { ...jwk, d }, ALG, false, ['sign']).catch(() => null) : null;

  let lastN = 0;                       // newest counter seen, sent or received
  const subs = [], statusSubs = [];
  let online = false;
  const setOnline = v => { if (v !== online) { online = v; statusSubs.forEach(f => f(v)); } };

  /* ---- receive ---- */
  let chain = Promise.resolve();       // verify in arrival order
  function onRaw(text) {
    chain = chain.then(async () => {
      const { p, sig } = JSON.parse(text);
      if (!await crypto.subtle.verify(SIG, await pubKey, unb64u(sig), enc.encode(p))) return;
      const m = JSON.parse(p);
      if (!(m.n > lastN)) return;
      lastN = m.n;
      subs.forEach(f => f(m.s, m.b));
    }).catch(() => {});
  }
  function connect() {
    const es = new EventSource(RELAY + '/sse?since=latest');
    es.onopen = () => setOnline(true);
    es.onerror = () => setOnline(false);   // EventSource retries by itself
    es.onmessage = e => { try { const m = JSON.parse(e.data); if (m.event === 'message') onRaw(m.message); } catch {} };
  }
  if (!solo) connect();

  /* ---- send (lead only): newest position wins, one request in flight ---- */
  let pending = null, busy = false;
  async function flush() {
    if (busy || !pending) return;
    busy = true;
    const { s, b } = pending; pending = null;
    try {
      const key = await privKey;
      if (!key) throw new Error('bad key');
      const n = lastN = Math.max(Date.now(), lastN + 1);
      const p = JSON.stringify({ s, b, n });
      const sig = b64u(await crypto.subtle.sign(SIG, key, enc.encode(p)));
      const r = await fetch(RELAY, { method: 'POST', body: JSON.stringify({ p, sig }) });
      if (!r.ok) throw new Error(r.status);
    } catch (e) {
      if (!pending) pending = { s, b };      // retry unless something newer is queued
      busy = false; setTimeout(flush, 1000); return;
    }
    busy = false; flush();
  }

  return {
    role, beats: CFG.beats,
    keyOk: privKey ? privKey.then(Boolean) : Promise.resolve(false),
    send(s, b) { if (role !== 'lead') return; pending = { s, b }; flush(); },
    listen(f) { subs.push(f); },
    onStatus(f) { statusSubs.push(f); f(online); },
  };
})();
