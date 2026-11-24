import { getStore } from '@netlify/blobs';
import { createHmac, createHash, scryptSync, randomBytes, timingSafeEqual } from 'node:crypto';

const SECRET = process.env.AUTH_SECRET;
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json' } });
const sign = (p) => createHmac('sha256', SECRET).update(p).digest('base64url');
const mint = (uid) => { const p = uid + '.' + (Date.now() + 30 * 864e5); return p + '.' + sign(p); };
function check(t) {
  const a = String(t || '').split('.');
  if (a.length !== 3) return null;
  const s = sign(a[0] + '.' + a[1]);
  if (a[2].length !== s.length || !timingSafeEqual(Buffer.from(a[2]), Buffer.from(s))) return null;
  return +a[1] > Date.now() ? a[0] : null;
}
const num = (v) => { v = Number(v); return isFinite(v) && v > 0 ? Math.min(Math.round(v), 1e9) : 0; };

export default async (req) => {
  if (req.method !== 'POST') return json({ error: 'method' }, 405);
  if (!SECRET) return json({ error: 'config' }, 500);
  let b; try { b = await req.json(); } catch { return json({ error: 'bad' }, 400); }
  const users = getStore('users'), board = getStore('board');

  if (b.op === 'auth') {
    const email = String(b.email || '').trim().toLowerCase().slice(0, 254);
    const pw = String(b.password || '');
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: 'email' }, 400);
    if (pw.length < 8 || pw.length > 200) return json({ error: 'password' }, 400);
    const key = createHash('sha256').update(email).digest('hex');
    const u = await users.get(key, { type: 'json' });
    if (u) {
      const h = scryptSync(pw, Buffer.from(u.salt, 'hex'), 32);
      if (!timingSafeEqual(h, Buffer.from(u.hash, 'hex'))) return json({ error: 'wrong' }, 401);
      return json({ token: mint(u.uid), uid: u.uid });
    }
    const salt = randomBytes(16), uid = randomBytes(6).toString('hex');
    await users.setJSON(key, { uid, salt: salt.toString('hex'), hash: scryptSync(pw, salt, 32).toString('hex'), t: Date.now() });
    return json({ token: mint(uid), uid });
  }

  if (b.op === 'list') {
    const { blobs } = await board.list();
    const rows = (await Promise.all(blobs.map(async (x) => {
      const v = await board.get(x.key, { type: 'json' });
      return v ? { id: x.key, n: v.n, xp: v.xp, p: v.p } : null;
    }))).filter(Boolean);
    return json({ rows });
  }

  const uid = check(b.token);
  if (!uid) return json({ error: 'session' }, 401);

  if (b.op === 'put') {
    const d = b.d || {}, p = {};
    Object.keys(d.p && typeof d.p === 'object' ? d.p : {}).slice(0, 12).forEach((k) => { if (/^[a-z0-9_-]{1,20}$/i.test(k)) p[k] = num(d.p[k]); });
    const n = String(d.n || '').replace(/\s+/g, ' ').trim().slice(0, 24);
    if (!n) return json({ error: 'name' }, 400);
    await board.setJSON(uid, { n, xp: num(d.xp), p, u: Date.now() });
    return json({ ok: true });
  }
  if (b.op === 'del') { await board.delete(uid); return json({ ok: true }); }
  return json({ error: 'op' }, 400);
};
