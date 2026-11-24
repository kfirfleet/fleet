// km-reminders: (1) התראות לטלפון על עדכון ק"מ (Web Push), (2) שליחת חשבוניות להנהלת החשבונות במייל,
// (3) קריאה אוטומטית של תמונה או קובץ PDF של חשבונית באמצעות Claude (תאריך, סכום, מוסך, ק"מ), וגם של מסמכי ביטוח וטסט (סכום, תאריך, תוקף) ושל רישיון רכב (מספר, דגם, שנה, תוקף).
// התראות לא צריכות מפתחות חיצוניים. שליחת מייל עוברת דרך סקריפט קטן ב-Gmail שלך (Google Apps Script),
// וכתובת הסקריפט נשמרת בסוד MAIL_SCRIPT_URL. הקריאה האוטומטית צריכה סוד בשם ANTHROPIC_API_KEY.
// חשוב: אחרי הפריסה לכבות את Verify JWT של הפונקציה (הפונקציה בודקת הרשאות בעצמה).
import { createClient } from 'npm:@supabase/supabase-js@2'

const SITE = 'https://kfirfleet.github.io/fleet/'
const cors = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type, x-cron-secret',
}
const reply = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, 'Content-Type': 'application/json' },
  })

const enc = new TextEncoder()
const b64u = (b: Uint8Array) =>
  btoa(String.fromCharCode(...b)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
const unb64u = (s: string) =>
  Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (s.length % 4)) % 4)), (c) =>
    c.charCodeAt(0))
const cat = (...a: Uint8Array[]) => {
  const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0))
  let i = 0
  for (const x of a) {
    o.set(x, i)
    i += x.length
  }
  return o
}
async function hkdf(salt: Uint8Array, ikm: Uint8Array, info: Uint8Array, len: number) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits'])
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8))
}

// הצפנת ההודעה לפי תקן Web Push (RFC 8291, aes128gcm)
async function encrypt(text: string, p256dh: string, auth: string) {
  const ua = unb64u(p256dh)
  const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits'])
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey))
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, [])
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256))
  const ikm = await hkdf(unb64u(auth), shared, cat(enc.encode('WebPush: info\0'), ua, asPub), 32)
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const cek = await hkdf(salt, ikm, enc.encode('Content-Encoding: aes128gcm\0'), 16)
  const nonce = await hkdf(salt, ikm, enc.encode('Content-Encoding: nonce\0'), 12)
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt'])
  const data = cat(enc.encode(text), new Uint8Array([2]))
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, data))
  return cat(salt, new Uint8Array([0, 0, 16, 0, 65]), asPub, ct)
}

// מפתחות VAPID: נוצרים אוטומטית בפעם הראשונה ונשמרים בטבלה app_secrets
type Vapid = { d: string; x: string; y: string }
async function vapidKeys(admin: ReturnType<typeof createClient>): Promise<Vapid> {
  const read = async () => (await admin.from('app_secrets').select('value').eq('key', 'vapid').maybeSingle()).data
  let row = await read()
  if (!row) {
    const kp = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    const j = await crypto.subtle.exportKey('jwk', kp.privateKey)
    await admin.from('app_secrets').upsert(
      { key: 'vapid', value: JSON.stringify({ d: j.d, x: j.x, y: j.y }) },
      { onConflict: 'key', ignoreDuplicates: true },
    )
    row = await read()
  }
  if (!row) throw new Error('vapid keys missing (run the SQL first)')
  return JSON.parse(row.value)
}
async function vapidJwt(aud: string, v: Vapid) {
  const head = b64u(enc.encode(JSON.stringify({ typ: 'JWT', alg: 'ES256' })))
  const claims = b64u(enc.encode(JSON.stringify({ aud, exp: Math.floor(Date.now() / 1000) + 43200, sub: SITE })))
  const key = await crypto.subtle.importKey(
    'jwk',
    { kty: 'EC', crv: 'P-256', d: v.d, x: v.x, y: v.y, ext: true },
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign'],
  )
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, enc.encode(head + '.' + claims)))
  return head + '.' + claims + '.' + b64u(sig)
}

type Sub = { id: string; user_id: string; endpoint: string; p256dh: string; auth: string }
async function push(sub: Sub, message: unknown, v: Vapid, pub: string) {
  const jwt = await vapidJwt(new URL(sub.endpoint).origin, v)
  const r = await fetch(sub.endpoint, {
    method: 'POST',
    headers: {
      Authorization: 'vapid t=' + jwt + ', k=' + pub,
      'Content-Encoding': 'aes128gcm',
      'Content-Type': 'application/octet-stream',
      TTL: '86400',
      Urgency: 'normal',
    },
    body: await encrypt(JSON.stringify(message), sub.p256dh, sub.auth),
  })
  return r.status
}

// ---------- שליחת חשבונית למייל (דרך סקריפט ב-Gmail) ----------
type Admin = ReturnType<typeof createClient>
const toB64 = (u: Uint8Array) => {
  let s = ''
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode(...u.subarray(i, i + 0x8000))
  return btoa(s)
}
const TYPES: Record<string, string> = {
  periodic: 'טיפול תקופתי',
  tires: 'החלפת צמיגים',
  brakes: 'בלמים',
  repair: 'תקלה / תיקון',
  other: 'טיפול',
}
async function mailTo(admin: Admin) {
  const { data } = await admin.from('invoice_mail').select('email').maybeSingle()
  return String(data?.email ?? '').trim()
}
async function sendMail(to: string, subject: string, body: string, file?: { filename: string; mime: string; data: string }) {
  const url = Deno.env.get('MAIL_SCRIPT_URL')
  if (!url) return { ok: false, error: 'no MAIL_SCRIPT_URL secret' }
  let r: Response
  try {
    r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ to, subject, body, ...file }),
      redirect: 'follow',
    })
  } catch (e) {
    return { ok: false, error: 'script unreachable: ' + String(e) }
  }
  const txt = await r.text()
  let j: { ok?: boolean; error?: string } | null = null
  try {
    j = JSON.parse(txt)
  } catch (_e) {
    j = null
  }
  if (!j) return { ok: false, error: 'script bad reply ' + r.status + ': ' + txt.replace(/\s+/g, ' ').slice(0, 120) }
  if (!j.ok) return { ok: false, error: 'script: ' + String(j.error ?? 'unknown').slice(0, 200) }
  return { ok: true }
}
async function sendInvoice(admin: Admin, serviceId: string) {
  const to = await mailTo(admin)
  if (!to) return reply({ ok: true, skipped: 'no_email' })
  const { data: s } = await admin.from('services').select('id,vehicle_id,type,service_date,invoice_path').eq('id', serviceId).maybeSingle()
  if (!s || !s.invoice_path) return reply({ ok: true, skipped: 'no_invoice' })
  const { data: v } = await admin.from('vehicles').select('plate').eq('id', s.vehicle_id).maybeSingle()
  const plate = String(v?.plate ?? '').trim()
  const what = (TYPES[s.type] ?? 'טיפול') + (plate ? ' עבור רכב ' + plate : '')
  const dl = await admin.storage.from('invoices').download(s.invoice_path)
  if (dl.error || !dl.data) return reply({ ok: false, error: 'download: ' + (dl.error?.message ?? 'empty') }, 500)
  const ext = (String(s.invoice_path).match(/\.([A-Za-z0-9]{2,4})$/)?.[1] ?? 'jpg').toLowerCase()
  const out = await sendMail(to, 'חשבונית: ' + what, 'מצורפת חשבונית: ' + what + '.', {
    filename: ['invoice', plate.replace(/[^A-Za-z0-9]/g, ''), String(s.service_date)].filter(Boolean).join('-') + '.' + ext,
    mime: dl.data.type || 'image/jpeg',
    data: toB64(new Uint8Array(await dl.data.arrayBuffer())),
  })
  return reply(out, out.ok ? 200 : 502)
}

// ---------- קריאה אוטומטית של חשבונית (Claude) ----------
const INVOICE_PROMPT = [
  'This is a photo or a PDF file of a receipt or invoice for a vehicle service, repair, tires or parts from an Israeli business.',
  'It is mostly in Hebrew, may be handwritten, and may show several papers (for example an invoice and a credit card slip).',
  'Dates in Israel are day/month/year.',
  'Answer with ONLY one JSON object and nothing else:',
  '{"readable": true or false, "date": "YYYY-MM-DD" or null, "cost": number or null, "km": number or null, "garage": string or null, "plate": string or null, "summary": string or null}',
  'cost = the final total actually paid, in NIS, including VAT (for example the total to pay, or the amount on the card slip), as a plain number.',
  'km = the vehicle odometer reading, only if it is clearly written, otherwise null.',
  'garage = the business name.',
  'plate = the vehicle license plate digits only, only if a vehicle number is written, otherwise null.',
  'summary = what was done, in Hebrew, at most 60 characters, or null.',
  'Inside string values never use the double-quote character (write בע״מ with the Hebrew gershayim mark, not a plain quote). Do not use code fences.',
  'Never guess. Use null for anything that is missing or unclear.',
  'If the file is not a receipt or an invoice, answer {"readable": false}.',
].join(' ')

// מסמך ביטוח או טסט (פוליסה, קבלה, אגרת רישוי, רישיון רכב)
const EXPENSE_PROMPT = [
  'This is a photo or a PDF file of a document about a vehicle in Israel: either a vehicle insurance document (a policy, a premium payment receipt or an invoice, compulsory or comprehensive insurance),',
  'or an annual vehicle test document (a test station receipt or invoice, an annual licence fee receipt, or the vehicle licence showing its validity date).',
  'It is mostly in Hebrew, may be handwritten, and may show several papers. Dates in Israel are day/month/year.',
  'Answer with ONLY one JSON object and nothing else:',
  '{"readable": true or false, "kind": "insurance" or "test" or "other" or null, "date": "YYYY-MM-DD" or null, "cost": number or null, "until": "YYYY-MM-DD" or null, "plate": string or null, "issuer": string or null, "summary": string or null}',
  'kind = "insurance" if the document is about vehicle insurance; "test" if it is about the annual test, the licence fee or the vehicle licence validity; otherwise "other".',
  'date = the payment date, or the issue date of the document if no payment date is shown.',
  'cost = the total amount actually paid in NIS including VAT, as a plain number. For insurance use the total premium for the whole period unless the document is clearly a receipt for one instalment, then use that instalment. Use null if no amount is shown.',
  'until = the date until which the insurance or the test / licence is valid (end of the insurance period, "valid until"), otherwise null.',
  'plate = the vehicle license plate digits only, only if a vehicle number is written, otherwise null.',
  'issuer = the insurance company, test station or business name.',
  'summary = a short description in Hebrew, at most 60 characters, for example the insurance type (ביטוח מקיף, ביטוח חובה) or the kind of test document, or null.',
  'Inside string values never use the double-quote character (write בע״מ with the Hebrew gershayim mark, not a plain quote). Do not use code fences.',
  'Never guess. Use null for anything that is missing or unclear.',
  'If the file is not a vehicle insurance or test document, answer {"readable": false}.',
].join(' ')

// רישיון רכב (להוספת רכב חדש לפי צילום הרישיון)
const LICENSE_PROMPT = [
  'This is a photo or a PDF file of an Israeli vehicle licence (רישיון רכב): the document that shows the vehicle registration details and the date until which the licence is valid.',
  'It is in Hebrew, may be photographed at an angle, and may be a digital copy. Dates in Israel are day/month/year.',
  'Answer with ONLY one JSON object and nothing else:',
  '{"readable": true or false, "plate": string or null, "model": string or null, "year": number or null, "until": "YYYY-MM-DD" or null}',
  'plate = the vehicle registration number (מספר רישוי), digits only, 5 to 8 digits.',
  'model = the manufacturer (תוצר) and the commercial name (כינוי מסחרי) together, in Hebrew when it is written in Hebrew, for example "סקודה אוקטביה" or "יונדאי איוניק 6", at most 40 characters. Do not add the engine size, the trim level or the word "דגם".',
  'year = the year of manufacture (שנת ייצור) as a four digit number.',
  'until = the date until which the licence is valid (תוקף רישיון עד), which is also the date of the next annual test.',
  'Inside string values never use the double-quote character. Do not use code fences.',
  'Never guess. Use null for anything that is missing or unclear.',
  'If the file is not a vehicle licence, answer {"readable": false}.',
].join(' ')

// מוציא את ה-JSON מתשובת המודל; אם יש בו שגיאת תחביר (למשל גרשיים בשם מוסך) שולף את השדות אחד אחד
function looseJson(t: string): Record<string, unknown> | null {
  const a = t.indexOf('{')
  const b = t.lastIndexOf('}')
  if (a < 0 || b < a) return null
  const s = t.slice(a, b + 1)
  try {
    return JSON.parse(s)
  } catch (_e) {
    // ממשיכים לשליפה ידנית
  }
  const readable = s.match(/"readable"\s*:\s*(true|false)/)
  if (!readable) return null
  const date = s.match(/"date"\s*:\s*"(\d{4}-\d{2}-\d{2})"/)
  const num = (k: string) => {
    const m = s.match(new RegExp('"' + k + '"\\s*:\\s*(-?[0-9][0-9.]*)'))
    return m ? Number(m[1]) : null
  }
  const str = (k: string, after: string) => {
    const m = s.match(new RegExp('"' + k + '"\\s*:\\s*"([\\s\\S]*?)"\\s*' + after))
    return m ? m[1].replace(/\\"/g, '"') : null
  }
  return {
    readable: readable[1] === 'true',
    date: date ? date[1] : null,
    cost: num('cost'),
    km: num('km'),
    garage: str('garage', ',\\s*"plate"'),
    plate: str('plate', '[,}]'),
    summary: str('summary', '\\}$'),
    kind: (s.match(/"kind"\s*:\s*"(insurance|test|other)"/) ?? [])[1] ?? null,
    until: (s.match(/"until"\s*:\s*"(\d{4}-\d{2}-\d{2})"/) ?? [])[1] ?? null,
    issuer: str('issuer', ',\\s*"summary"'),
    year: num('year'),
    model: str('model', ',\\s*"year"'),
  }
}

async function readInvoice(admin: Admin, userId: string, image: unknown, doc = '', mime = '') {
  const expense = doc === 'expense'
  const license = doc === 'license'
  const pdf = mime === 'application/pdf'
  // רק מנהל, או נהג שמשויך אליו רכב, יכול להשתמש בשירות (כל קריאה עולה כסף קטן)
  const { data: me } = await admin.from('profiles').select('role').eq('id', userId).maybeSingle()
  if (me?.role !== 'manager') {
    if (expense || license) return reply({ ok: false, error: 'forbidden' }, 403)
    const { data: own } = await admin.from('vehicles').select('id').eq('driver_id', userId).limit(1)
    if (!own || own.length === 0) return reply({ ok: false, error: 'forbidden' }, 403)
  }
  if (typeof image !== 'string' || image.length < 100 || image.length > 7000000) {
    return reply({ ok: false, error: 'bad image' }, 400)
  }
  // קובץ PDF תקין מתחיל ב-%PDF, ובקידוד base64 זה JVBER
  if (pdf && !image.startsWith('JVBER')) return reply({ ok: false, error: 'bad image' }, 400)
  const rawKey = Deno.env.get('ANTHROPIC_API_KEY') ?? ''
  // מפתח תקין הוא תווי ASCII בלבד: זורקים רווחים, שורות חדשות ותווים בלתי נראים שנדבקו בטעות
  const key = rawKey.replace(/[^\x21-\x7E]/g, '')
  if (!key) return reply({ ok: false, error: 'missing ANTHROPIC_API_KEY' }, 500)
  const hide = (t: string) => t.split(rawKey).join('[key]').split(key).join('[key]')
  const fail = (why: string, detail: string) => {
    console.error('read fail:', hide(why).slice(0, 160), hide(detail).slice(0, 400))
    return reply({ ok: false, error: hide(why).slice(0, 160) }, 502)
  }
  const ws = Deno.env.get('ANTHROPIC_WORKSPACE_ID')
  let r: Response
  try {
    r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'x-api-key': key,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
        ...(ws ? { 'anthropic-workspace-id': ws } : {}),
      },
      body: JSON.stringify({
        model: Deno.env.get('INVOICE_MODEL') ?? 'claude-sonnet-5-5',
        max_tokens: 1500,
        messages: [{
          role: 'user',
          content: [
            pdf
              ? { type: 'document', source: { type: 'base64', media_type: 'application/pdf', data: image } }
              : { type: 'image', source: { type: 'base64', media_type: 'image/jpeg', data: image } },
            { type: 'text', text: expense ? EXPENSE_PROMPT : license ? LICENSE_PROMPT : INVOICE_PROMPT },
          ],
        }],
      }),
    })
  } catch (e) {
    return fail('ai unreachable: ' + String(e), String(e))
  }
  if (!r.ok) {
    console.error('anthropic', r.status, hide(await r.text()).slice(0, 300))
    return reply({ ok: false, error: 'ai ' + r.status }, 502)
  }
  let out: { content?: { type?: string; text?: string }[]; stop_reason?: string } | null = null
  try {
    out = await r.json()
  } catch (_e) {
    return fail('bad ai reply', 'status ' + r.status)
  }
  const text = (out?.content ?? []).map((c) => c.text ?? '').join('')
  const info = 'stop=' + out?.stop_reason + ' blocks=' + (out?.content ?? []).map((c) => c.type).join(',') + ' text=' + text
  if (text.indexOf('{') < 0) return fail('no json', info)
  const data = looseJson(text)
  if (!data) return fail('bad json', info)
  return reply({ ok: true, data })
}

Deno.serve(async (req) => {
  if (req.method === 'OPTIONS') return new Response('ok', { headers: cors })
  try {
    const url = Deno.env.get('SUPABASE_URL')!
    const secretKeys = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') ?? '{}')
    const publicKeys = JSON.parse(Deno.env.get('SUPABASE_PUBLISHABLE_KEYS') ?? '{}')
    const service = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') ?? (Object.values(secretKeys)[0] as string)
    const anon = Deno.env.get('SUPABASE_ANON_KEY') ?? (Object.values(publicKeys)[0] as string)
    const opts = { auth: { persistSession: false, autoRefreshToken: false } }
    const admin = createClient(url, service, opts)
    const body = await req.json().catch(() => ({}))
    const mode = String(body.mode ?? '')

    // 1. מי קורא: הטיימר של Supabase (עם סוד), או משתמש מחובר
    let userId = ''
    let userEmail = ''
    const cronSecret = req.headers.get('x-cron-secret')
    if (cronSecret) {
      const { data } = await admin.from('app_secrets').select('value').eq('key', 'cron').maybeSingle()
      if (!data || data.value !== cronSecret || (mode !== 'cron' && mode !== 'invoice')) {
        return reply({ ok: false, error: 'unauthorized' }, 401)
      }
    } else {
      const token = (req.headers.get('Authorization') ?? '').replace('Bearer ', '')
      const { data, error } = await createClient(url, anon, opts).auth.getUser(token)
      if (error || !data.user) return reply({ ok: false, error: 'unauthorized' }, 401)
      userId = data.user.id
      userEmail = data.user.email ?? ''
    }

    // 1ב. חשבוניות למייל: חשבונית חדשה (מהטריגר של מסד הנתונים) ומייל בדיקה (ממנהל)
    if (mode === 'invoice') {
      if (userId) return reply({ ok: false, error: 'forbidden' }, 403)
      return await sendInvoice(admin, String(body.service_id ?? ''))
    }
    if (mode === 'mailtest') {
      const { data: me } = await admin.from('profiles').select('role').eq('id', userId).maybeSingle()
      if (!me || me.role !== 'manager') return reply({ ok: false, error: 'forbidden' }, 403)
      if (!userEmail) return reply({ ok: false, error: 'no_login_email' })
      const out = await sendMail(
        userEmail,
        'בדיקה: שליחת חשבוניות',
        'זו הודעת בדיקה מאתר צי הרכב. השליחה עובדת. חשבוניות חדשות יישלחו להנהלת החשבונות כקובץ מצורף.',
      )
      return reply({ ...out, to: userEmail })
    }
    if (mode === 'read') {
      if (!userId) return reply({ ok: false, error: 'forbidden' }, 403)
      return await readInvoice(admin, userId, body.image, String(body.doc ?? ''), String(body.mime ?? ''))
    }
    if (mode === 'cron' && userId) return reply({ ok: false, error: 'forbidden' }, 403)

    const v = await vapidKeys(admin)
    const pub = b64u(cat(new Uint8Array([4]), unb64u(v.x), unb64u(v.y)))
    if (mode === 'key') return reply({ ok: true, key: pub })

    const cols = 'id,user_id,endpoint,p256dh,auth'
    const drop = async (s: Sub, status: number) => {
      if (status === 404 || status === 410) await admin.from('push_subs').delete().eq('id', s.id)
      return status === 404 || status === 410
    }

    // 2. התראת בדיקה למכשירים של המשתמש עצמו
    if (mode === 'test') {
      const { data: subs } = await admin.from('push_subs').select(cols).eq('user_id', userId)
      let sent = 0
      for (const s of (subs ?? []) as Sub[]) {
        const st = await push(s, { title: 'צי רכב', body: 'בדיקה: ההתראות עובדות', url: SITE }, v, pub)
        if (st >= 200 && st < 300) sent++
        else await drop(s, st)
      }
      return reply({ ok: true, sent })
    }

    // 3. תזכורות לנהגים שלא עדכנו ק"מ (טיימר חודשי, או מנהל שלוחץ "שלח עכשיו")
    if (mode !== 'cron' && mode !== 'now') return reply({ ok: false, error: 'bad mode' }, 400)
    if (mode === 'now') {
      const { data: me } = await admin.from('profiles').select('role').eq('id', userId).maybeSingle()
      if (!me || me.role !== 'manager') return reply({ ok: false, error: 'forbidden' }, 403)
    }
    const days = Number(body.min_days) > 0 ? Number(body.min_days) : 20
    const { data: stale, error: se } = await admin.rpc('km_stale_drivers', { min_days: days })
    if (se) return reply({ ok: false, error: 'rpc: ' + se.message }, 500)
    const first = new Map<string, { plate: string; model: string }>()
    for (const r of stale ?? []) if (!first.has(r.driver_id)) first.set(r.driver_id, r)
    const ids = [...first.keys()]
    if (ids.length === 0) return reply({ ok: true, drivers: 0, sent: 0, noPush: [], removed: 0 })
    const { data: subs } = await admin.from('push_subs').select(cols).in('user_id', ids)
    const { data: people } = await admin.from('profiles').select('id,full_name').in('id', ids)
    const byUser = new Map<string, Sub[]>()
    for (const s of (subs ?? []) as Sub[]) byUser.set(s.user_id, [...(byUser.get(s.user_id) ?? []), s])
    const noPush = ids.filter((i) => !byUser.has(i)).map((i) => (people ?? []).find((p) => p.id === i)?.full_name ?? '')
    if (body.dry) return reply({ ok: true, dry: true, drivers: ids.length, withPush: byUser.size, noPush })
    let sent = 0
    let removed = 0
    for (const [uid, list] of byUser) {
      const car = first.get(uid)!
      const message = {
        title: 'עדכון קילומטראז׳',
        body: "הגיע הזמן לעדכן קילומטראז' ל" + car.model + ' ' + car.plate,
        url: SITE,
        tag: 'km',
      }
      for (const s of list) {
        const st = await push(s, message, v, pub)
        if (st >= 200 && st < 300) sent++
        else if (await drop(s, st)) removed++
      }
    }
    return reply({ ok: true, drivers: ids.length, sent, noPush, removed })
  } catch (e) {
    console.error(e)
    return reply({ ok: false, error: String(e) }, 500)
  }
})
