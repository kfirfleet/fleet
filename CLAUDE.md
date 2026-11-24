# צי רכב (kfirfleet/fleet)

Vehicle-fleet maintenance web app for Kfir (קפיר), a dog breeder who manages a small fleet of vehicles. This file is the project memory: read it first.

## How to work with Kfir (important)
- Answer in **Hebrew only**. He is not a developer and usually works from his **phone** (sometimes a computer). He often types Hebrew on an English keyboard layout (for example `vugu,e` = `הועתק`); decode it instead of asking.
- Give **tiny steps, one stage at a time**, with exact button names in English and Hebrew (for example **Deploy updates**). Refer to files by name.
- Code and SQL for him to run go in code blocks in the chat.
- **Never ask him to paste API keys, passwords or secret URLs in chat.** Secrets go only into Supabase → Edge Functions → Secrets. Screenshots must not reveal full keys.
- Ask before deleting anything. Old leftovers in the repo (`index-.html`, `index-1.html`, `index. .html`, `index..html`) are not used, but do not remove them without his approval.

## What it is
- Single-file Hebrew RTL app: `index.html` (HTML + CSS + JS, supabase-js from a CDN). Plus `sw.js`, `manifest.json`, icons.
- Hosted on **GitHub Pages**: https://kfirfleet.github.io/fleet/ . Deploy = push to `main` (republishes in 1-2 minutes). Commit with a `Co-Authored-By` trailer.
- Backend: **Supabase** project `rodlmlsdgwqyxqaimkfm` (dashboard: https://supabase.com/dashboard/project/rodlmlsdgwqyxqaimkfm). Postgres + Auth + Storage + one Edge Function.
- Two roles: **manager** (Kfir) sees everything; **driver** sees only his vehicle (update km, add a service with invoice).

## Database (public schema, RLS on everything)
`profiles` (role manager|driver), `vehicles` (plate, model, year, km, driver_id, test_date, insurance_date, license_path, license_at, service_interval_km/months), `services` (type periodic|tires|brakes|repair|other, service_date, km, cost, garage, invoice_path), `settings`, `km_updates`, `app_installs`, `push_subs`, `app_secrets` (vapid, cron), `invoice_mail` (accounting email), `vehicle_expenses` (kind insurance|test, expense_date, amount, note, invoice_path; manager only via `public.is_manager()`).
Storage bucket `invoices` (private; allowed types include PDF): service invoices `<vehicle_id>/<uuid>.jpg|pdf`, licenses `<vehicle_id>/license-<uuid>.*`, insurance/test documents `exp/<vehicle_id>/<uuid>.*`.
The app's in-page guide ("מדריך" tab) holds the SQL for every optional feature (`sqlX`, `sqlV`, `sqlD`, ...). Kfir runs SQL himself in the Supabase SQL Editor: https://supabase.com/dashboard/project/rodlmlsdgwqyxqaimkfm/sql/new

## Edge Function `swift-handler`
- Source: `swift-handler.ts` in this repo. The same text is embedded in `index.html` as ``const kmFnCode=String.raw`...` `` (shown in the guide). **Keep both identical**; the TS must contain no backtick and no `${`.
- Kfir deploys it by hand: Supabase → Edge Functions → swift-handler → **Code** → select all → paste → **Deploy updates**. After EVERY deploy check Settings → **Verify JWT with legacy secret** is **OFF** (the function checks auth itself; ON gives 401). When the function changes, send him the full code in a chat code block and tell him the last line number so he can verify the paste.
- It authenticates itself (user JWT, or `x-cron-secret` only for modes `cron` and `invoice`). Modes: `key`, `test`, `now`, `cron` (km reminders by Web Push), `invoice` (mails a new service invoice via Google Apps Script, called by DB trigger `services_mail_invoice` through pg_net), `mailtest`, `read`.
- `read` = automatic reading with Claude (`https://api.anthropic.com/v1/messages`, model from secret `INVOICE_MODEL`, default `claude-sonnet-5-5`, about 1 cent per read, prepaid credit). Body: `{mode:'read', image:<base64>, doc:'' | 'expense' | 'license', mime:'application/pdf' (optional)}`. `doc:'expense'` (insurance/test documents) and `'license'` (vehicle licence) are manager only. Failures are logged as `read fail: <why>` in the function Logs.
- Secrets (names only): `ANTHROPIC_API_KEY`, `MAIL_SCRIPT_URL` (Apps Script web app that sends mail from the manager's Gmail), optional `ANTHROPIC_WORKSPACE_ID`, `INVOICE_MODEL`.

## Client structure (`index.html`)
- Global state `D` (profiles, vehicles, services, settings, km_updates, exp ...) filled by `load()`; `render()` draws the current tab. Manager tabs: סקירה (dash), טיפולים (hist), ניהול (mng: רכבים / נהגים / הגדרות), מדריך (help); hidden report page `ui.tab==='rep'`.
- Forms: `<form data-f="NAME">` is handled by `H.NAME(values, form)` in the `H` object (returns `[ok, message]`). Clicks: `data-a="ACTION"` handled in the click listener. Overlays: `#ed` (edit forms), `#ov` (document viewer; PDFs show an open button).
- Helpers: `shrink(file,max)` (canvas → jpeg), `prepFile` (image or PDF, PDF max 4 MB), `readInvoice(blob, doc)`, `parseInv/parseDoc/parseLic`, `svcStatus`, `docs`, `repRows/repCsv` (audit list, CSV for Excel + print).
- Features: invoice reading on service form; insurance/test payments per vehicle (`vehicle_expenses`) with auto-reading from a photo, PDF or the stored licence; adding a vehicle from a licence photo/PDF; vehicle licence storage; km reminders (push); accounting mail; "רשימת רכבים לביקורת" (ISO audit list).

## Testing
Earlier sessions tested with Playwright (Chromium) against `index.html` with a mocked `supabase-js` and a local Postgres 16 for RLS/SQL checks, plus a Node harness for the function. Those scripts are not in the repo; rebuild what you need. Always re-run a check after changing form handlers, and parse the script (`new Function(...)`) before pushing.
