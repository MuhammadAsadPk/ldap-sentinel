# 🛡️ LDAP Sentinel

**A Burp Suite extension (Jython) that hunts LDAP Injection, XPath Injection, and XXE — passively and actively — with a low false‑positive, evidence‑first detection engine and a guard‑railed Auth‑Bypass helper.**

> Created by **asad0x0** · Jython 2.7 · Burp Suite Professional

LDAP Sentinel silently watches your in‑scope Proxy traffic, derives safe test requests (one parameter at a time), and only reports a finding when it has **real proof** — a new backend parser error, a reproducible TRUE/FALSE oracle, or actual file content read off the server. Everything lands in **one findings table** with a confidence rating and copy‑ready evidence for your report.

---

## ✨ What it covers

| Class | Techniques |
|-------|-----------|
| 🔎 **LDAP Injection** | Error‑based · Boolean‑based (TRUE/FALSE diff) · Wildcard oracle · DN‑context break |
| 🧬 **XPath Injection** | Error‑based · Boolean‑based predicate injection |
| 📄 **XXE (XML External Entity)** | Reflection/DTD probe · Error‑based · Classic in‑band file read · Error‑exfil · XInclude · OOB (opt‑in) |
| 🔓 **Auth‑Bypass helper** | Manual, context‑menu, guard‑railed login‑bypass tester |

All three injection classes report into **the same tab and table**, tagged by `Type` (LDAP / XPath / XXE) — just like Burp’s own scanner groups issues.

---

## 🚀 Installation

1. Burp Suite → **Extensions → Installed → Add**
2. **Extension type:** `Python`
3. Make sure a **Jython 2.7 standalone JAR** is configured under *Extensions → Settings → Python environment*
4. Select **`ldap_sentinel.py`**
5. A new tab **“LDAP Sentinel”** appears. Done. ✅

> ⚠️ Only test systems you are **authorized** to test. The active scanner sends crafted requests, and the Auth‑Bypass helper sends real login attempts.

---

## 🧠 Detection methodology

The core idea across every module: **never trust reflection alone.** A payload echoed back proves nothing. LDAP Sentinel reports only when the server’s *behaviour* changes in a way that proves the parser/filter executed our input.

### 1️⃣ Baseline capture
Before any probe, the original request is sent and modelled into a **multi‑signal fingerprint**:
- HTTP status code
- Normalized body length (CSRF tokens, hex/base64 blobs, timestamps and digit‑runs stripped out)
- `Location` header
- Session `Set-Cookie` presence
- Success/failure keyword set (`welcome`, `invalid`, `not found`, …)
- Result‑count heuristic (`<tr>` / `<li>` / JSON array markers)

A second baseline is sent to measure the page’s **natural variance**, so dynamic pages don’t trigger false positives.

### 2️⃣ Multi‑signal diff engine
Two responses are declared *different* only when **≥ 2 independent signals** disagree. Length alone is never enough — this is what keeps noise down on busy, token‑heavy pages.

---

## 🔎 LDAP Injection methodology

**Vulnerable pattern:** `(&(uid=USER)(userPassword=PASS))` — user input concatenated straight into an LDAP search filter.

- **Stage 0 — Baseline & stability** 🧪
  Two baseline requests; if the page is inherently unstable, boolean checks are skipped and only error‑based runs.

- **Stage 1 — Error‑based** ❌
  Syntax‑break payloads `)` · `(` · `\` · `*)(`. A **new** LDAP parser error that was *not* in the baseline (`InvalidSearchFilterException`, `Bad search filter`, `javax.naming.*`, `LDAP: error code`, PHP/.NET/Python signatures) = execution evidence. Backend is fingerprinted as **ActiveDirectory** vs **OpenLDAP**.

- **Stage 1b — DN‑context break** 🧩
  Extra payloads `,` `=` `+` to catch injection inside a Distinguished Name (`InvalidNameException` / `Invalid DN syntax`).

- **Stage 2 — Boolean‑based (TRUE/FALSE)** ⚖️
  A structurally‑identical pair where only the clause can/can’t match:
  - TRUE → `VAL)(objectClass=*`
  - FALSE → `VAL)(objectClass=zzq<rand>`
  If the base value returns nothing (e.g. a login), it falls back to a wildcard pair (`*)(objectClass=*`). `objectClass=*` is used because it works on **both** AD and OpenLDAP.

- **Stage 3 — Wildcard oracle** 🃏
  `prefix*` vs `zzq<rand>*` — supporting evidence only, **never reported alone** (legit search endpoints use `*` natively).

- **Stage 4 — Confirmation** ✅
  A fresh‑token TRUE/FALSE pair must reproduce the difference before the finding is upgraded to **Certain**.

---

## 🧬 XPath Injection methodology

Runs in parallel on the same engine (XML‑backed auth / search endpoints).

- **Error‑based** ❌ — `'` · `"` · `']` · `)` → new XPath parser errors (`XPathException`, `javax.xml.xpath`, `MS.Internal.Xml`, `xmlXPathEval`, …).
- **Boolean‑based** ⚖️ — `VAL' or '1'='1` (TRUE) vs `VAL' or '1'='<n>` (FALSE), confirmed by the same multi‑signal diff.

---

## 📄 XXE methodology (OOB‑free by default)

Fires **only on XML request bodies** (`Content-Type: *xml*` or XML‑looking content). The builder injects a `DOCTYPE` after the prolog and swaps a chosen leaf element’s text for an entity reference.

- **Stage 0 — Reflection / DTD probe** 🔁
  An internal entity `<!ENTITY x "TOKEN">` whose **expansion** in the response proves DTD processing is on and that leaf is a reflected sink.

- **Stage 1 — Error‑based confirmation** ❌
  A broken entity reference forces an XML parser error (`DOCTYPE is disallowed`, `org.xml.sax`, `lxml.etree.XMLSyntaxError`, `System.Xml.XmlException`, …).

- **Stage 2 — Classic in‑band file read** 🔴 *(default ON)*
  Into a reflected sink: `file:///etc/passwd` (oracle `root:.*:0:0:`) and `file:///c:/windows/win.ini` (oracle `[fonts]`/`[extensions]`), with a **reflection guard** so our own payload echoed back is never mistaken for a real read.

- **Stage 3 — Error‑based exfil** 🔴
  Parameter‑entity trick that forces file content into a parser error message — for when there’s no reflected sink.

- **Stage 4 — XInclude** 🧷
  `xi:include parse="text" href="file://…"` for cases where the app embeds your input into its own server‑side XML and you can’t set a DOCTYPE.

- **OOB (external DTD)** 🌐 *(default OFF)*
  Opt‑in toggle, requires a host you control. **Billion‑laughs / DoS payloads are never sent.**

- 🎯 **Custom file path** field lets you target app‑specific files (`/WEB-INF/web.xml`, `file:///var/www/config.php`, …).

---

## 🔓 Auth‑Bypass helper

**Manual only** — right‑click a login request → *LDAP Sentinel: Auth bypass test*.

Guardrails 🚧
- In‑scope check (refuses out‑of‑scope targets)
- Confirmation dialog before sending real logins
- **Max‑attempts cap** (default 6)
- **Stop‑on‑success** (halts the moment a bypass lands — no lockouts/noise)

Flow ⚙️
1. Map the username/search field and password field (auto‑guessed).
2. A deliberately‑failing login is sent first to model the “fail” response.
3. The payload set is tried, each diffed against that baseline:
   `*` / `*` · `*)(objectClass=*` · `admin)(|(objectClass=*` · `admin)(|(uid=*` · `admin))%00` *(null‑byte, kept as a real NUL — not `%2500`)*
4. Each attempt is marked **LIKELY BYPASS ✅ / no change ❌**, and the first bypassing request is sent straight to **Repeater** as PoC.

---

## 🧰 Parameter coverage

- ✅ URL (GET), body (POST), **JSON** leaves, **XML** leaves, **multipart** fields
- 🔀 Optional **method swap** (test a GET param as POST and vice‑versa)
- 🛣️ Optional **path‑segment injection**
- 🍪 **Cookies are never injected**; CSRF tokens, numeric‑only IDs and static assets are skipped
- ⭐ Hinted params (`uid`, `cn`, `mail`, `username`, `login`, `dn`, `samaccountname`, …) are tested first

---

## ⚙️ Engine & performance

- 🧵 Multi‑threaded worker pool (configurable) with a shared **rate‑limiter**
- 🔁 **Dedup** per `(method, path, param, placement)` — reload a page or hit **Rescan** to re‑test
- 💰 Per‑parameter **request budget** (~11) so scans stay cheap and quiet
- 📥 **Proxy Scan** / **Sitemap Scan** buttons to sweep existing history
- 🖱️ Context menu: *Scan this request* · *Auth bypass test*

---

## 🖥️ UI & reporting

Findings table columns:
`Time · Method · URL · Where · Type · Context · Confidence · Technique · Backend · Evidence · Status · Length`

- 🎨 Colour‑coded confidence: 🔴 **Certain** · 🟠 **Firm** · 🟡 **Tentative**
- 🧷 Highlights & annotates the original request in Proxy history
- 📤 **Export CSV**, **Send to Repeater / Intruder**, **Copy URL / Request**
- 📝 Live log pane of every probe and verdict

---

## ⚙️ Configuration toggles

Enable/disable per class (LDAP / XPath / XXE) and per technique (error / boolean / wildcard / DN‑context / file‑read / XInclude / OOB), set the custom always‑true clause, XXE custom file path, OOB host, thread count, rate‑limit, max‑requests per param, and ignored extensions — all from the settings panel, applied live.

---

## 📈 Severity guidance

- 🔴 **Certain** auth‑bypass or file‑read → P1 / P2 (confirm the PoC)
- 🟠 **Firm** boolean/error on a sensitive endpoint → P2 / P3
- 🟡 **Tentative** parser error only → informational until exploitation is proven

---

## 🗺️ Roadmap ideas

- ⏱️ Time‑based blind oracle as a last‑resort confirmation
- 🧾 Blind LDAP attribute extractor (char‑by‑char) for PoC‑grade data
- 🧼 WAF/rate‑limit backoff awareness
- 💾 Finding & config persistence across reloads

---

## ⚠️ Disclaimer

LDAP Sentinel is for **authorized security testing and research only**. You are responsible for having explicit permission to test any target. The authors assume no liability for misuse.

---

## 👤 Author

**asad0x0** · [github.com/MuhammadAsadPk](https://github.com/MuhammadAsadPk)

If this tool helps you land a finding, a ⭐ on the repo is appreciated!
