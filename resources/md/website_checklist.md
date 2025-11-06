# What to test on each site

> **NOTE**: Below is the list of checks we can scan on each website. Most (hopefully) make sense on static/brochure-like webpages. Some of the other headers found in MDN, W3C and OWASP seem to be context specific, making them difficult to do in an automated fashion, thus I have left them out.  I did briefly look into some certificate authority (CA) checks (some in google doc), but have left them out of this list. I have also **_not_** looked into DNS checks, as I dont want to let the scope get too large. If some of these are not suitable, and we need replacements let me know, otherwise we can trim the list.  

---

## Enforce HTTPS 

### Who?

* US Binding Operational Directive (BOD 18-01) (2017)
  * Found [here](https://cyber.dhs.gov/assets/report/bod-18-01.pdf).
* US National Institute of Standards and Technology (NIST SP 800-52r2)
  * Found [here](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf).
* Canadian Centre for Cyber Security (CCCS) — ITSP.40.062
  * Found [here](https://www.cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062) and PDF [here](https://www.cyber.gc.ca/sites/default/files/itsp.40.062-guidance-on-securely-configuring-network-protocols-e.pdf).
* OWASP TLS Cheat Sheet
  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html).

### Why?

“HTTP connections can be easily monitored, modified, and impersonated; HTTPS remedies each of these vulnerabilities. HSTS ensures browsers always use an https:// connection, and removes the ability for users to click through a certificate-related warning.” — BOD 18-01 (web-friendly DHS/CISA version [here](https://www.cisa.gov/news-events/directives/bod-18-01-enhance-email-and-web-security)).

### What we will check?

* Attempt connection over `https://` and confirm TLS session established (no mixed-content on landing page).
* Record final scheme and status code after any redirects (should land on `https://`).
* (Report) Whether site also sets **HSTS** (see next section).

---

## HTTP to HTTPS Redirection & Strict-Transport-Security header (HSTS) 

### Who?

* US HTTPS-Only & HSTS guidance (US CIO) — examples and preload policy

  * Found [here](https://https.cio.gov/hsts/) and compliance guide [here](https://https.cio.gov/guide/). 
* US OMB M-15-13 HTTPS-Only Standard

  * Found [here](https://obamawhitehouse.archives.gov/sites/default/files/omb/memoranda/2015/m-15-13.pdf).
* DHS/CISA BOD 18-01 (HTTPS-only with HSTS)

  * Found [here](https://cyber.dhs.gov/assets/report/bod-18-01.pdf). 
* CCCS ITSP.40.062 (recommends modern TLS and secure configuration; references HSTS)
  * Found [here](https://www.cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062).

* OWASP HSTS Cheat Sheet
  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html).

* MDN reference for header semantics
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security). 

### Why?

* Eliminates plaintext and “SSL-strip” downgrade on first visit, blocks click-through on bad certs, locks future requests to HTTPS (and, with **preload**, even first request).

### What we will check?

* From `http://` origin: expect **3xx** redirect to `https://…` (301/308 preferred over 302/307).
* On `https://` response: presence and quality of **Strict-Transport-Security**:

  * `max-age >= 31536000` (1 year) — recommendation: one year or more. Guidance: [US CIO HSTS](https://https.cio.gov/hsts/) and MDN.
  * `includeSubDomains` recommended for gov sites. Guidance: [US CIO HSTS](https://https.cio.gov/hsts/).
  * `preload` **optional but recommended**: if present, we’ll note whether domain appears on the [HSTS preload list](https://hstspreload.org/), noted in [CIO](https://https.cio.gov/hsts/)

---

## TLS Protocol Versions (support 1.3, allow 1.2, reject 1.1/1.0/SSL)

### Who?

* IETF **RFC 8996** — *Deprecating TLS 1.0 and 1.1*

  * Found [here](https://www.rfc-editor.org/rfc/rfc8996.html) or [HTML mirror](https://datatracker.ietf.org/doc/html/rfc8996). 
* **NIST SP 800-52r2** — TLS selection/configuration; mandates modern versions for US federal systems

  * Found [here](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf). 
* **NSA** — *Eliminating Obsolete TLS* (detect/fix deprecated protocols)

  * Found [here](https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF). 
* **CCCS ITSP.40.062** — modern protocol configuration for Canada

  * Found [here](https://www.cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062). 
* (Secondary/implementation) **Mozilla Server-Side TLS** (kept current with browser ecosystem)

  * Found [here](https://wiki.mozilla.org/Security/Server_Side_TLS).)

### Why?

* TLS 1.0/1.1 lack AEAD cipher support and rely on SHA-1 in parts of the protocol; keeping legacy versions increases downgrade and misconfiguration risk.

### What we will check?

* Server **supports** TLS **1.3** and **1.2** (for compatibility).
* Server **does not** negotiate TLS **1.1/1.0** or any **SSL**).

---

## Cipher & Hash Strength (AEAD only, no RC4/3DES, no SHA-1)

### Who?

* **NIST SP 800-52r2** — FIPS-approved algorithms, prefer TLS 1.3, strong suites for 1.2.

  * Found [here](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-52r2.pdf).
* **NSA** — guidance to detect/remove obsolete cipher suites and weak KEX.

  * Found [here](https://media.defense.gov/2021/Jan/05/2002560140/-1/-1/0/ELIMINATING_OBSOLETE_TLS_UOO197443-20.PDF).
* **DHS/CISA BOD 18-01** — remove support for known-weak protocols/ciphers (e.g., RC4/3DES).

  * Found [here](https://cyber.dhs.gov/assets/report/bod-18-01.pdf).
* **CCCS** — migrate from SHA-1 and legacy algorithms; use approved AES/SHA-2/3.

  * Found [here](https://www.cyber.gc.ca/en/guidance/guidance-securely-configuring-network-protocols-itsp40062). (Within ITSP.40.062 family)
* **Mozilla Server-Side TLS** — AEAD-only (AES-GCM/ChaCha20-Poly1305) for 1.2; TLS 1.3 suites by default.

  * Found [here](https://wiki.mozilla.org/Security/Server_Side_TLS) and generator [here](https://ssl-config.mozilla.org/).

### Why?

* Legacy ciphers (RC4/3DES) and MAC-then-encrypt CBC suites have known weaknesses. **SHA-1** hashes are deprecated and increase risk of forgery/interception.

### What we will check?

* **Negotiated suite** on 1.3: one of the RFC 8446 AEAD suites (AES-GCM or ChaCha20-Poly1305).
* **Negotiated suite** on 1.2: **ECDHE + AES-GCM/ChaCha20-Poly1305** only.
* **Disabled**: RC4, 3DES, export/NULL suites.
* **Certificate/chain**: no **SHA-1** signatures. Key type/size meets modern norms (e.g., RSA-2048+ or ECDSA P-256+).
* Could also compare to Mozilla “Intermediate” profile [here](https://ssl-config.mozilla.org/).

---

## Referrer-Policy

### Who?

* **OWASP – HTTP Security Headers Cheat Sheet** - recommends setting an explicit policy on all responses. 
  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
* **MDN – Practical guide** - recommends `strict-origin-when-cross-origin` as a strong default. 
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Referrer_policy).
* **MDN – Header reference** . 
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Referrer-Policy).  

### Why?

The `Referer` header can leak the **full URL** (including query parameters) to third-party origins during navigations or embedded loads. An explicit policy reduces cross-site data leakage (tokens, internal paths, personal info in URLs). Even static sites use non static dependencies, leaking URLS (especially those with PII in the query string) can also increase the likelihood of targetted phishing. 

**For example:** An authority page loads third-party analytics. A citizen clicks a link like
`https://min.gov.ca/benefits?sin=***&case=12345`. Without a policy, the analytics beacon receives that **entire URL** in the `Referer`. With `Referrer-Policy: strict-origin-when-cross-origin`, the beacon only sees `https://min.gov.ca/`.

### What we will check

* Presence of `Referrer-Policy` with **`strict-origin-when-cross-origin`** (preferred) or stricter (`same-origin`, `no-referrer`).

---

## Anti-framing (Clickjacking) - Content-Security-Policy (CSP) `frame-ancestors` and/or `X-Frame-Options`

### Who?

* **OWASP – Clickjacking Defense Cheat Sheet** — use **CSP `frame-ancestors 'none'`** keep `X-Frame-Options: DENY` for legacy. 
  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html).
* **MDN – `X-Frame-Options`** and **CSP `frame-ancestors`** references. 
* Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/X-Frame-Options) and [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors). 

### Why?

Prevents the page from being embedded by an attacker domain to **hijack clicks** (approve, submit, pay) or to assist other attacks.

### Example

A fake survey site loads a concealed `<iframe>` of a municipal portal’s **profile** page. The victim thinks they’re clicking “Next”, but the click lands on **“Submit change of address”** behind it. Proper `frame-ancestors 'none'` (or `X-Frame-Options: DENY`) stops the embed entirely. 

### What we will check

* Prefer **`Content-Security-Policy: frame-ancestors 'none'`**.
* Fallback for legacy: **`X-Frame-Options: DENY`** or `SAMEORIGIN`. If both set, CSP takes precedence.

---

## X-Content-Type-Options: `nosniff`

### Who?

* **OWASP – HTTP Security Headers Cheat Sheet.** 
  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html).
* **MDN – header overview** (disables MIME sniffing). 
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers).

### Why?

Tells the browser **not** to guess file types. Prevents accidental execution of content when servers/CDNs mis-label types (common in mixed infrastructures).

### Example

A department hosts a “documents library.” An attacker uploads a `.txt` that is actually HTML+JS. If the server replies with a loose or missing `Content-Type`, some browsers might execute it as a page; `nosniff` forces the browser **not** to run it. The same protection helps if a third-party widget is misconfigured and returns `text/html` for a script resource. 

- **Attack**: "MIME Confusion Attack enables attacks via user generated content sites by allowing users uploading malicious code that is then executed by browsers which will interpret the files using alternate content types, e.g. implicit application/javascript vs. explicit text/plain. This can result in a "drive-by download" attack which is a common attack vector for phishing. Sites that host user generated content should use this header to protect their users. This is mentioned by VeraCode and OWASP which says the following:" 
  > This reduces exposure to drive-by download attacks and sites serving user uploaded content that, by clever naming, could be treated by MSIE as executable or dynamic HTML files.
- **Attack**: "Unauthorized Hotlinking can also be enabled by Content-Type sniffing. By hotlinking to sites with resources for one purpose, e.g. viewing, apps can rely on content-type sniffing and generate a lot of traffic on sites for another purpose where it may be against their terms of service, e.g. GitHub displays JavaScript code for viewing, but not for execution:"
  > Some pesky non-human users (namely computers) have taken to "hotlinking" assets via the raw view feature -- using the raw URL as the src for a script or img tag. The problem is that these are not static assets. The raw file view, like any other view in a Rails app, must be rendered before being returned to the user. This quickly adds up to a big toll on performance. In the past we've been forced to block popular content served this way because it put excessive strain on our servers.

### What we will check

* Header present exactly as `X-Content-Type-Options: nosniff`.

---

## Cookie security flags (`Secure`, `HttpOnly`, `SameSite`)

### Who?

* **Canadian Centre for Cyber Security – ITSM.60.005** (and PDF). 
  * Found [here](https://www.cyber.gc.ca/en/guidance/security-considerations-your-website-itsm60005) and
  * Found [here](https://www.cyber.gc.ca/sites/default/files/cyber/2022-01/ITSM-60-005-Security-considerations-for-your-website_e.pdf). (PDF)
* MDN
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/Security/Practical_implementation_guides/Cookies)

### Why?

Even "public" sites set cookies (language prefs, CSRF tokens, analytics).

* **`Secure`**: prevents cookies over HTTP.
* **`HttpOnly`**: JS can’t read cookie if XSS occurs.
* **`SameSite`**: reduces CSRF/drive-by state changes. 

### Example

A contact-form page sets a CSRF token cookie. Without `SameSite=Lax` or `Strict`, a malicious site can trigger a form POST that the browser **sends with cookies**. With `SameSite`, that cross-site POST won’t include the cookie. `HttpOnly` shields any session-ish cookie if there’s a small XSS elsewhere. 

### What we will check

* For **every** `Set-Cookie`: require **`Secure`**; require **`HttpOnly`** for session/CSRF/state cookies; require **`SameSite`** (`Lax` or stricter; `None` only with `Secure`). 

---

## `security.txt` (RFC 9116)

### Who?

* **IETF – RFC 9116** ("A File Format to Aid in Security Vulnerability Disclosure"). 
  * Found [here](https://www.rfc-editor.org/rfc/rfc9116.html) 
  * Found [here](https://datatracker.ietf.org/doc/rfc9116/). (IETF copy)
* **CISA – explainer promoting adoption.** 
  * Found [here](https://www.cisa.gov/news-events/news/securitytxt-simple-file-big-value).

### Why?

Speeds up **responsible disclosure**: researchers can quickly find the right contact/policy, reducing the time a real-world issue remains exploitable.

### Example

A researcher finds reflected XSS on a city portal. With `/.well-known/security.txt` listing `Contact: mailto:security@city.ca`, they report it the same day instead of tweeting or giving up—risk window shrinks dramatically. ([RFC Editor][8])

### What we will check

* Presence at **`/.well-known/security.txt`** (or `/security.txt`) over HTTPS; parse for key fields (`Contact`, `Policy`, etc.). 

---

## Content-Security-Policy (CSP) — **baseline on all pages**

### Who?

* **Government Digital Service (GDS) (UK Gov) – Security overview for websites** (enable CSP and move from Report-Only to enforcing). 
  * Found [here](https://gds-way.digital.cabinet-office.gov.uk/manuals/security-overview-for-websites.html).
* **OWASP – CSP Cheat Sheet.** 
  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html). 
* **MDN – CSP guide/directives** (authoritative developer reference). 
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CSP). 

### Why?

A tight allow-list for what a page can load/execute **mitigates XSS and supply-chain** incidents and doubles as an anti-framing control (`frame-ancestors`). GDS endorses rolling it out site-wide. 

### Intuitive example

A third-party widget on the homepage is compromised overnight. With a baseline CSP (`default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests`), rogue script URLs from unexpected hosts are simply **blocked**, turning a silent compromise into a visible break instead of executing on citizens’ browsers. 

### What we will check

* Presence of **CSP** with at least:
  `default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'` (and `upgrade-insecure-requests` for HTTPS-only sites).
* Flag weak patterns like wildcard `*` on `script-src` or use of `'unsafe-inline'`/`'unsafe-eval'` (informational if legacy inline scripts exist). 

---

## Permissions-Policy

### Who?

* **W3C – Permissions Policy** (standard)

  * Found [here](https://www.w3.org/TR/permissions-policy/).
* **MDN – Permissions-Policy header** (reference)
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Permissions-Policy) 
  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Permissions_Policy) (guide)

* **Chrome Developers – "Control browser features with Permissions Policy"**
  * Found [here](https://developer.chrome.com/docs/privacy-security/permissions-policy). 

### Why?

Prevents **embedded third-party content** (iframes/widgets, analytics, video/chat, maps) and even your own code from **requesting powerful browser features** (camera, mic, geolocation, clipboard, payments, USB, etc.) unless you explicitly allow it. This reduces the blast radius of supply-chain attacks and over permissive embed content.

### Example

A city site embeds a third-party chat widget. The vendor later pushes an update that auto-prompts for **microphone** access for a "voice chat" feature. With
`Permissions-Policy: microphone=(), camera=(), geolocation=()` the browser blocks the prompt entirely inside that iframe—no user data exposure, no confusing consent.

### What we will check?

* Presence of **`Permissions-Policy`** with a **deny-list for powerful features** on general pages, e.g.:
  `camera=(), microphone=(), geolocation=(), payment=(), usb=(), clipboard-read=(), clipboard-write=(), fullscreen=(), xr-spatial-tracking=()`
  (Pages that truly need a feature can be scoped to allow a specific origin.) 

---

## "Revealing" headers

### Who?

* **OWASP – Secure Headers Project** (documents **headers to remove** and provides validation tooling).

  * Found [here](https://owasp.org/www-project-secure-headers/)
  * Found [here](https://github.com/OWASP/www-project-secure-headers) (project repo)
  * Found [here](https://owasp.org/www-project-secure-headers/ci/headers_remove.json) (json, for scanning tool)
* **OWASP – HTTP Security Response Headers Cheat Sheet** (general guidance on header hardening).

  * Found [here](https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html). 
* **MDN – Header reference** (describes legacy/banner headers like `X-Permitted-Cross-Domain-Policies`, `X-Powered-By`, etc.).

  * Found [here](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers).

### Why?

Server banners and framework/version headers (e.g., **`Server`**, **`X-Powered-By`**, **`X-AspNet-Version`**, **`X-AspNetMvc-Version`**) **help fingerprint the stack** and speed targeted exploitation (e.g., “version X.Y.Z has RCE CVE-####”). They also leak operational details that aid phishing and reconnaissance. Cleaning them is a low-friction privacy & security win recommended by the OWASP Secure Headers Project.

**For example:** An attacker scrapes thousands of government pages and filters for `Server: Apache/2.4.49` (a version with a known path traversal/RCE). Exposed version banners let them **pinpoint a vulnerable subset** instantly; removing or genericizing these headers denies that shortcut. 

### What we will check?

* **Look for headers listed by the OWASP Secure Headers Project as candidates to remove**. Flaggin the presence of common banners and **any obvious version strings** (e.g., `X-Powered-By: Express 4.17.1`, `Server: nginx/1.18.0`).
* Result classification: **Pass** (none or genericized: e.g., `Server: cloud`), **Warn** (banner present without versions), **Fail** (explicit product + version).

---

## Error Pages (404/410) & Edge Responses

### Who?

* **OWASP – Improper Error Handling** (don’t disclose internals; return simple, generic errors). 
  * Found [here](https://owasp.org/www-community/Improper_Error_Handling).
* **OWASP WSTG – Testing for Improper Error Handling** (how to test; errors reveal internals). 
  * Found [here](https://owasp.org/www-project-web-security-testing-guide/stable/4-Web_Application_Security_Testing/08-Testing_for_Error_Handling/01-Testing_For_Improper_Error_Handling). 
* **OWASP Top 10 A05:2021 – Security Misconfiguration** (stack traces / verbose errors are misconfig). 
  * Found [here](https://owasp.org/Top10/A05_2021-Security_Misconfiguration/). 
* **MITRE CWE-209** – Information exposure via error messages. 
  * Found [here](https://cwe.mitre.org/data/definitions/209.html). 
* **MDN – HTTP 404 / 410** (reference). 
  * [404](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/404)
  *  [410](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Status/410). 

### Why?

Error handlers often run on a different layer (proxy/app server) and drop security headers or leak stack/framework details. Even a static site can expose:

* framework & **version** (useful for targeted exploits),
* **paths/queries/SQL** fragments (aid injection & reconnaissance),
* wrong **status codes** (soft-404s) that enable phishing/SEO abuse.
  OWASP and CWE recommend **generic errors to users** and detailed logging **server-side only**. 

### What we will check?

* First source top N programming languages:
  * [Stack Overflow Dev Survey](https://survey.stackoverflow.co/2024/technology#1-programming-scripting-and-markup-languages)
  * [Browser Stack](https://www.browserstack.com/guide/best-language-for-web-development)
  * [Regex Patterns](https://regex101.com/r/uU1vQ6/1)

Languages: 
```
JavaScript / TypeScript (Node.js)
Python
Java
C#/.NET
PHP
Go
Ruby
```
<!-- 
We send **one GET** to a clearly nonexistent path and compare with the normal 200 page. 500's are probably too invasive.

1. **Header parity on 404/410**

   * Expect the same protections as 200s: **HSTS**, **CSP**, **X-Content-Type-Options**, **Referrer-Policy**, **X-Frame-Options / `frame-ancestors`**, **CORP**, **Permissions-Policy**.
   * **Fail** if missing on errors but present on 2xx (got worse).
   * **Optionally**: Also verify a sane `Content-Type` (e.g., `text/html; charset=utf-8`) and **`nosniff`**.
     *(OWASP A05 / headers guidance.)* 

2. **Status correctness**

   * 404 for missing, 410 when permanently removed. If body looks like "not found" but status is 2xx, well flag it as a soft-4xx. Some sources recommend this, Example: [here](https://owasp.org/www-community/controls/Blocking_Brute_Force_Attacks) and [here](https://owasp.org/www-community/Improper_Error_Handling).
  > "One simple yet surprisingly effective solution is to design your Website not to use predictable behavior for failed passwords. For example, most Web sites return an “HTTP 401 error” code with a password failure, although some web sites instead return an “HTTP 200 SUCCESS” code but direct the user to a page explaining the failed password attempt. This fools some automated systems, but it is also easy to circumvent."

1. **Body leak detection (regex)**

   * **Stack traces / frameworks** (warn high if version seen) (regex):
   * **File paths & env** (warn) (regex):
   * **SQL/ORM errors** (warn) (regex):
   * **Directory listing** (fail) (regex):
      * (Reasoning: CWE-209 / OWASP WSTG show error messages can reveal DB/stack/paths.)* 
      * Source [here](https://cwe.mitre.org/data/definitions/209.html)
  
 2. **Caching of error pages**
  * Warn if a personalized/dynamic error appears cacheable (e.g., long `max-age` public). Prefer `no-store` for dynamic error pages. (OWASP) -->
<!-- 
### Example Algorithm

```text
1. Pick UUID path: `/__scan__/<uuid>`
2. GET it (once). Capture: status, headers, first ~3KB of body.
3. Compare required headers with the site’s main 200 response.
4. Regex body with the patterns above.
5. Optional single XSS reflection check** using the `<script>alert(1)</script>` suffix.
6. Never trigger a 5xx(no fuzzing/POST's)
```
### What to Report -->

* **Header parity:** list any protections missing on 404/410 vs 200.
* **Status correctness:** 404/4xx vs soft-4xx.
* **Leaks found:** banners/frameworks (and versions), stack trace, SQL strings, directory listing (with short snippet).
* **Reflected XSS on error page:** yes/no.

---

## TODO List For The Tool

> Below is what I would need to implement in the code to add checks for these features. Most of the above is already implemented. I just need to update some of the parsing logic to check for more specific header parameters. The error page checks will need to be fully implemented.

#### Cipher & Hash Strength

* Update tests for RC4/3DES/CBC to check the direct SSL suites (not generic strings, sweedish did just a str).
* Check signature hash family and key size/type.
* NOTE: Might need to use PyOpenSSL for this, I am not sure OpenSSL has support for all of these. I have used OpenSSL as the sweedish code used it.

#### Anti-framing (CSP `frame-ancestors` / X-Frame-Options)

* Update CSP header parser to check for `frame-ancestors`

#### `security.txt`

* Add check to validate fields (`Contact`, `Expires`), basic URL/mailto syntax. (Optional, I already check for security.txt in `/` and `.well-known`)

#### Content-Security-Policy (baseline)

* Update parser to include all of: `default-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`, `form-action 'self'`

#### Permissions-Policy

* Parse header and deny-list (e.g., `camera=(), microphone=(), geolocation=()`).
* Current check only looks for `=*`

#### Error Pages (404/410) & Edge Responses

* This needs to be fully implemented, there is nothing in the tool.