# ctf_js — Interactive Recon & Flag Hunter

- Grab HTML + JavaScript from target websites
- Look for **API endpoints**, **OAuth auth URLs**, and **doc-like IDs**
- Search for **custom patterns** in responses and JS (like `CTF{...}`, API keys, tokens, etc.)
- Build a simple **link/redirect graph** to see how pages connect
- Save interesting results into a `recon_loot/` folder

---

##  Features

-  Interactive CLI (just run it and answer questions)
-  Supports **multiple targets** at once (comma separated)
-  Optional **extra paths** per domain to probe (e.g. `/api/status`)
-  Custom **patterns/flags** with regex or plain words
-  JS deep parsing:
  - Finds JS files
  - Looks for doc IDs (big numeric IDs)
  - Extracts API endpoints
  - Detects OAuth/auth URLs
-  Simple graph output:
  - Shows who links/redirects to what (`source -> destination`)
-  Saves interesting responses and JS into `recon_loot/` for later review

---
## Clone the repo:

```bash
git clone https://github.com/ekomsSavior/ctf_js.git
cd ctf_js
```

## Run Requirements:

```bash
sudo apt update
sudo apt install -y python3 python3-pip
pip3 install requests 
````



---

## Run ctf_js framework:

```bash
cd ctf_js
python3 ctf_hunter.py
```

You’ll see an interactive menu like:

```text
====================================================
        INTERACTIVE RECON / FLAG HUNTER — ek0ms
====================================================
[*] This tool will:
    - Fetch JS + HTML from your targets
    - Map OAuth/auth endpoints
    - Build a simple link/redirect graph
    - Search responses/JS for custom patterns
[*] Loot directory: recon_loot
```

Then it will ask you a few questions.

---

##  Step 1 – Enter target websites

You’ll see:

```text
[?] Enter target domains/URLs (comma-separated):
```

You can enter:

* **Just hostnames**:

  * `example.com`
* Or **full URLs**:

  * `https://example.com`
  * `https://app.example.com`

You can list **multiple** targets separated by commas:

```text
superhuman.com,coda.io,https://app.grammarly.com
```

The script will normalize them to proper `https://` URLs if you forget the scheme.

You’ll see:

```text
[+] Targets loaded:
   -> https://superhuman.com
   -> https://coda.io
   -> https://app.grammarly.com
```

---

##  Step 2 – Enter extra paths to probe (optional)

Next prompt:

```text
[?] Enter extra paths to probe per domain (comma-separated, e.g. /api/status,/api/users) or leave blank:
```

This is where you can specify **endpoints or paths** you want to test on **each** domain.

Examples:

* For a simple API:

  ```text
  /api/status,/api/users,/api/docs
  ```

* For login / docs:

  ```text
  /login,/api/document,/v1/docs
  ```

If you don’t want to probe any specific paths, just hit **Enter** and leave it blank.

The script will automatically combine each path with each domain.
Example: if you gave domain `https://example.com` and path `/api/status`, it will probe:

```text
https://example.com/api/status
```

---

##  Step 3 – Enter patterns / flags to search for

This is the most important part for bug bounty / CTF hunting.

Prompt:

```text
[?] Enter regex/strings to search for in responses/JS (comma-separated),
    e.g. CTF\{[^}]+\},FLAG\{[^}]+\},apikey,secret
    Leave blank for no custom pattern matching:
```

You can enter **plain words** or full **regex patterns**.

###  Example: CTF-style flags

```text
CTF\{[^}]+\},FLAG\{[^}]+\}
```

This will match things like:

* `CTF{super_secret_flag}`
* `FLAG{this_is_the_flag}`

###  Example: secrets / tokens

```text
apikey,api_key,authorization,bearer,token,secret
```

The script auto-escapes simple words (like `apikey`) so you don’t have to worry about regex syntax for those.

###  Mixed example

```text
CTF\{[^}]+\},FLAG\{[^}]+\},apikey,token,secret
```

**How it works internally:**

* It combines them into one big regex:

  * `"(CTF\{[^}]+\}|FLAG\{[^}]+\}|apikey|token|secret)"`
* It searches:

  * HTML responses (200s)
  * JSON responses
  * JavaScript files

When it finds a match, it prints a **🎯 PATTERN MATCH** and saves the full body/JS to `recon_loot/`.

If you don’t want pattern matching, just press **Enter** at the prompt and skip it.

---

##  What the script actually does

Once you’ve answered the three prompts, the script runs four phases:

### 1️ JS Recon

For each target domain:

* Downloads the main page HTML.
* Extracts all `<script src="...">` JS URLs.
* Fetches each JS file and:

  * Logs doc-like numeric IDs it sees (9–15 digit numbers).
  * Logs any URLs with `/api/`, `/apis/`, `/v1/`, `/v2/`.
  * Logs OAuth/auth URLs that contain `oauth`, `authorize`, or `auth`.
  * Searches for your **custom patterns** (flags, secrets, etc.).
  * Saves JS files with matches into `recon_loot/`.

It also parses basic links (`href="..."`) off the front page and records them in a **graph**.

---

### 2️ Direct Path / API Probing

For each target domain and each extra path you entered, e.g.:

* domain: `https://example.com`
* path: `/api/status`

It will request:

```text
https://example.com/api/status
```

For each 200 OK response:

* If JSON or pattern matches → prints a 🎯 hit and saves to `recon_loot/`.
* Else → shows a short snippet so you can eyeball if it’s interesting.

Redirects (`Location` headers) are recorded as edges in the graph.

---

### 3️ OAuth Mapper

At the end, it prints any OAuth/auth-related URLs it saw in JS:

```text
====================================================
        OAUTH / AUTH ENDPOINT MAPPER
====================================================
[+] OAuth-ish URL: https://accounts.google.com/o/oauth2/v2/auth?...
    redirect_uri = https://example.com/oauth/callback
```

You can then copy/paste these into Burp or your browser to explore login flows, check `redirect_uri` behavior, etc.

---

### 4️ Recon Graph Summary

Finally, you get a high-level view of what was discovered:

* Per-domain:

  * JS files
  * APIs
  * Doc-like IDs
* Global:

  * total doc-like IDs seen
* Link / redirect edges:

```text
[GRAPH] Link / redirect edges:
  https://example.com
    -> https://example.com/login
    -> https://static.example.com/app.js
  https://example.com/login
    -> https://auth.example.com/oauth/authorize?...
```

This helps you see **how the app flows**, where auth happens, and what endpoints hang off what pages.

---

##  Where results are saved

Everything juicy gets saved under:

```text
recon_loot/
```

Example:

```text
recon_loot/
├── PROBE_https_example.com_api_status.txt
├── PATTERN_JS_https_static.example.com_assets_app.js
└── HIT_https_example.com_api_document_123456789.txt
```

If you see a 🎯 in the console, there will be a corresponding file here with the full response/JS.

---

##  Ethics & Scope

* **Only scan targets you own or have explicit permission to test.**
* Always stay within the **bug bounty / program scope**.
* Do not brute force paths, share tokens, or credentials unless the program/CTF explicitly allows it.
* This tool is for **recon, pattern discovery, and analysis**, not for password guessing or auth abuse.

---

##  Quick Example Run

```bash
python3 ctf_hunter.py
```

Inputs:

```text
[?] Enter target domains/URLs (comma-separated):
superhuman.com,coda.io

[?] Enter extra paths to probe per domain (comma-separated, e.g. /api/status,/api/users) or leave blank:
/api/status,/api/document,/v1/docs

[?] Enter regex/strings to search for in responses/JS (comma-separated),
    e.g. CTF\{[^}]+\},FLAG\{[^}]+\},apikey,secret
    Leave blank for no custom pattern matching:
CTF\{[^}]+\},FLAG\{[^}]+\},apikey,token,secret
```

Then just watch the output:

* JS files being fetched
* APIs being discovered
* OAuth URLs listed
* Any 🎯 matches and loot saved

![Screenshot 2025-10-14 111008](https://github.com/user-attachments/assets/4e6f1682-8cb5-4439-8d40-aded11fb325d)

