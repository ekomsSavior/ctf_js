#!/usr/bin/env python3
import requests, re, os
from urllib.parse import urljoin, urlparse

# ===== Global Config (can be tweaked) =====
DEFAULT_UA = "Recon-Hunter/1.0 ek0ms"
HEADERS = {
    "User-Agent": DEFAULT_UA,
}

LOOT_DIR = "recon_loot"
os.makedirs(LOOT_DIR, exist_ok=True)

graph = {
    "domains": {},          # domain -> {js, apis, docs}
    "oauth_endpoints": set(),
    "doc_ids": set(),
    "api_endpoints": set(),
    "edges": set(),         # (src, dest)
}

PATTERN_REGEX = None        # compiled later from user input


# ===== Utility helpers =====

def save_loot(name: str, content: str):
    safe = name.replace("://", "_").replace("/", "_")
    path = os.path.join(LOOT_DIR, safe)
    with open(path, "w", encoding="utf-8", errors="ignore") as f:
        f.write(content)
    print(f"    [💾 saved] {path}")


def pretty_short(text: str, n: int = 400):
    text = text.replace("\n", " ")
    if len(text) > n:
        return text[:n] + "..."
    return text


def record_edge(src: str, dest: str):
    if not src or not dest:
        return
    graph["edges"].add((src, dest))


def normalize_url(base: str, href: str) -> str:
    """Turn a relative href into an absolute URL."""
    if href.startswith("//"):
        return "https:" + href
    if href.startswith("http://") or href.startswith("https://"):
        return href
    return urljoin(base, href)


# ===== Core HTTP / parsing =====

def try_url(url, tag=None):
    global PATTERN_REGEX
    try:
        r = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        print(f"[+] {url} -> {r.status_code}")

        # record redirects as graph edges
        if r.history:
            prev = url
            for h in r.history:
                loc = h.headers.get("Location")
                if loc:
                    dest = normalize_url(prev, loc)
                    record_edge(prev, dest)
                    prev = dest
            record_edge(prev, r.url)

        body = r.text or ""
        ctype = r.headers.get("Content-Type", "")

        if r.status_code == 200:
            interesting = False
            reasons = []

            # JSON is usually interesting
            if "application/json" in ctype.lower():
                interesting = True
                reasons.append("JSON response")

            # User-defined patterns (flags / secrets / keywords)
            if PATTERN_REGEX and PATTERN_REGEX.search(body):
                interesting = True
                reasons.append("matched custom pattern(s)")

            label = tag or "HIT"
            if interesting:
                print(f"    [🎯 {label}] reasons: {', '.join(reasons) or 'manual review'}")
                print("    ------------------------------")
                print(pretty_short(body))
                print("    ------------------------------")
                loot_name = f"{label}_{url}"
                save_loot(loot_name, body)
            else:
                print("    [✓ 200] (generic?) snippet:")
                print("    ------------------------------")
                print(pretty_short(body))
                print("    ------------------------------")

        return r
    except Exception as e:
        print(f"    [!] Error fetching {url}: {e}")
        return None


def js_deep_parse(js_url: str, domain: str):
    """Fetch and deeply parse a JS file for doc IDs, APIs, OAuth, and patterns."""
    global PATTERN_REGEX
    try:
        js_resp = requests.get(js_url, headers=HEADERS, timeout=10)
        js_data = js_resp.text
    except Exception as e:
        print(f"      [!] Error fetching JS {js_url}: {e}")
        return

    dom_entry = graph["domains"].setdefault(domain, {"js": set(), "apis": set(), "docs": set()})
    dom_entry["js"].add(js_url)

    # Numeric IDs (often doc IDs / internal IDs)
    doc_matches = re.findall(r"\b(\d{9,15})\b", js_data)
    if doc_matches:
        dom_entry["docs"].update(doc_matches)
        graph["doc_ids"].update(doc_matches)
        print("      [!] Doc-like IDs in JS:", ", ".join(sorted(set(doc_matches))))

    # API endpoints
    api_matches = re.findall(r"https?://[a-zA-Z0-9\.\-]+/[^\s'\"()<>]+", js_data)
    for api in api_matches:
        if any(x in api for x in ["api", "apis", "/v1/", "/v2/"]):
            dom_entry["apis"].add(api)
            graph["api_endpoints"].add(api)

    if "api" in js_data.lower():
        print("      [!] Found generic API references in JS")

    # OAuth / auth endpoints
    urls = re.findall(
        r"https?://[^\s\"']*(?:oauth|authorize|auth)[^\s\"']*",
        js_data,
        flags=re.IGNORECASE,
    )
    for u in urls:
        graph["oauth_endpoints"].add(u)
    if urls:
        print("      [!] OAuth/auth URLs in JS")

    # User-defined pattern hits in JS
    if PATTERN_REGEX:
        hits = PATTERN_REGEX.findall(js_data)
        if hits:
            print("      [🎯 PATTERN MATCH IN JS] examples:")
            for h in list(set(hits))[:5]:
                print(f"        -> {h}")
            loot_name = f"PATTERN_JS_{js_url}"
            save_loot(loot_name, js_data)


def fetch_js_and_links(domain):
    print(f"\n[+] Fetching JS + links from {domain}")
    graph["domains"].setdefault(domain, {"js": set(), "apis": set(), "docs": set()})

    try:
        r = requests.get(domain, headers=HEADERS, timeout=10)
    except Exception as e:
        print(f"    [!] Error fetching {domain}: {e}")
        return

    html = r.text

    # Record HTML links for the graph mapper
    links = re.findall(r'href="([^"#]+)"', html)
    for href in set(links):
        dest = normalize_url(domain, href)
        record_edge(domain, dest)

    # Collect JS srcs
    js_urls = re.findall(r'src="(.*?\.js)"', html)
    js_urls = list(set(js_urls))  # unique

    for js in js_urls:
        if js.startswith("//"):
            js = "https:" + js
        elif js.startswith("/"):
            js = domain + js

        print("    JS:", js)
        js_deep_parse(js, domain)


# ===== Reporting =====

def oauth_mapper():
    print("\n====================================================")
    print("        OAUTH / AUTH ENDPOINT MAPPER")
    print("====================================================")
    if not graph["oauth_endpoints"]:
        print("[!] No OAuth-like endpoints discovered in JS yet.")
        return

    for u in sorted(graph["oauth_endpoints"]):
        print(f"[+] OAuth-ish URL: {u}")
        params = re.findall(r"redirect_uri=([^&]+)", u)
        if params:
            for p in params:
                print(f"    redirect_uri = {p}")


def dump_graph():
    print("\n====================================================")
    print("        RECON GRAPH SUMMARY")
    print("====================================================")
    for domain, data in graph["domains"].items():
        print(f"\n[DOMAIN] {domain}")
        if data["js"]:
            print(f"  JS files ({len(data['js'])}):")
            for js in sorted(data["js"]):
                print(f"    - {js}")
        if data["apis"]:
            print(f"  API endpoints ({len(data['apis'])}):")
            for api in sorted(data["apis"]):
                print(f"    - {api}")
        if data["docs"]:
            print(f"  Doc-like IDs in JS ({len(data['docs'])}): {', '.join(sorted(data['docs']))}")

    if graph["doc_ids"]:
        print(f"\n[GLOBAL] Total unique doc-like IDs seen in JS: {len(graph['doc_ids'])}")
        print("         Sample:", ", ".join(list(sorted(graph["doc_ids"]))[:15]))

    if graph["edges"]:
        print("\n[GRAPH] Link / redirect edges:")
        by_src = {}
        for src, dest in graph["edges"]:
            by_src.setdefault(src, set()).add(dest)
        for src, dests in by_src.items():
            print(f"  {src}")
            for d in sorted(dests):
                print(f"    -> {d}")


# ===== Probing paths =====

def probe_paths(domains, paths):
    if not paths:
        print("\n[!] No extra paths configured to probe.")
        return

    print("\n====================================================")
    print("        DIRECT PATH / API PROBES")
    print("====================================================")

    for domain in domains:
        print(f"\n[+] Checking domain: {domain}")
        for path in paths:
            full = urljoin(domain, path)
            try_url(full, tag="PROBE")


# ===== Interactive CLI =====

def normalize_domain_input(raw: str):
    raw = raw.strip()
    if not raw:
        return None
    parsed = urlparse(raw)
    if not parsed.scheme:
        return "https://" + raw
    return raw


if __name__ == "__main__":
    print("\n====================================================")
    print("        INTERACTIVE RECON / FLAG HUNTER — ek0ms")
    print("====================================================")
    print("[*] This tool will:")
    print("    - Fetch JS + HTML from your targets")
    print("    - Map OAuth/auth endpoints")
    print("    - Build a simple link/redirect graph")
    print("    - Search responses/JS for custom patterns")
    print(f"[*] Loot directory: {LOOT_DIR}")

    # --- Targets ---
    targets_input = input("\n[?] Enter target domains/URLs (comma-separated): ").strip()
    raw_targets = [t.strip() for t in targets_input.split(",") if t.strip()]
    DOMAINS = []
    for t in raw_targets:
        norm = normalize_domain_input(t)
        if norm:
            DOMAINS.append(norm)

    if not DOMAINS:
        print("[!] No valid targets provided, exiting.")
        exit(1)

    print("[+] Targets loaded:")
    for d in DOMAINS:
        print("   ->", d)

    # --- Extra paths to probe ---
    paths_input = input(
        "\n[?] Enter extra paths to probe per domain (comma-separated, e.g. /api/status,/api/users) or leave blank: "
    ).strip()
    PROBE_PATHS = [p.strip() for p in paths_input.split(",") if p.strip()]

    # --- Patterns / flags to look for ---
    pat_input = input(
        "\n[?] Enter regex/strings to search for in responses/JS (comma-separated),\n"
        "    e.g. CTF\\{[^}]+\\},FLAG\\{[^}]+\\},apikey,secret\n"
        "    Leave blank for no custom pattern matching: "
    ).strip()

    patterns = []
    if pat_input:
        parts = [p.strip() for p in pat_input.split(",") if p.strip()]
        for p in parts:
            # if user gives plain word, escape it
            if not any(ch in p for ch in ".+*?[](){}|\\" ):
                patterns.append(re.escape(p))
            else:
                patterns.append(p)

    if patterns:
        combined = "(" + "|".join(patterns) + ")"
        PATTERN_REGEX = re.compile(combined, flags=re.IGNORECASE)
        print(f"[+] Compiled pattern regex: {combined}")
    else:
        PATTERN_REGEX = None
        print("[*] No custom patterns configured. Tool will still map JS/APIs/OAuth/graph.")

    # --- GO TIME ---

    # Phase 1: JS recon (discover APIs, OAuth, doc-like IDs, pattern hits in JS)
    for domain in DOMAINS:
        fetch_js_and_links(domain)

    # Phase 2: Direct path / API probing
    probe_paths(DOMAINS, PROBE_PATHS)

    # Phase 3: OAuth mapping overview
    oauth_mapper()

    # Phase 4: Graph summary
    dump_graph()

    print("\n[+] Recon complete.")
