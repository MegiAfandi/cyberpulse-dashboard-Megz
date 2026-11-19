# CyberPulse — Local Cyber Threat Intelligence Dashboard v2

Interactive local dashboard for **Cloudflare**, **Microsoft Azure public RSS**, **Microsoft 365 source links**, **NIST NVD CVE/CWE**, and **CISA KEV**. Free to run locally, with no third-party npm packages.

## Windows setup

1. Install Node.js **20+** from https://nodejs.org/ and verify with `node --version`.
2. Extract the ZIP to `C:\Cloud-Monitoring-v2` (make sure `server.mjs` and the `public` folder are in the same directory).
3. Open PowerShell:

   ```powershell
   cd C:\Cloud-Monitoring-v2
   node server.mjs
   ```

4. Open http://localhost:3000 in your browser.
5. Stop the server using `Ctrl+C`.

**Port 3000 already in use?** Stop the old `server.mjs` process with Ctrl+C in its PowerShell window, or start this app on 3001:

```powershell
$env:PORT=3001
node server.mjs
```

Then use http://localhost:3001.

## Kali / Linux

```bash
cd cyber-monitor-v2
node server.mjs
```

## How to search

- `CVE-2021-44228`: exact CVE ID.
- `CWE-79`: NVD's CWE search.
- `OpenSSL` or `Spring`: keyword search.
- Use severity, KEV, dates and sorting across all results in the selected date window, before pagination.
- The CISA KEV tab supports vendor/product/CVE filtering of the downloaded catalog.
- Click **Details** for description, CWE, CVSS score/version, published/modified dates, KEV data, and source links.

## Sources and limitations

- **Cloudflare**: official summary and incidents API. Includes actual source health, incident updates, and direct links. Data refreshed every 5 min (backend Cloudflare cache 60s).
- **Azure**: official public status RSS. **RSS reachability is not proof all Azure services are healthy**; some incidents are only in Azure Service Health for authenticated tenants. Errors show as UNVERIFIED.
- **Microsoft 365**: **UNVERIFIED** unless Microsoft Graph Service Health access is implemented. Official link is displayed, but no fake operational status. Outlook/Exchange Online tenant data is not accessible without tenant authentication.
- **NVD**: official CVE API 2.0 with server-side paging (20/page), query cache 10 min, and public API rate limiting. Default search covers the last 30 days of the selected Published / Last Modified field. Sorting and filters apply to the complete result set before pagination. Optional NVD API key using `NVD_API_KEY` environment variable (never embed it in frontend code).
- **CISA KEV**: official JSON catalog cache 6 hours. KEV-listed is evidence of known exploitation. Not-listed does **not** mean unexploited.
- **CWE** values come from NVD CVE weakness metadata, not a standalone complete CWE catalog.
- No vulnerability scanner is included; CVE search cannot confirm which software is actually installed or exploitable in your environment.
- No data is fabricated; upstream outages and rate limits are disclosed.
- This dashboard does not alter your existing ChatGPT push-alert automation.

## Official references

- https://www.cloudflarestatus.com/api
- https://azure.status.microsoft/status/feed/
- https://status.cloud.microsoft/
- https://learn.microsoft.com/en-us/graph/api/resources/service-communications-api-overview
- https://nvd.nist.gov/developers/vulnerabilities
- https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- https://cwe.mitre.org/

## Privacy / security

Listens on `127.0.0.1` only by default; do not set `HOST=0.0.0.0` unless you intend to expose your local server to other devices and have implemented access controls. API calls originate from the local backend and require outbound HTTPS access.

## v2.2 — complete date sorting fix

The old server fetched only the earliest 20 NVD results in a 30-day window, so sorting never reached November. For local severity/KEV filters or score/modified sorting, the server downloads every NVD page in the selected window, applies filters, sorts stably, and returns a 20-row UI page. Published date sorting without additional filters uses native NVD pagination (see v2.3 below). Newest/Oldest, header buttons, search and pagination all use the same complete snapshot.

- Default: last 30 days of Published or Last Modified, for keyword and CWE searches too. Exact CVE ID without dates retains all-time lookup.
- From/To are inclusive WIB days and are sent to NVD as UTC date bounds. With only To, From defaults to 30 days earlier. With only From, To defaults to now. Max span: 120 days. Future From and reversed bounds show errors.
- Scope dates and source/filtered counts are displayed under the table. This is a date-window search, not a claim to include all historical NVD records.
- Click Published / Last Modified headings repeatedly for descending (↓ newest) or ascending (↑ oldest). Sorting resets to page 1 and is global within the date window. CVSS sorting is also global within that window.
- A maximum of 40,000 source matches is allowed per complete-snapshot query; native Published pagination does not need that limit. Broader queries ask for a narrower window and never return an apparently complete partial result. Changing/incomplete NVD pagination also fails explicitly instead of hiding records.
- Upstream requests are serialized with the existing rate-limit gap. First load can take 1–2 minutes or longer on a broad window. Complete snapshots are cached 10 minutes; at most six completed query snapshots are retained. Sort and page changes reuse them. Default time bounds are rounded up to the current UTC hour to permit cache reuse; the scope is displayed explicitly.
- Stale snapshot fallback is disclosed. Failed initial queries can be retried. Out-of-order browser responses cannot overwrite a newer search. KEV-only filters fail visibly if CISA is unavailable.
- Cloud filters, provider cards, detail dialogs, themes, caches, refresh timers and external monitoring automation are preserved. Azure RSS still has no Last Modified field; Cloudflare has created/updated dates. Cloud history remains limited to the provider feed, not a persistent archive.

### Run the correct copy

Extract this ZIP, open the folder containing THIS README, server.mjs and public together, and run `node server.mjs`. Stop the older server first, or choose a separate port:

```powershell
$env:PORT=3001
node server.mjs
```

Open http://localhost:3001 and press Ctrl+F5. The footer must read **CYBERPULSE v2.3 • DATE SORT + TIMEOUT RECOVERY**. Extracting a ZIP next to an older running server does not update that server.

Run regression tests with `node --test tests/*.test.mjs`.

## v2.3 — avoid bulk downloads for the default view

- Published Newest/Oldest with Severity=All and Exploitation=All now uses one lightweight count request, then fetches just the requested 20 results from the appropriate end of the full NVD result set. It does not fetch thousands of CVEs first. This also supports keyword, CWE and exact CVE searches and the selected WIB date range.
- Date sorting and pagination cover the complete selected scope; displayed rows are not merely a reversal of the first 20 oldest CVEs. Equal timestamps retain deterministic NVD response order (reversed in descending mode).
- Last Modified, CVSS, severity and KEV filtering still use a complete snapshot for correctness. Bulk requests are now 500 records, reducing automatically to 100 on network/timeout/server failure. Narrow the date window for faster loading in these modes.
- Each NVD request has a 60-second timeout, one retry for timeout/network/429/5xx, and a rate-limited delay. Blocks (403), malformed responses and validation errors are not blindly retried. NVD availability is still required; the app does not fabricate replacement records.
- Retry NVD is provided explicitly. A failed refresh of the same successful query preserves previous rows and marks them as previous results. A failed different query clearly reports an unavailable source, not an empty CVE result. Loading text is removed on failure. Older responses still cannot overwrite a newer search.
- Cloud integrations and external automation are unchanged.

Extract to a new folder, run Start-CyberPulse.cmd, open http://localhost:3002 and confirm the footer says v2.3. Stop any older server already using that port, or set PORT to another free port before running node server.mjs. The original installed project is not modified by extracting this separate release.

