# CyberPulse v3 — Cloudflare Workers Free

This version runs at a workers.dev address without a local Node process, payment method, custom domain, database, KV, R2, cron or other paid bindings. The site remains available when the owner's laptop is off. Availability is subject to Cloudflare and upstream provider limits; Workers Free currently allows 100,000 invocations/day and 10 ms of CPU per invocation.

## What changed

- worker.mjs is a self-contained deployment module. It embeds the HTML, CSS, app code, date helpers and browser API client, and streams responses only from the fixed official NVD, CISA, Cloudflare and Azure sources.
- Large NVD/CISA JSON parsing, complete-window severity/KEV filtering and stable sorting execute in the visitor's browser. They no longer consume the Worker's small CPU budget. Default publication sorting still downloads a count plus the selected newest/oldest page, so November results are not hidden behind October pages.
- Broad modified-date/CVSS/severity/KEV searches may take several minutes because of NVD's rate limits. Progress is shown. Keep the visitor tab open until the search finishes; closing the owner's laptop does not stop the hosted service, but closing a visitor's tab cancels that visitor's in-progress search.
- Worker Cache API caches successful source bodies at the edge (NVD 10 minutes, KEV 6 hours, cloud sources 60 seconds). Browser search snapshots have a 10-minute TTL, two complete snapshots max. Caches are opportunistic, not persistent incident archives. NVD limits can still be shared by multiple visitors; errors and retries remain visible.
- The live UI retains CVE/CWE search, date range, ascending/descending headers, CVSS, severity/KEV filters, pagination, details, source links, cloud incidents, local WIB clock, light theme and 5-minute refresh. M365 remains unverified without tenant authentication. Existing external alert automation is not modified.
- The proxy is an allowlist, not an open proxy. It validates NVD parameters/page limits and never accepts an arbitrary destination URL. Optional NVD_API_KEY can be stored as a Cloudflare secret; it is added only to NVD requests and never sent to the frontend.

## Deploy/update

Dashboard method: create a Worker on Workers Free, open Edit code, replace the module with worker.mjs, and Deploy. The editor's filename can stay worker.js. No Node server or Docker container is required. No access tokens need to be posted into chat or committed to GitHub.

CLI/Git method: put worker.mjs and wrangler.jsonc together in the repository root, then run `npx wrangler@4 deploy` while authenticated to the intended Cloudflare account. Original server.mjs/public files can stay for local/Node hosting; the Cloudflare deployment uses the embedded assets in worker.mjs. Editing those original files alone does not update the embedded Worker bundle.

The standalone source ZIP also includes readable public/ files and client-api.js, assets.json, and tests. Run `node --test tests/*.test.mjs` for regression checks. Worker deployment itself does not require third-party application dependencies. Local tests do not emulate Cloudflare billing, CPU limits or live source availability, so verify the deployed URL too.

Verification: open /healthz, check latest published CVEs, toggle Oldest/Newest, choose a narrow date range, open Details, and inspect Cloudflare/Azure/KEV source states. Azure can validly return an empty RSS feed; availability is not overall health.

References:
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/workers/platform/pricing/
