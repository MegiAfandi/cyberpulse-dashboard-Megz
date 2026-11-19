# Publish CyberPulse on Render Free

This folder is ready for a GitHub repository. Upload its CONTENTS to the repository root: server.mjs, public/, tests/, package.json, render.yaml, .node-version and .gitignore must be together. Do not upload the ZIP itself or put the project inside a second nested folder. No API keys or payment information are included.

1. Create a private GitHub repository named cyberpulse-dashboard and upload these files. A private source repository does not make the deployed dashboard private: this version has no login and the website will be publicly accessible.
2. Sign in to https://dashboard.render.com/. If you are creating a new account, review and accept its terms yourself. Choose the free workspace option; do not add a payment method or select a paid plan.
3. Create New > Blueprint and select the repository. Allow Render access to ONLY this repository when GitHub asks. Review the configuration: exactly one web service, plan Free, Singapore, no database or disk. render.yaml supplies the other settings.
4. Deploy the Blueprint. The build runs the regression tests, then starts the server. The health check at /healthz only checks the app, so a slow NVD/CISA source cannot prevent server startup.
5. Open the actual onrender.com URL from the successful deploy; the service name is not a guarantee that a particular subdomain is available. Check /healthz, Published Newest/Oldest, November date bounds, CVE details, CISA KEV, Cloudflare and Azure feeds. A successful deploy does not prove that external providers are reachable from the hosting region.

Manual Web Service alternative:

| Setting | Value |
|---|---|
| Runtime | Node |
| Instance | Free |
| Root directory | Blank (project at repository root) |
| Build command | npm test |
| Start command | npm start |
| Health check | /healthz |
| Environment | HOST=0.0.0.0; NODE_ENV=production |
| Port | Use Render's provided PORT; do not set it to the local launcher port |

NVD_API_KEY is optional. If you have one, add it as a secret environment variable in Render; never put it in GitHub, the frontend, a screenshot, or this document. No key is required to start the app.

The Free service sleeps after 15 minutes without inbound traffic. Initial access can take roughly a minute to wake it. In-memory source caches are lost on restart, and broad modified-date/severity/KEV queries may take several minutes. No always-on monitoring service is created; the existing external automation is unchanged. Do not add artificial keep-alive traffic to defeat the free tier's idle behavior.

Cost: render.yaml explicitly selects plan free and creates no paid resources. Stay within included usage; without a payment method, exceeding applicable quotas can suspend services/builds rather than incur usage charges. If Render requests a card or a paid upgrade, stop and review instead of continuing automatically. Review current terms at https://render.com/docs/free.

This release keeps the local launcher and localhost defaults; Render sets HOST explicitly to expose the hosted instance. To test locally, run npm test then npm start. On the hosting server use Node 24 (pinned by .node-version).

References: https://render.com/docs/blueprint-spec and https://render.com/docs/node-version.
