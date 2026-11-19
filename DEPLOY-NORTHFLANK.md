# CyberPulse on Northflank Sandbox

Northflank's Sandbox pricing page currently advertises no card needed, two services, two jobs, one database, and up to $20/month of included Northflank Cloud resources. Use only one Sandbox service for this app, the smallest Sandbox-compatible compute plan, and one replica. No database, volume, job, BYOC infrastructure, paid upgrade or payment method is required for this configuration.

1. Sign in or create an account at https://app.northflank.com/. Complete account verification and acceptance of terms yourself. Choose Sandbox, not Pay as you go. If onboarding asks for a card, stop and review rather than adding one automatically.
2. Create a Sandbox project on Northflank Cloud. Choose an available region close to your users; verify the selected resource plan is included in Sandbox.
3. Create a Combined service (build and deploy). Select the existing GitHub repository MegiAfandi/cyberpulse-dashboard-Megz, branch main. If using the GitHub integration, limit access to this repository when possible. A permission grant may require you to approve it.
4. Choose Dockerfile build, path /Dockerfile, build context repository root. The Dockerfile uses Node 24, copies only app/test files, runs npm test, and starts node server.mjs as a non-root user. No npm dependency installation is needed.
5. Expose container port 8080 using HTTP and Public accessibility. Northflank generates a public HTTPS address. HOST=0.0.0.0, PORT=8080, and NODE_ENV=production are already set by the Dockerfile. Use /healthz for an HTTP health check.
6. Keep one replica and the included Sandbox compute size. Review the cost estimate before creating the service; do not upgrade the account or select paid resources.
7. Wait for build/deploy success and open the generated HTTPS URL. Verify /healthz, provider feeds, Newest/Oldest publication sorting, date bounds and CVE details from that hosting region. Deployment success alone does not verify upstream NVD/CISA reachability.

The dashboard has no login and will be publicly accessible. API keys are optional and must only be added as runtime secrets, never committed to GitHub. In-memory caches are lost on restart. Source availability and NVD rate limits still apply. Existing external alert automation is unchanged.

The Dockerfile can also be tested locally with Docker, if installed:

```
docker build -t cyberpulse-dashboard .
docker run --rm -p 8080:8080 cyberpulse-dashboard
```

Reference: https://northflank.com/pricing and https://northflank.com/docs/v1/application/getting-started/build-and-deploy-your-code.
