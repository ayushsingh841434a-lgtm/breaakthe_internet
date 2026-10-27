# TASKS.md — Build checklist

## Delivered

- [x] Exact structure: `index.html`, `style.css`, `script.js`,
      `README.md`, `TASKS.md` — HTML5 + CSS3 + vanilla JS only.
      No frameworks, libraries, build step, or external resources.
- [x] Landing: logo, "BREAK THE INTERNET / INFRASTRUCTURE LAB",
      system status, Start/Pause, Reset, headline "Everything
      works. Until it doesn't.", supporting copy, "Launch
      Simulation", and an animated preview diagram.
- [x] Workspace grid: diagram (largest), failure controls,
      8 live metrics + sparkline, event timeline (60 cap,
      Clear Log, empty state), education panel with glossary.
- [x] Custom SVG diagram: Browser, DNS, Primary, Backup,
      Database, Cache — custom stroke icons, no emoji, status
      text + colour + health dot, hover/selected states, stable
      node positions, JS packets following real SVG paths
      (cyan request, lime response, red failed leg), dashed
      backup route that activates on failover.
- [x] Failure controls, all wired to real state: DNS, Database,
      Overload (queue 8 warn / 12 timeout, latency grows),
      Primary failure, Backup (standby → active on failover,
      cannot bypass DNS), Cache (hits/misses, fall-through).
- [x] Quick scenario selector: Normal, DNS, Database, Overload,
      Primary, Primary + Backup — applies real state, one timer
      set, no duplicate listeners on re-selection.
- [x] Simulation engine: central `state` object, deterministic
      request-type rotation, explicit lifecycle, honest
      DNS/cache/backup limits documented in README and panel.
- [x] Metrics from real events only: totals, success rate,
      average simulated latency, queue, active failures,
      cache hit rate, sparkline of last 24 outcomes.
- [x] Start / Pause / Resume / Reset with the semantics in
      README; reset restores the documented baseline.
- [x] Responsive: 2-column desktop workstation, stacked tablet,
      single-column mobile with horizontal scroll inside the
      diagram only (no page overflow). Touch targets ≥ 40 px
      on small screens.
- [x] Accessibility: semantic HTML, labelled buttons, focus
      rings, text + colour status, `prefers-reduced-motion`.

## Verification performed

- [x] `node --check script.js` — clean.
- [x] Checked every SVG path id referenced in `script.js`
      exists in `index.html` (7 paths), and that `index.html`
      references `style.css` and `script.js`.
- [ ] Manual browser check (recommended before presenting):
      open `index.html`, launch, trigger each scenario in turn,
      confirm packets follow the paths, counters move only on
      real outcomes, pause freezes new requests, and reset
      returns to a clean healthy baseline.

## Known simplifications (by design)

- No cached DNS resolution; no cache expiry; instant failover;
  no replication, TLS, CDN, or load-balancer model. Each is
  stated in the education panel and README, not hidden.
