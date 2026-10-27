# BREAK THE INTERNET — Infrastructure Failure Simulator

A premium, fully local educational playground. Break simulated
infrastructure, watch requests fail, and discover what keeps the
internet running. **Nothing here touches a real server, DNS service,
or website.** All traffic, failures, and numbers are generated in
your browser by the simulation engine in `script.js`.

## Run it

No build step, no packages, no libraries, no API keys.

1. Open `index.html` directly in a modern browser
   (double-click it, or serve the folder with any static server).
2. Click **Launch Simulation**.
3. Break something: use the failure controls, or pick a quick
   scenario (DNS Failure, Database Failure, Server Overload,
   Primary Server Failure, Primary Failure with Backup).

## What is simulated

Components: Browser Client, DNS Resolver, Primary Web Server,
Backup Server, Database, Cache.

Request types, in a fixed deterministic rotation
(`db, cached, static, db, cached, db, static, cached`):

| Type | Needs database? | Survives a database failure? |
|---|---|---|
| Static content | No | Yes |
| Cached content, cache on | No (cache hit) | Yes |
| Cached content, cache off | Yes (cache miss) | No |
| Database-dependent | Yes | No |

Request lifecycle (in `script.js`, `runRequest()`):

1. Request created.
2. DNS resolution checked — if DNS has failed, the request stops
   here. **Modelled explicitly:** no cached DNS resolution is
   modelled, so every *new* request fails at DNS. This says nothing
   about pre-existing connections, which are not modelled.
3. Server route selected — primary, or backup if the primary has
   failed *and* the backup is enabled. The backup cannot bypass a
   DNS failure.
4. Server capacity checked — under overload, each request joins
   the queue. Warning at 8, timeout at 12 (configurable in
   `state.warnAt` / `state.queueLimit`).
5. Database or cache dependency evaluated, per the table above.
6. Request succeeds or fails; metrics updated; event recorded;
   response animation (lime) travels back along the same path.

## How the metrics are calculated

- **Success Rate** = successful ÷ completed (successful + failed).
  In-flight requests are counted in Total but not in the rate.
- **Average Latency** = mean of the simulated latencies of
  completed requests. Simulated latency is a *reported number*,
  not wall-clock time: base by type (static 42 ms, cache hit
  58 ms, database 110 ms) + 28 ms per queued request + 120 ms
  overload penalty + a fixed per-request variation of
  `(request number mod 5) × 7 ms`. No randomness is used, so the
  same state and request type always produce the same outcome.
  Packet animation speed is scaled for viewing and is not the
  latency number.
- **Cache Hit Rate** = cache hits ÷ (hits + misses), where a miss
  is a cached-type request that had to go to the database because
  the cache is off. Before any cached-type request runs it is "—".
- **Queue Depth** = requests waiting under overload. Arrivals:
  one every 1,600 ms normally, 650 ms under overload. Drain: one
  per second normally, one every 3 seconds under overload.
- **Active Failures** = count of DNS failed + database failed +
  primary failed + overload active. Standby backup and a disabled
  cache are intentional states, not failures.
- **Sparkline** = the last 24 completed requests (high = success,
  low = failure), drawn from real outcomes only.

## v3 — Real-world architectures (simulated only, simplified models)

- **Architecture Modes:** Generic Website, Instagram Mode, and
  WhatsApp Mode. Switching modes relabels the diagram nodes and
  changes request labels and mode-specific failures, on the same
  engine. Instagram: App → CDN Edge → Feed Service → Feed Cache /
  Sharded DB / Media Storage; CDN down = photos/reels blank but
  text loads, media down = uploads fail but cached posts load,
  feed down = feed empty but profile loads. WhatsApp: Sender →
  Connection Gateway → Message Queue → Chat Server → Message
  Store → Receiver + Push; gateway down = stuck at one tick,
  queue backlog = delayed not lost (+600 ms), push down =
  delivered but no notification, store down = live chat works
  but history won't load. The server routes encrypted blobs
  only. These are simplified educational models based on
  publicly known patterns, not Meta's actual internal code.
- **Real Outage Replay:** step-by-step replays of the 2021 Meta
  outage (BGP/DNS withdrawal) and an Instagram CDN outage, as
  simplified stories.
- **Fix-it Challenge:** a hidden break (DNS / DB / primary /
  overload, in deterministic rotation) is injected with no
  answer logged. Fix it with the correct control; the panel
  reports MTTR in seconds and a score (100 − 3 × seconds,
  minimum 10).
- **Scale Lab:** slider from 10 to 10,000,000 simulated users.
  Servers grow 1 → 1 → 1 → 2 → 4 → 8 → 16, DB shards =
  ceil(servers / 2). With auto-scale on, a queue of 4+ servers
  drains 2 per tick instead of 1; with it off, high traffic
  chokes like overload.
- **Multi-Region + Cost:** Fail Region A, enable Region B.
  Region B acts as a failover target like the backup server.
  Simulated cost = $100 base + $50 cache + $80 backup +
  $120 Region B + $20 per auto-scaled server per month.
  Availability starts at 99.90% and loses points per unmitigated
  failure (DNS 5, gateway 3, primary/Region A 3, DB 2, CDN 2,
  overload 1), floored at 90%.
- **Share a Broken Scenario:** "Copy Scenario Link" builds a
  URL hash (mode, dns, db, primary, overload, backup, cache,
  queue, cdn, gateway). Opening that link restores the same
  state. No login, no backend, no data leaves the page.
- **Manual changes needed to deploy v3:** none. Still static
  HTML/CSS/JS, no .env, no API keys, no backend, no build
  step. Deploy exactly as v2: same Vercel settings, same
  empty environment variables, or just open index.html.

## v2 — Attack Lab, demo mode, traffic lab (simulated only)

- **Attack Lab** (new nodes: Attacker / Botnet, Fake Server):
  - *DDoS flood* — red flood packets stream over the top route
    every 900 ms. Unmitigated, each flood packet adds to the
    queue (capped at the queue limit) and adds 80 ms to
    legitimate latency. *Rate limiting* drops flood packets
    instead; they are counted as blocked.
  - *DNS spoofing* — with spoofing on and DNSSEC off, requests
    divert DNS → Fake Server and fail (90 ms). With *DNSSEC
    validation* on, fake answers are rejected and attempts are
    counted as blocked.
  - *SQL injection attempts* — every 2.8 s while active. With
    the *WAF* on, attempts are blocked. With it off, the first
    successful attempt sets the database to DEGRADED and
    database-dependent requests fail integrity checks (160 ms)
    until the attack stops, when the database is restored from
    a clean snapshot in this model. No real payload, SQL, or
    exploit is supplied — attempts are red packets + a flag.
  - Mitigations start OFF so the damage is visible first, then
    you turn them ON to watch recovery. Attack stats
    (blocked / hit) are counted from real simulated events.
- **Demo mode** — "Play Demo" auto-plays 7 narrated steps
  (normal → DNS failure → restored → database failure →
  restored → primary failure with backup → restored) with a
  banner showing the current step. Any manual control stops it.
- **Traffic lab** — request-rate slider (600–3,000 ms spawn
  interval; overload uses 40% of it), traffic-mix selector
  (balanced / database-heavy / cache-heavy / static-heavy,
  each a fixed deterministic rotation), and queue-limit slider
  (6–20; warning threshold = limit − 4, minimum 4).
- **Request inspector** — under the diagram, the last completed
  request shows its id, type, exact path, outcome, and latency.
- **Component uptime** — per-component healthy seconds ÷ total
  seconds while running, updated every second. Overload counts
  as degraded for the primary; a disabled cache counts as down;
  the backup has no failure mode in this model (100%).
- **Export session report** — downloads a text summary with
  counters, rates, attack stats, uptime, and the timeline.
- **Dynamic UI** — live-feed ticker under the top bar, pulsing
  node highlights as packets arrive, animated metric bumps,
  an attack-mode border tint while any attack runs, and a
  highlighted "doesn't." in the hero headline. All motion
  respects `prefers-reduced-motion`.

## Controls

- **Start / Pause / Resume** — pausing stops new requests and
  freezes in-flight packet animation; state, counters, queue,
  and log are preserved. Resuming continues without resetting.
- **Reset** — stops the spawn timer, clears packets, queue,
  counters, latency history, and log, and restores the healthy
  baseline (backup on standby, cache on, scenario Normal).
- **Quick scenarios** — apply real simulation state, not just
  styling. Selecting one never creates a second timer: there is
  exactly one spawn timer, one clock timer, and one drain timer.
- **Clear Log** — empties the timeline; the log is capped at the
  last 60 events in any case.

## Files

- `index.html` — semantic structure: navigation, landing,
  workspace, SVG infrastructure diagram, failure controls,
  metrics, timeline, education panel.
- `style.css` — design tokens (`#101114` background, `#181A20`
  surfaces, `#1D2027` panels, `#30333B` borders, `#F2F1EC` text,
  `#C8F169` lime accent, `#5ED3E8` cyan traffic, `#F5B942`
  amber warnings, `#FF5A5A` critical failures), responsive
  layout, and `prefers-reduced-motion` support.
- `script.js` — the whole simulation engine (vanilla ES6+).
- `TASKS.md` — build checklist and verification notes.
- `PROJECT_SUMMARY.md` — presentation / viva / hackathon Q&A:
  tech stack, why it stands out, AI integration, and future scope.
- `logo.webp` — the project logo (see below).

## Logo

The BREAK THE INTERNET logo shows a globe built from connected
network nodes, split by a bold crack running through it. The globe
represents the internet itself, the nodes and lines represent the
infrastructure that holds it together — browsers, DNS, servers,
databases, and caches — and the crack represents the moment that
infrastructure fails. The electric lime stands for energy and
healthy systems, the cyan stands for live network traffic, and the
deep charcoal background gives it the feel of a developer's lab
tool. Below the globe, the name is set in strong, clean capital
letters, making the mark clear and memorable even at a small size.

Short version, for a Vercel project or portfolio: a cracked
network globe in lime and cyan on deep charcoal — the internet,
built from connected nodes, breaking at its weakest point.

What each part means:

- Globe — the internet as one connected system
- Nodes and lines — the infrastructure behind every website
- The crack — a failure breaking the chain
- Lime and cyan — healthy systems and live traffic, against a
  dark lab background

## Accessibility and honesty notes

- Status is shown with text labels as well as colour. Nodes are
  keyboard-focusable (`Tab`, `Enter` / `Space` to select).
- The simulated DNS address in the diagram is a label, not a
  real lookup. No data leaves the page.
- Known simplifications, stated in the education panel:
  cached DNS is not modelled; cache entries never expire;
  failover is instant (no health-check delay); there is no
  replication, TLS, CDN, or load balancer model.
