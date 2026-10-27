# BREAK THE INTERNET — Project Summary

A complete summary for a presentation, viva, or hackathon pitch. Each answer is kept to one or two lines, technically, with a layman version where it helps.

## Elevator pitch

BREAK THE INTERNET is an educational infrastructure failure simulator that lets users deliberately break a simulated website and watch, in real time, how requests fail, recover, or reroute. It runs entirely in the browser with no backend, no database, and no real servers touched.

## 1. What is the project?

Technical: A client-side simulation engine in vanilla JavaScript that models a 6-component web infrastructure and computes request outcomes from explicit, deterministic rules.

Layman: A safe playground where you can break a fake website and see exactly why it stops working.

## 2. What problem does it solve?

Technical: Infrastructure failure is usually invisible — users only see an error page, not DNS, queueing, caching, or failover. This makes those hidden steps visible and testable.

Layman: Most people know a site is "down" but not which part broke. This shows the broken part.

## 3. Who is it for?

Students learning system design and networking, hackathon judges and presenters, and beginners who want to understand DNS, databases, caching, and redundancy without setting up real servers.

## 4. Tech stack

- HTML5 — semantic structure, no frameworks
- CSS3 — custom design system, no Tailwind or Bootstrap
- Vanilla JavaScript (ES6+) — the whole simulation engine, no React, Vue, jQuery, or libraries
- Inline SVG — the infrastructure diagram and packet animation, no external images
- No backend, no database, no API keys, no build step, no `.env` file. Open `index.html` and it runs.

## 5. Architecture

Three files only: `index.html` for structure, `style.css` for design, `script.js` for logic. All simulation state lives in one central `state` object — component health, queue, counters, latency totals, cache hits/misses, attack stats, and event history — so every panel reads the same truth.

## 6. Components simulated

Browser Client, DNS Resolver, Primary Web Server, Backup Server, Database, and Cache, plus in v2 an Attacker/Botnet node and a Fake Server node.

## 7. How does a request work?

Technical: Request created → DNS checked → server route selected → queue/capacity checked → database or cache dependency evaluated → success or failure → metrics updated → event logged → response animated back.

Layman: A packet travels from your browser to DNS to the server to the database or cache, then comes back — unless something on the way is broken.

## 8. Request types

Static content needs no database, cached content can be served from cache without a database query, and database-dependent content needs a live database. That is why a database failure does not kill everything — static and cached pages can survive.

## 9. Failure scenarios

DNS failure, database disconnection, server overload, primary server failure, backup failover, and cache on/off — plus 6 quick scenarios that apply real state, not just a visual change.

## 10. Simulated attacks (all local, no real targets)

DDoS flood with rate-limiting mitigation, DNS spoofing with DNSSEC mitigation, and SQL injection attempts with WAF mitigation. Mitigations start OFF so the damage is visible first, then ON to show recovery.

## 11. How are metrics calculated?

Success rate = successful ÷ completed requests. Average latency = mean of completed simulated latencies. Cache hit rate = hits ÷ (hits + misses). Queue warns at 8 and times out at 12 by default, and the queue limit is adjustable from 6 to 20 in v2.

Latency formula: base by type (static 42 ms, cache hit 58 ms, database 110 ms) + 28 ms per queued request + 120 ms overload penalty + 80 ms unmitigated DDoS penalty + a fixed per-request variation. It is a reported simulated number, not wall-clock time.

## 12. Why is it deterministic, not random?

Technical: Request types follow a fixed rotation and outcomes follow fixed rules, so the same state and request type always give the same result. No `Math.random()` is used for outcomes.

Layman: If you repeat the same break, you get the same result — so it can be demonstrated, tested, and explained, unlike a dashboard that just shows random numbers.

## 13. Why no backend?

Because there is nothing real to store or fetch. Keeping it client-side makes it free to host, instant to run, private (no data leaves the page), and deployable on Vercel with environment variables left empty.

## 14. Extra features in v2

Demo/presentation mode that auto-plays 7 narrated steps, traffic controls for request rate, traffic mix, and queue limit, a request inspector showing the last request's exact path, per-component uptime, live-feed ticker, and an exportable session report.

## 15. How was it tested?

`node --check` on the JavaScript, checks that every SVG path the engine uses exists in the page, and a real headless Chrome run with Playwright: 14/14 checks passed, including DNS fail/restore, DDoS + rate limiting, spoofing + DNSSEC, SQL injection degrade + restore, demo mode, export, and reset, with zero console errors.

## 16. Limitations — say these honestly in a viva

It does not model cached DNS resolutions, cache expiry, TLS, CDNs, load balancers, replication, or health-check delay. Failover is instant here; in real systems, detecting a failure takes time. These limits are stated in the education panel and README, not hidden.

## Why it stands out

Most college simulators are static dashboards or animations that only *look* alive. This one is different because: (1) metrics come from requests that actually ran through the rules, not random values; (2) failures and attacks change real state and packet routes, including backup routing that still cannot bypass a DNS failure; (3) it is honest about what it does not model; (4) it works as a live hackathon demo with presentation mode and an exportable report; and (5) it needs zero setup, zero cost, and zero backend to run or deploy.

## AI integration — questions and honest answers

Q: Does it use AI right now?
A: No. It uses a deterministic, rule-based engine plus a rule-based explainer that maps the current state to an educational explanation. That is deliberate — for teaching, a repeatable result matters more than a generated guess.

Q: Why not add an LLM now?
A: It would need API keys, cost, and network calls, and an LLM could invent metrics that contradict the simulation. The current design keeps every number provable from the state object.

Q: How could AI be added later?
A: The state object, timeline, and metrics are already structured, so an AI layer could read them directly without changing the engine — for example, an AI tutor that explains *this* failure from *these* logs, a natural-language scenario builder ("simulate a DNS outage"), an AI chaos agent that picks the next failure to test, or an AI-written incident report generated only from the exported timeline.

Q: What AI risks must be handled?
A: Grounding and hallucination: any AI explanation must be checked against the actual state and counters, never allowed to invent a failure, a number, or a component that is not in the simulation.

## Future scope

1. AI tutor and plain-English scenario creation, grounded in the live simulation state.
2. More components: CDN, load balancer, TLS handshake, message queue, and Kubernetes-style replicas.
3. Classroom and team mode: shared scenarios, quizzes, and incident-response exercises with scoring.
4. Save, share, and replay custom scenarios, plus a backend-optional multiplayer mode.
5. Real-world concepts layered on top: chaos engineering practices, monitoring alerts, and post-incident reports, while keeping the core simulation free and offline-capable.
