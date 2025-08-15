Option Correlation TODOs:

PRs:

(1) Main one: enrichment actor + flow_options actor
--> options handling + enrichment logic

- need to finish handling the weighting on the enrichment side (DONE)

- separate code into another file and only keep actor logic in actor.rs
  --> finish moving code to cache.rs

- unit tests (thorough testing of all corner cases of enrichment logic, scoping, weigth overriding)
- otel metrics (cache sizing per peer, vrf/interface/sampling counters since we have the detection anyway...)
- performance tuning (focus on the fast path...)

Discussions:

- exploded output vs retain current structure? (keep current structure for now...)

(1b) - FieldRef+helper functions use if in aggregation as well

(2) Options data "cleanup": support cisco, huawei, 6wind options (test with most of them we have...)

- process vrf and interface options so that they're ready to be used by the generic enrichment
  --> idea send both "original" as well as cleaned up data to the enrichment actor, and send the cleaned up ones with lower weights! (idea being that if in the future vrf or interface options are sent with proper & then we would have the correct match in the cache)
  ==> pay attention because we have already scenarios where sending the original option as it is would lead in wrong correlation! (vrf_id in cisco...)

(3) Files input actor

- config.rs for configuring the weights...
  -- eventual config for enrichment (e.g. enable/disable enrichment
  (if_name/vrf_name etc...) or resampling features?) Also the weights for all
  handlers sources will go here? --> the idea is we can have multiple
  enrichment actors at different steps in the pipeline, and so we could
  configure each of them differently e.g. first one only enrich sampling
  and RD info and second one at end of chain enriches more stuff??
- for sampling and flow_to_rd map handling
- test some global scoping cases with it...

(4) Performance Optimization:

- setup a benchmark code with the pcaps from prod capture (need to capture ipfix ...)

(5) Renormalize [ Riccardo ]

- renormalize based on sampling information and put new bool IE, is renormalized

Discussion:

- ok to put field modification logic in enrichment actor or add a new actor?
  --> separate actor for this, starting project for riccardo

(6) Integrate SONATA in the new enrichment actor

- also keep in mind when changing sonata how we can integrate in yang-push pipeline as well...

Discussions:

- also discuss if we want this single enrichment actor or not
  --> alternative: still use the same enrichment actor code but keep a separate instance at the end of the pipeline...

---

1. Option Correlation

- decide where to put it (enrichment actor?)
- check generic way to implement it based on scope fields...

2. move aggregation and enrichment actors from collector to flow service...

3. Missing stuff required for migrating all flow prod to netgauze

- NetFlow v9 support..
- custom_tunnel_ips_handler --> logic to present ip_src/dst and tunnel_ip_src/dst based on all possibilities (support also more nested tunnels?) --> discuss on wednesday...
- to ms from epoch for pmacct timestamps...
- validation of transform config (only allow valid operations, force operations if we'd produce an invalid avro type....)
  --> also figure out how to prevent addition of internal config knobs...
- generalizable Agg (flow aggr config transforms) functions to more types (e.g. uint, int, bool, string) needed?
- add OTEL id to differentiate instances of a collector in the same site (e.g. some id in the otel config or another global id in the config root)
- dump spreading

OTHER IDEAS:

- PR to add print actor and move all tracing logs to std.err...

- consider arc for passing over messages in buffer?
- Transform for peer_ip_src (v4/v6 field) that in case we have ::ffff:192.168.1.1 (v4-to-v6 translation for
  socker [::]:9991 listening) will translate to 192.168.1.1
