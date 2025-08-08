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
