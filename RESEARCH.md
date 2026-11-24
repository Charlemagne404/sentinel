# Research and decisions

Sentinel follows the supplied references: Netdata for per-metric anomaly thinking, Beszel for lightweight operations, Glances and Node Exporter for host interfaces, Prometheus naming conventions, Grafana for history exploration, Linux documentation for PSI/procfs/cgroups, SQLite for local time series, uPlot for charts, and OWASP for password/session/CSRF practices.

## Decisions

| Area | Choice | Reason and trade-off |
|---|---|---|
| Runtime | One Rust/Tokio executable | Keeps collection, storage, API and notifications together without extra services. Compile cost is higher than a scripting daemon. |
| Collection | procfs/sysfs, cgroup v2, systemctl, infrequent nvidia-smi fallback | Avoids root and long-lived external agents. Some service/sensor/GPU details may be unavailable to the user account. |
| Storage | SQLite WAL, one serialized writer | Local, straightforward to back up, bounded, and adequate for one host. |
| Detection | Safety thresholds plus median/MAD, EWMA, p95, clean-point exclusion | Explainable and inexpensive. Requires 48 hours to mature; workload-conditioned and weekly models remain future work. |
| Web | Static React/TypeScript and uPlot served by Axum | No production Node process, CDN, remote font, or analytics. |
| Streaming | SSE with bounded REST history | Browser-friendly one-way updates without a WebSocket server. |
| Authentication | Argon2id, one-time local bootstrap token, hashed random session, CSRF | Small single-owner model; no organization or role system. |
| Notifications | Optional ntfy or Discord webhook, bounded worker | Opt-in outbound delivery; secrets stay in the owner-only config file. |
| AI | Disabled by default, loopback Ollama/OpenAI-compatible endpoint | On-demand explanation only; can be refused during pressure and receives bounded sanitized evidence. |
| Install | User-level systemd unit with resource and filesystem controls | No sudo, system service, lingering change, firewall modification, or public bind. |

## References

- [Netdata anomaly detection](https://learn.netdata.cloud/docs/netdata-ai/anomaly-detection)
- [Beszel](https://github.com/henrygd/beszel)
- Linux [PSI](https://docs.kernel.org/accounting/psi.html), [procfs](https://docs.kernel.org/filesystems/proc.html), and [cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [SQLite WAL](https://sqlite.org/wal.html)
- [uPlot](https://github.com/leeoniya/uPlot)
- OWASP [Password Storage](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html), [Session Management](https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html), and [CSRF Prevention](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)
- [Tailscale WireGuard networking](https://tailscale.com/kb/1035/wireguard)

Sentinel has not been benchmarked in a long-running production service session. Resource controls are starting limits, not proof that idle CPU/RSS targets have been met.
