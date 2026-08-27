# Third-party engine licenses

Sentinel's MIT core embeds or invokes the following engines. Each retains its
own license. Copyleft (GPL/AGPL) engines are **invoked as external processes
only** — never imported or vendored into the MIT core.

| Engine | Repo | License | How Sentinel uses it |
|---|---|---|---|
| subfinder | projectdiscovery/subfinder | MIT | Embedded CLI (./bin) |
| httpx | projectdiscovery/httpx | MIT | Embedded CLI (./bin) |
| nuclei | projectdiscovery/nuclei | MIT | Embedded CLI (./bin) |
| sherlock | sherlock-project/sherlock | MIT | Pip dependency, subprocess |
| prowler | prowler-cloud/prowler | Apache-2.0 | External subprocess (AWS creds) |
| **sqlmap** | sqlmapproject/sqlmap | **GPL-2.0** | External subprocess ONLY (wrapper template) |
| **sliver** | BishopFox/sliver | **GPL-3.0** | External subprocess ONLY |
| **MobSF** | MobSF/Mobile-Security-Framework-MobSF | **GPL-3.0** | External subprocess ONLY |
| **wazuh** | wazuh/wazuh | **GPL-2.0** | External subprocess ONLY |
| **fail2ban** | fail2ban/fail2ban | **GPL-2.0** | External subprocess ONLY |
| **MISP** | MISP/MISP | **AGPL-3.0** | External subprocess ONLY |
| **radare2** | radareorg/radare2 | **LGPL-3.0** | External subprocess ONLY |
| **ImHex** | WerWolv/ImHex | **GPL-2.0** | External subprocess ONLY |

> Excluded entirely: repos with **no license file** (default "all rights
> reserved"), e.g. 1N3/Sn1per, maurosoria/dirsearch, most "attack-surface"
> tools. Public-on-GitHub ≠ free-to-use.
