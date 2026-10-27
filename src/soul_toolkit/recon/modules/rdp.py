"""RDP notes: what nmap's rdp-ntlm-info already gave away (host/domain names, Windows build)
and how to use RDP once you have credentials. No extra connections are made."""

from __future__ import annotations

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module, hosts_command
from soul_toolkit.recon.nmap import script_fields

# Windows build number -> release, for the Product_Version nmap reports (e.g. 10.0.17763).
BUILDS = {
    "7600": "Windows 7 / Server 2008 R2", "7601": "Windows 7 SP1 / Server 2008 R2 SP1",
    "9200": "Windows 8 / Server 2012", "9600": "Windows 8.1 / Server 2012 R2",
    "10240": "Windows 10 1507", "14393": "Windows 10 1607 / Server 2016", "17763": "Windows 10 1809 / Server 2019",
    "19041": "Windows 10 2004", "19045": "Windows 10 22H2", "20348": "Windows Server 2022",
    "22621": "Windows 11 22H2", "26100": "Windows 11 24H2 / Server 2025",
}
BLUEKEEP_BUILDS = {"7600", "7601"}  # CVE-2019-0708 affects Windows 7 / Server 2008 R2 (and older)
NTLM_FIELDS = ("Target_Name", "NetBIOS_Domain_Name", "NetBIOS_Computer_Name", "DNS_Domain_Name",
               "DNS_Computer_Name", "DNS_Tree_Name", "Product_Version")


def windows_release(product_version: str) -> str:
    build = product_version.rsplit(".", 1)[-1]
    return BUILDS.get(build, "")


class RdpModule(Module):
    name = "rdp"
    description = "RDP: host/domain names and Windows build from nmap's NTLM info, login hints"

    def matches(self, svc: Service) -> bool:
        return svc.name.lower() == "ms-wbt-server" or svc.port == 3389

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        info = script_fields(svc.scripts.get("rdp-ntlm-info", ""))
        rows = [[k, info[k]] for k in NTLM_FIELDS if info.get(k)]
        release = windows_release(info.get("Product_Version", ""))
        if release:
            rows.append(["Windows release", release])
        detail = "Remote Desktop. " + (f"{info['DNS_Computer_Name']} ({release or 'unknown build'})"
                                       if info.get("DNS_Computer_Name") else svc.banner)
        findings = [Finding(self.name, svc.port, "RDP (Remote Desktop) is open", "info", detail.strip(),
                            {"table": {"headers": ["Field", "Value"], "rows": rows}} if rows else {})]

        domain = info.get("DNS_Domain_Name", "")
        if domain and "." in domain:
            names = [info.get("DNS_Computer_Name", ""), domain]
            ctx.lead("ad-hosts", svc.port, f"Add the Windows domain {domain} to /etc/hosts",
                     "RDP's NTLM info leaked the host and domain names. Kerberos, LDAP and SMB tools need "
                     "these names to resolve.", hosts_command(ctx.target_ip(), names))

        build = info.get("Product_Version", "").rsplit(".", 1)[-1]
        if build in BLUEKEEP_BUILDS:
            findings.append(Finding(self.name, svc.port, f"Old Windows build ({release}) - check BlueKeep",
                                    "low", "CVE-2019-0708 affects RDP on Windows 7 / Server 2008 R2. "
                                    "Run a non-intrusive scanner before assuming anything."))
            ctx.lead("rdp-bluekeep", svc.port, "Check RDP for BlueKeep (CVE-2019-0708)",
                     f"{release} is in the affected range. The Metasploit scanner module only checks; "
                     "it doesn't exploit.",
                     f'msfconsole -q -x "use auxiliary/scanner/rdp/cve_2019_0708_bluekeep; '
                     f'set RHOSTS {ctx.target}; set RPORT {svc.port}; run; exit"')

        port = f":{svc.port}" if svc.port != 3389 else ""
        ctx.lead("rdp-later", svc.port, "Keep RDP for when you have credentials",
                 "A GUI session on the box. Any Windows credentials you find (SMB, web configs, "
                 "Kerberos) are worth trying here.",
                 f"xfreerdp /v:{ctx.target}{port} /u:<user> /p:'<password>' /cert:ignore")
        return findings
