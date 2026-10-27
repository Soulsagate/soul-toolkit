"""LDAP notes: the Active Directory domain nmap's version scan reported, plus the anonymous-bind
checks to run by hand. No extra connections are made."""

from __future__ import annotations

import re

from soul_toolkit.core.models import Finding, Service
from soul_toolkit.recon.modules import Context, Module, hosts_command
from soul_toolkit.recon.nmap import script_fields

LDAP_PORTS = {389: False, 636: True, 3268: False, 3269: True}  # port -> LDAPS
# nmap: "Microsoft Windows Active Directory LDAP (Domain: thm.local0., Site: Default-First-Site-Name)"
# The "0." is a well-known artifact of nmap's match line; it's not part of the domain.
_DOMAIN = re.compile(r"Domain:\s*([A-Za-z0-9.-]+?)(?:0\.)?(?:,|\s|$)")


def ad_domain(svc: Service) -> str:
    m = _DOMAIN.search(svc.extrainfo)
    if m:
        return m.group(1).strip(".").lower()
    # ldap-rootdse (only when someone runs it) has defaultNamingContext: DC=thm,DC=local
    nc = script_fields(svc.scripts.get("ldap-rootdse", "")).get("defaultNamingContext", "")
    return ".".join(p.split("=", 1)[1] for p in nc.split(",") if p.upper().startswith("DC=")).lower()


def base_dn(domain: str) -> str:
    return ",".join(f"DC={p}" for p in domain.split(".") if p)


class LdapModule(Module):
    name = "ldap"
    description = "LDAP / Active Directory: domain from nmap, anonymous-bind commands to try"

    def matches(self, svc: Service) -> bool:
        return svc.port in LDAP_PORTS or svc.name.lower() in ("ldap", "ldapssl", "globalcatldap", "globalcatldapssl")

    def run(self, ctx: Context, svc: Service) -> list[Finding]:
        # 389, 636, 3268 and 3269 are one directory: only speak up for the first LDAP port.
        first = next((s for s in ctx.result.services if s.protocol == svc.protocol and self.matches(s)), svc)
        if first is not svc:
            return []
        domain = ad_domain(svc)
        scheme = "ldaps" if LDAP_PORTS.get(svc.port, svc.tunnel == "ssl") else "ldap"
        uri = f"{scheme}://{ctx.target}" + ("" if svc.port in (389, 636) else f":{svc.port}")
        is_ad = "active directory" in svc.product.lower() or bool(domain)

        if domain:
            ctx.lead("ad-hosts", svc.port, f"Add the Windows domain {domain} to /etc/hosts",
                     "Kerberos, LDAP and SMB tools need the domain (and the DC's name) to resolve.",
                     hosts_command(ctx.target_ip(), [svc.hostname and f"{svc.hostname}.{domain}", domain]))
            search = f'ldapsearch -x -H {uri} -b "{base_dn(domain)}"'
        else:
            search = f"ldapsearch -x -H {uri} -s base namingcontexts"
        ctx.lead("ldap-anon", svc.port, "Check whether LDAP allows anonymous reads",
                 "An anonymous bind that returns objects lists users, groups and descriptions - "
                 "people leave passwords in description fields. Empty results mean anonymous reads are off.",
                 search)
        title = f"Active Directory LDAP (domain {domain})" if domain else (
            "Active Directory LDAP" if is_ad else "LDAP directory")
        detail = svc.banner + (f"; domain controller {svc.hostname}" if svc.hostname else "")
        return [Finding(self.name, svc.port, title, "info", detail.strip("; "))]
