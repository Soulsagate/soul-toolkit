from soul_toolkit.core.log import Logger
from soul_toolkit.core.models import HostResult, Service
from soul_toolkit.recon import leads
from soul_toolkit.recon.modules import Context, Options, hosts_command, ldap, rdp, winrm
from soul_toolkit.recon.nmap import script_fields

# rdp-ntlm-info output as documented in nmap's rdp-ntlm-info.nse (@output)
NTLM = ("\n  Target_Name: W2016\n  NetBIOS_Domain_Name: W2016\n  NetBIOS_Computer_Name: W16GA-SRV01\n"
        "  DNS_Domain_Name: W2016.lab\n  DNS_Computer_Name: W16GA-SRV01.W2016.lab\n  DNS_Tree_Name: W2016.lab\n"
        "  Product_Version: 10.0.14393\n  System_Time: 2019-06-13T10:38:35+00:00")
# -sV line built from nmap-service-probes' AD LDAP match (p/.../ i/Domain: $3.$4, Site: $2/ h/$1/)
AD_LDAP = Service(389, name="ldap", product="Microsoft Windows Active Directory LDAP",
                  extrainfo="Domain: w2016.lab0., Site: Default-First-Site-Name", hostname="W16GA-SRV01")


def make_ctx(tmp_path, services=()):
    return Context(target="10.10.10.10", outdir=tmp_path, log=Logger(quiet=True, colour=False),
                   result=HostResult("10.10.10.10", services=list(services)), options=Options())


def test_script_fields():
    f = script_fields(NTLM)
    assert f["DNS_Computer_Name"] == "W16GA-SRV01.W2016.lab" and f["System_Time"].startswith("2019-06-13T10")
    assert script_fields("Message signing enabled but not required") == {}


def test_hosts_command_is_order_independent():
    a = hosts_command("10.10.10.10", ["W2016.lab", "W16GA-SRV01.W2016.lab", ""])
    b = hosts_command("10.10.10.10", ["w16ga-srv01.w2016.lab.", "w2016.lab"])
    assert a == b == "echo '10.10.10.10 w16ga-srv01.w2016.lab w2016.lab' | sudo tee -a /etc/hosts"


# ----------------------------------------------------------------- rdp


def test_rdp_ntlm_info(tmp_path):
    svc = Service(3389, name="ms-wbt-server", product="Microsoft Terminal Services", scripts={"rdp-ntlm-info": NTLM})
    ctx = make_ctx(tmp_path, [svc])
    [f] = rdp.RdpModule().run(ctx, svc)
    rows = dict(f.data["table"]["rows"])
    assert rows["DNS_Domain_Name"] == "W2016.lab" and rows["Windows release"] == "Windows 10 1607 / Server 2016"
    kinds = {x.kind: x for x in ctx.result.leads}
    assert kinds["ad-hosts"].command == "echo '10.10.10.10 w16ga-srv01.w2016.lab w2016.lab' | sudo tee -a /etc/hosts"
    assert kinds["rdp-later"].command == "xfreerdp /v:10.10.10.10 /u:<user> /p:'<password>' /cert:ignore"
    assert "rdp-bluekeep" not in kinds


def test_rdp_old_build_bluekeep(tmp_path):
    ntlm = NTLM.replace("10.0.14393", "6.1.7601")
    svc = Service(3390, name="ms-wbt-server", scripts={"rdp-ntlm-info": ntlm})
    ctx = make_ctx(tmp_path, [svc])
    findings = rdp.RdpModule().run(ctx, svc)
    assert findings[1].title == "Old Windows build (Windows 7 SP1 / Server 2008 R2 SP1) - check BlueKeep"
    kinds = {x.kind: x for x in ctx.result.leads}
    bluekeep = kinds["rdp-bluekeep"].command
    assert "cve_2019_0708_bluekeep" in bluekeep and "set RPORT 3390" in bluekeep
    assert kinds["rdp-later"].command.startswith("xfreerdp /v:10.10.10.10:3390 ")


def test_rdp_without_scripts(tmp_path):
    svc = Service(3389, name="ms-wbt-server", product="Microsoft Terminal Services")
    ctx = make_ctx(tmp_path, [svc])
    [f] = rdp.RdpModule().run(ctx, svc)
    assert f.data == {} and [x.kind for x in ctx.result.leads] == ["rdp-later"]


# ----------------------------------------------------------------- winrm


def test_winrm(tmp_path):
    ctx = make_ctx(tmp_path)
    [f] = winrm.WinrmModule().run(ctx, Service(5985, name="http", product="Microsoft HTTPAPI httpd", version="2.0"))
    assert f.detail.startswith("HTTP transport")
    assert ctx.result.leads[0].command == "evil-winrm -i 10.10.10.10 -u <user> -p '<password>'"
    ctx = make_ctx(tmp_path)
    winrm.WinrmModule().run(ctx, Service(5986, name="wsmans"))
    assert ctx.result.leads[0].command == "evil-winrm -i 10.10.10.10 -S -u <user> -p '<password>'"
    assert winrm.WinrmModule().matches(Service(5985, name="http"))


# ----------------------------------------------------------------- ldap


def test_ad_domain_parsing():
    assert ldap.ad_domain(AD_LDAP) == "w2016.lab"  # nmap's trailing "0." artifact removed
    assert ldap.ad_domain(Service(389, extrainfo="Domain: thm.local, Site: Default")) == "thm.local"
    rootdse = Service(389, scripts={"ldap-rootdse": "  defaultNamingContext: DC=spooky,DC=local\n"})
    assert ldap.ad_domain(rootdse) == "spooky.local"
    assert ldap.ad_domain(Service(389, name="ldap", product="OpenLDAP")) == ""
    assert ldap.base_dn("thm.local") == "DC=thm,DC=local"


def test_ldap_active_directory(tmp_path):
    gc = Service(3268, name="ldap", product=AD_LDAP.product, extrainfo=AD_LDAP.extrainfo)
    ctx = make_ctx(tmp_path, [AD_LDAP, gc])
    [f] = ldap.LdapModule().run(ctx, AD_LDAP)
    assert f.title == "Active Directory LDAP (domain w2016.lab)" and "W16GA-SRV01" in f.detail
    kinds = {x.kind: x for x in ctx.result.leads}
    assert kinds["ldap-anon"].command == 'ldapsearch -x -H ldap://10.10.10.10 -b "DC=w2016,DC=lab"'
    assert kinds["ad-hosts"].command == "echo '10.10.10.10 w16ga-srv01.w2016.lab w2016.lab' | sudo tee -a /etc/hosts"
    assert ldap.LdapModule().run(ctx, gc) == []  # one directory, one set of notes


def test_ldap_plain(tmp_path):
    svc = Service(636, name="ldapssl", product="OpenLDAP", tunnel="ssl")
    ctx = make_ctx(tmp_path, [svc])
    [f] = ldap.LdapModule().run(ctx, svc)
    assert f.title == "LDAP directory"
    assert ctx.result.leads[0].command == "ldapsearch -x -H ldaps://10.10.10.10 -s base namingcontexts"


def test_rdp_and_ldap_share_one_hosts_lead(tmp_path):
    svc = Service(3389, name="ms-wbt-server", scripts={"rdp-ntlm-info": NTLM})
    ctx = make_ctx(tmp_path, [svc, AD_LDAP])
    rdp.RdpModule().run(ctx, svc)
    ldap.LdapModule().run(ctx, AD_LDAP)
    ranked = leads.rank(ctx.result.leads)
    assert [x.kind for x in ranked].count("ad-hosts") == 1
