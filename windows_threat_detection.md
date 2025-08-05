**DISCLAIMER:** This project is for ***educational purposes only***. All attacks were performed in a controlled lab environment on devices I own. Never use these techniques on unauthorized networks or systems.
<br><br>

**Lab Setup:**

1) Splunk Enterprise on target windows host with logs ingested from Event Logs and Sysmon.
2) Atomic Red Team (ART) on target windows host.
<br><br>

**Attacks to be simulated:**

| MITRE ID    | Tactic                                   | Technique                            | Description                                                             |
|-------------|-------------------------------------------|---------------------------------------|-------------------------------------------------------------------------|
| T1059.001   | Execution                                 | Encoded PowerShell Execution         | Running PowerShell with Base64-encoded commands to evade detection.     |
| T1003.001   | Credential Access                         | Credential Theft with Mimikatz       | Using Mimikatz to extract plaintext credentials or hashes from LSASS.   |
| T1218.005   | Execution                                 | mshta.exe Execution                  | Abusing `mshta.exe` to execute malicious scripts or commands.           |
| T1547.001   | Persistence                               | Registry Persistence via Run Key     | Adding entries to Windows Run keys for persistence across reboots.     |
| T1070.002   | Defense Evasion                           | Delete USN Journal with FSUtil       | Clearing the USN Journal to hide file system changes from forensics.   |
| T1003.001   | Credential Access                         | LSASS Dump with Procdump             | Dumping LSASS memory with Procdump to extract credentials offline.     |
| T1548.001   | Privilege Escalation / Defense Evasion    | UAC Bypass with Fodhelper            | Exploiting `fodhelper.exe` to bypass UAC and execute code as admin.    |

<br><br>

**Splunk SPL Filters for each attack:**
<br><br>

Encoded Powershell Execution

*index=\*
<br>EventCode=1 
<br>Image=\*powershell.exe\* 
<br>(CommandLine="\*-enc\*" OR CommandLine="\*-EncodedCommand\*" OR CommandLine="\*-e \*")*
<br><br>

Credential Theft With Mimikatz

*index=\*
<br>EventCode=1 
<br>(CommandLine="\*mimikatz\*" OR Image="\*mimikatz.exe")*
<br><br>

mshta.exe Execution

*index=\*
<br>EventCode=1
<br>Image="\*mshta.exe\*" OR CommandLine="\*mshta\*"*
<br><br>

Registry Persistence via Run Key

*index=\* 
<br>TargetObject="\*Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ \*"*
<br><br>

Delete USN Journal with FSUtil

*index=\* 
<br>(Image="\*\\fsutil.exe" AND CommandLine="\*usn deletejournal\*")*
<br><br>

LSASS Dump with Procdump

*index=\* 
<br>EventCode=1 
<br>(CommandLine="\*procdump\*" OR Image="\*procdump.exe")*
<br><br>

UAC Bypass with Fodhelper

*index=\* 
<br>EventCode=1 
<br>(Image="\*\\fodhelper.exe" OR OriginalFileName="fodhelper.exe")*
<br><br><br>

Splunk Alerts created with above filters:

<img width="975" height="321" alt="image" src="https://github.com/user-attachments/assets/f6fa0b54-95f1-4500-a48d-58a453924e40" />
<br><br>

Initially no triggered alerts:

<img width="975" height="142" alt="image" src="https://github.com/user-attachments/assets/5105394e-6925-4b8d-a475-53f6b5666edc" />
<br><br><br>

**Attack Simulation with ART & Alert Trigger in Splunk:**
<br><br>

Encoded Powershell Execution:

<img width="975" height="357" alt="image" src="https://github.com/user-attachments/assets/1ced0835-a74e-4d0e-a5d4-0ba85e3dc359" />
<br><br>

Alert trigger:

<img width="975" height="157" alt="image" src="https://github.com/user-attachments/assets/21c09650-1761-4d6f-9598-00304d389ec7" />
<br><br>

Credential Theft With Mimikatz:

<img width="975" height="203" alt="image" src="https://github.com/user-attachments/assets/ab105716-53d5-48ae-bf72-b4baee276288" />
<br><br>

Alert trigger:

<img width="975" height="180" alt="image" src="https://github.com/user-attachments/assets/2fa3defe-6091-4093-b33b-65fded524e56" />
<br><br>

mshta.exe Execution:

<img width="975" height="126" alt="image" src="https://github.com/user-attachments/assets/1a40343f-917e-4d05-b3ab-523586c897ff" />
<br><br>

Alert trigger:

<img width="975" height="211" alt="image" src="https://github.com/user-attachments/assets/68372bf9-3264-4216-97da-31536b638f29" />
<br><br>

Registry Persistence via Run Key:

<img width="975" height="312" alt="image" src="https://github.com/user-attachments/assets/15db1423-5b18-45ca-827d-98242fd23bbc" />
<br><br>

Alert trigger:

<img width="975" height="228" alt="image" src="https://github.com/user-attachments/assets/2f4698e8-75b2-44a8-9298-961c9bcb5710" />
<br><br>

Delete USN Journal with FSUtil:

<img width="975" height="206" alt="image" src="https://github.com/user-attachments/assets/1cc8d5b9-bd51-483c-bff5-ae3b63ebac1a" />
<br><br>

Alert trigger:

<img width="975" height="254" alt="image" src="https://github.com/user-attachments/assets/5816da11-0a4b-45e5-b695-e8cadc049da5" />
<br><br>

LSASS Dump with Procdump:

<img width="975" height="323" alt="image" src="https://github.com/user-attachments/assets/1cab8160-0bd1-4629-8997-43927f8494f2" />
<br><br>

Alert trigger:

<img width="975" height="283" alt="image" src="https://github.com/user-attachments/assets/44635d10-7520-495a-8fd3-d3c16589e92e" />
Note- There are 2 alerts for procdump. Both have different image file, procdump.exe and cmd.exe

<br><br>

UAC Bypass with Fodhelper:

<img width="975" height="283" alt="image" src="https://github.com/user-attachments/assets/84fc2541-5b52-40bd-bf54-2ce67701cb4d" />
<br><br>

Alert trigger:

<img width="975" height="309" alt="image" src="https://github.com/user-attachments/assets/0a42c9fe-fe41-4d6e-a13f-f97806ae7fc6" />
<br><br>

