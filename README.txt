M$ Windows Hacking Pack
===========

Tools here are from different sources. The repo is generally licensed with WTFPL, but some content may be not (eg. sysinternals).
"pes" means "PE Scambled". It's useful sometimes.


Remote Exploits
===========

Windows 2000 / XP SP1
MS05-039 Microsoft Plug and Play Service Overflow, Works with SSDP too
http://www.rapid7.com/db/modules/exploit/windows/smb/ms05_039_pnp


Windows XP/NT (beofre SP2)
MS03-026  Microsoft RPC DCOM Interface Overflow (kaht2.zip)
http://www.securityfocus.com/bid/8205/exploit


Windows XP (SP2 and SP3) (can be used also for priv esc)
MS08-067 Remote Stack Overflow Vulnerability Exploit (srvscv)
https://www.exploit-db.com/exploits/7104/



Privilege Escalation
===========

First, if you have meterpreter, it may be a good idea to try "getsystem".


srvcheck3.exe
=====
Privilege escalation for Windows XP SP2 and before
This can exploit vulnerable services. http://seclists.org/fulldisclosure/2006/Feb/231
Example: srvcheck3.exe -m upnphost -H 127.0.0.1 -c "cmd.exe /c c:\Inetpub\wwwroot\shell.exe"


KiTrap0D.tar
=====
Privilege escalation for Microsoft Windows NT/2000/XP/2003/Vista/2008/7
MS10-015 / CVE-2010-0232 / https://www.exploit-db.com/exploits/11199/


Other ways of exploits listed
=====
Windows XP/2003
MS11-080  → Local Privilege Escalation Exploit  Afd.sys
https://www.exploit-db.com/exploits/18176/


Windows Vista/7 
CVE: 2010-4398  Elevation of Privileges (UAC Bypass) 
http://www.securityfocus.com/bid/45045/exploit


Windows 8.1 (and before)
MS14-058 → TrackPopupMenu Privilege Escalation
https://www.exploit-db.com/exploits/37064/


Windows 8.1 (and before)
MS15-051 Win32k LPE vulnerability used in APT attack "taihou32"
https://www.exploit-db.com/exploits/37049/


Windows 10 (and before)
Hot Potato (nbns spoof + wpad + smb ntlm)
http://foxglovesecurity.com/2016/01/16/hot-potato/


Windows 10 (and before)
Link/URL based exploitation of NetNTLM hashes. Eg. sending link file in email or dropping on file share.
Technique presented here: https://www.youtube.com/watch?v=cuF_Ibo-mmM

Windows XP SP2 (and before)
srvcheck3.exe - upnp service or SSDPSRV service 


Windows XP/2003
MS11-080  → Local Privilege Escalation Exploit  Afd.sys
https://www.exploit-db.com/exploits/18176/


Windows Vista/7 
CVE: 2010-4398  Elevation of Privileges (UAC Bypass) 
http://www.securityfocus.com/bid/45045/exploit


Windows 8.1 (and before)
MS14-058 → TrackPopupMenu Privilege Escalation
https://www.exploit-db.com/exploits/37064/


Windows 8.1 (and before)
MS15-051 Win32k LPE vulnerability used in APT attack "taihou32"
https://www.exploit-db.com/exploits/37049/


Windows NT/2K/XP/2K3/Vista/2K8/7/8
KiTrap0D - EPATHOBJ Local Ring Exploit
https://www.exploit-db.com/exploits/11199/


Windows 10 (and before)
Hot Potato (nbns spoof + wpad + smb ntlm)
http://foxglovesecurity.com/2016/01/16/hot-potato/


Windows XP (and after)
.lnk exploit for receiving NetNTLM hashes remotely.
https://www.youtube.com/watch?v=cuF_Ibo-mmM


Backup files if contain sam
Windows/system32/config/SAM
/WINDOWS/repair/SAM
regedit.exe HKEY_LOCAL_MACHINE -> SAM

Tools to get the SAM database if locked: pwdump, samdump, samdump2, Cain&Abel
Otherwise just copy.


Dump SAM through shadow volume
If it can be created the database could be copied from this.
Vista command: vssadmin create shadow
Server 2008 command: diskshadow


Windows Credentials Editor
WCE / Windows Credentials Editor can recover password hashes from LSASS - http://www.ampliasecurity.com/research/wcefaq.html
WCE supports Windows XP, Windows 2003, Vista, Windows 7 and Windows 2008 (all SPs, 32bit and 64bit versions). 


Mimikatz dumping
mimikatz # privilege::debug
mimikatz # sekurlsa::logonpasswords
mimikatz # lsadump::sam


Cachedump aka In-memory attacks for SAM hashes / Cached Domain Credentials
fgdump.exe (contains pwdump and cachedump, can read from memory)


SAM dump (hive)
"A hive is a logical group of keys, subkeys, and values in the registry that has a set of supporting files containing backups of its data."


Dump SAM, then spray hashes
keimpx (try hashes with different users, against domain accounts)
http://code.google.com/p/keimpx/


LSA dumping (memory) / Windows 2000, Windows 95, Windows 98, Windows Me, Windows NT, Windows XP
LSAdump2, LSASecretsDump, pwdumpx, gsecdump or Cain & Abel
https://github.com/CoreSecurity/impacket
http://packetstormsecurity.org/files/view/10457/lsadump2.zip
http://www.nirsoft.net/utils/lsa_secrets_dump.html
http://packetstormsecurity.org/files/view/62371/PWDumpX14.zip


PassTheHash (before Windows 8.1)
pth-winexe --user=pc.local/Administrator%aad3b435b51404eeaad3b435b514t234e:1321ae011e02ab0k26e4edc5012deac8 //10.1.1.1 cmd


PassTheTicket (Kerberos)
mimikatz can do it


Duplicate Access Tokens (if admin access token can be used, it's win)
http://sourceforge.net/projects/incognito/


Token "Kidnapping"
MS 09-12, Churrasco.bin shell.bin (runs shell.bin with nt system authority)
http://carnal0wnage.attackresearch.com/2010/05/playing-with-ms09-012-windows-local.html


Other notablelo tools
psexec, smbshell, metasploit’s psexec, etc



To Be Added
===========
- http://www.nirsoft.net/ --> Stuff for dumping passwords
- openvpn
- evilgrade



Hashes (SHA256) and VirusTotal scans
===========

8ee65368afcd98ea660f5161f9cbe0c4c08863018f28e5eb024d8db58b234333  AwesomerShell.tar
7487ec568b6e2547ef30957610e60df3089d916f043b02da1167959dd9e0c051  KiTrap0D.tar
96f17857f3eb28a7d93dad930bc099a3cb65a9a2afb37069bfd1ba5ec5964389  LICENSE.txt
b3991cbab99149f243735750690b52f38a4a9903a323c8c95d037a1957ec058e  ncat.exe
da24e2a2fefc4e53c22bc5ba1df278a0f644ada6e95f6bc602d75f5158a5932b  ncat_pes.exe
be4211fe5c1a19ff393a2bcfa21dad8d0a687663263a63789552bda446d9421b  nc.exe
56580f1eebdccfbc5ce6d75690600225738ddbe8d991a417e56032869b0f43c7  nmap-7.12-setup-gui.exe
0cb7c3d9c4a0ce86f44ab4d0db2de264b64abbb83ef453afe05f5fddf330a1c5  nmap-7.12-win32_commandline.zip
976c216119d5627afc9ad29fd4f72e38de3711d65419fda6482bc795e0ebf654  plink.exe
952aa0bfb7ea58669fb50b945a09e9e69cd178739c5d1281a45ecfc54cc7f92f  srvcheck3.exe
ca5214e14ed5e879dd000a8a13895c474c89248386e9d337dd43f105a70f4170  PEScrambler.exe
ef0f4bf2267b866a00b3e60c0e70f7f37cc5529fee417a625e502b3c93d215d9  SysinternalsSuite.zip
8e9bc40efd17a37a4ecf7ada7a3d739f343e207abe4e17f05a531baccc607336  windows-privesc-check.exe
6c367696e6cc8e6093426dbd19daf13b2375b0c078387ae6355519522d23b0fd  windows-privesc-check.py
ffe3808989bdfe986b17023e5d6583d49d644182e81234dc1db604e260ba76c9  fgdump.exe
c36225d4515a92b905f8337acfd3d365cb813a2654e65067dbdba4fc58e7126a  kaht2.zip
2951e49efbc9e18d4641c0061f10da021b4bca2bd51247fe80107cbd334c195d  mimikatz_2-1.zip
0682a92bc96a66cf3e3eca1e44296838b9baad4feef0c391fc48044e039e642a  ms08-067_exploit_31874.py
cc4b4eceb04142b9e0794be029302feb33cf58c6a0cd1fdca3ff611df9b83827  ms08-067_exploit_7132.py
950bbdde2cc92799675c138fd8dfb2b60f0c01759533bc1a6993559508bd131e  Responder.tar
54bd6cccf4c74604eb9956ce167a3ea94a06fabf4954e691d020023f8827c448  samdump2.exe
ece925f85dc15b816dacacbb92ad41045f0cc58c2e10c5d3b66723ae11cf65c8  wce_getlsasrvaddr.exe
c6333c684762ed4b4129c7f9f49c88c33384b66dfb1f100e459ec6f18526dff7  wce_v1_41beta_universal.exe
ecbac2a6c0bf8dbc7bed2370ed098cd43a56b0d69a0db1d5715751270711f1d6  wce_v1_42beta_x32.exe

5b3fda14e972d908896a605293f4634a72e2968278117410e12d8b3faf9a3976  sources/nc110.tgz
47ec6f337a386828005eeaa0535b9b31c3fb13f657ce7eb56bcaf7ce50f9fdf9  sources/rdp2tcp-0.1.tar.gz
33d109696d22b7e89f4eac6d07f4b4461551247ce2bfcbead09373ce39364f78  sources/srvcheck3.zip
f706df25bb061a669b13ff76c121a8d72140406c7b0930bae5dcf713f9520a56  sources/3proxy-0.8.6.tar.gz
7e8cfbf10bcc91fa9b9a60d3335d4a52bd6d4b6ca888533dbdd2afc86bebb5cc  sources/3proxy-0.9-devel.tgz
dec12905822ea64676d0ec58b62c00631ef8ddde2c700ffe74bfcf9026f17d81  sources/fgdump-2.1.0.tar.bz2
352888e441be33ae6266cfac1a072d52cfaafd65cc33b07daa51600f1cd803ca  sources/impacket_0-9-15.tar
21faf49ae9ff08054214675f18d813bcf042798c325d68ae8b2417a119b439f4  sources/keimpx-0.3-dev.tar
16136256911c31f7c56eef415b11e14c13abe89cface46df78033456194eddfd  sources/mimikatz-2016-06.zip
602659af30c565750fa01650e0a223d26355b5df98f2fbc30e3a6c593ed4e526  sources/samdump2-3.0.0.tar.bz2


ncat.exe
SHA256: b3991cbab99149f243735750690b52f38a4a9903a323c8c95d037a1957ec058e
https://virustotal.com/en/file/b3991cbab99149f243735750690b52f38a4a9903a323c8c95d037a1957ec058e/analysis/1466258994/

ncat_pes.exe
SHA256: da24e2a2fefc4e53c22bc5ba1df278a0f644ada6e95f6bc602d75f5158a5932b 
https://virustotal.com/en/file/da24e2a2fefc4e53c22bc5ba1df278a0f644ada6e95f6bc602d75f5158a5932b/analysis/1466259528/

nc110.tgz
SHA256: 5b3fda14e972d908896a605293f4634a72e2968278117410e12d8b3faf9a3976
https://virustotal.com/en/file/5b3fda14e972d908896a605293f4634a72e2968278117410e12d8b3faf9a3976/analysis/1466258410/

rdp2tcp-0.1.tar.gz
SHA256: 47ec6f337a386828005eeaa0535b9b31c3fb13f657ce7eb56bcaf7ce50f9fdf9
https://virustotal.com/en/file/47ec6f337a386828005eeaa0535b9b31c3fb13f657ce7eb56bcaf7ce50f9fdf9/analysis/1466271163/

