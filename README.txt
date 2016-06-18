M$ Windows Hacking Pack
===========

Tools here are from different sources. The repo is generally licensed with WTFPL, but some content may be not (eg. sysinternals).
"pes" means "PE Scambled". It's useful sometimes.



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
Undisclosed lnk based exploit. Possible disclosure @hack.lu 2016.




Hashes and VirusTotal scans
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


5b3fda14e972d908896a605293f4634a72e2968278117410e12d8b3faf9a3976  sources/nc110.tgz
47ec6f337a386828005eeaa0535b9b31c3fb13f657ce7eb56bcaf7ce50f9fdf9  sources/rdp2tcp-0.1.tar.gz
33d109696d22b7e89f4eac6d07f4b4461551247ce2bfcbead09373ce39364f78  sources/srvcheck3.zip


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
