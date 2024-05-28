/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

rule CVE_2017_1182
{
    meta:
	  old_name = "potential_CVE_2017_11882"
      author = "ReversingLabs"
      reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
      
    strings:
        $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }

        $equation1 = "Equation Native" wide ascii
        $equation2 = "Microsoft Equation 3.0" wide ascii

        $mshta = "mshta"
        $http  = "http://"
        $https = "https://"
        $cmd   = "cmd"
        $pwsh  = "powershell"
        $exe   = ".exe"

        $address = { 12 0C 43 00 }

    condition:
        $docfilemagic at 0 and any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}

rule CVE_2017_11882_OLE
{
    meta:
		old_name = "rtf_cve2017_11882_ole / malicious exploit cve_2017_11882"
        author = "John Davison"
        description = "Attempts to identify the exploit CVE 2017 11882"
        reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
        sample = "51cf2a6c0c1a29abca9fd13cb22421da"
        score = 60
        //file_name = "re:^stream_[0-9]+_[0-9]+.dat$"
    strings:
        $headers = { 1c 00 00 00 02 00 ?? ?? a9 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 03 01 01 03 ?? }
        $font = { 0a 01 08 5a 5a } // <-- I think that 5a 5a is the trigger for the buffer overflow
        //$code = /[\x01-\x7F]{44}/
        $winexec = { 12 0c 43 00 }
    condition:
        all of them and @font > @headers and @winexec == @font + 5 + 44
}

// same as above but for RTF documents
rule CVE_2017_1182_rtf
{
    meta:
		old_name = "rtf_cve2017_11882 / malicious exploit cve_2017_1182"
        author = "John Davison"
        description = "Attempts to identify the exploit CVE 2017 11882"
        reference = "https://embedi.com/blog/skeleton-closet-ms-office-vulnerability-you-didnt-know-about"
        sample = "51cf2a6c0c1a29abca9fd13cb22421da"
        score = 60
        //file_ext = "rtf"
    strings:
        $headers = { 31 63 30 30 30 30 30 30  30 32 30 30 ?? ?? ?? ??
                     61 39 30 30 30 30 30 30  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  ?? ?? ?? ?? ?? ?? ?? ??
                     ?? ?? ?? ?? ?? ?? ?? ??  30 33 30 31 30 31 30 33
                     ?? ?? }
        $font = { 30 61 30 31 30 38 35 61  35 61 }
        $winexec = { 31 32 30 63 34 33 30 30 }
    condition:
        all of them and @font > @headers and @winexec == @font + ((5 + 44) * 2)
}

rule CVE_2015_2545_1
{
    meta:
		old_name = "HWP_eps_exploit"
        description = "EPS Vulnerability(CVE-2015-2545)"
        KicomAV = "Exploit.EPS.CVE-2015-2545"
    strings:
        $regex1 = /3.{46}D\b>\s+token\s+pop\s+exch\s+pop\s+exec\s*/ nocase
    condition:
        all of them
}

rule CVE_2015_2545_2
{
    meta:
		old_name = "HWP_eps_exploit1"
        hash1 = "a68169aba0691c337241ea1049d8d848765dcfc35a9e43897c51379979b48455"
        KicomAV = "Exploit.HWP.CVE-2015-2545"
    strings:
        $regex1 = /[0-9A-Fa-f]{200}/
        $regex2 = /3.{46}D>\s+token\s+pop\s+exch\s+pop\s+exec\b/ nocase
    condition:
        $regex1 in (0..4096) and filesize < 20KB and all of them
}