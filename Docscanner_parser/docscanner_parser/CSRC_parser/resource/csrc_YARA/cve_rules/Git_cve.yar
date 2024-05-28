rule CVE_2012_0158_1
{
	meta:
		old_name = "maldoc_cve_2012_0158 / exploit"
		author = "@h3x2b <tracker _AT h3x.eu>"
		description = "Detect MSComctlLib.ListViewCtrl.2 in DOC documents-cve_2012_0158"

	strings:
		//MSComctlLib.ListViewCtrl.2 GUID={BDD1F04B-858B-11D1-B16A-00C0F0283628}
	        $doc_activex_01 = { 4B F0 D1 BD 8B 85 D1 11 B1 6A 00 C0 F0 28 36 28 }

	condition:
                // DOC/Composite file magic
		uint32be(0) == 0xd0cf11e0 and uint32be(4) == 0xa1b11ae1
		and $doc_activex_01
}

/*
   Modified rule of Jeremy Brown
   see my video: https://www.youtube.com/watch?v=53gpfmKFxr4
*/

rule CVE_2021_40444_XML_1
{
   meta:
	  old_name = "EXPL_CVE_2021_40444_Document_Rels_XML"
      description = "Detects indicators found in weaponized documents that exploit CVE-2021-40444"
      author = "Jeremy Brown / @alteredbytes"
      reference = "https://twitter.com/AlteredBytes/status/1435811407249952772"
      date = "2021-09-10"
   strings:
      $b1 = "/relationships/oleObject" ascii 
      $b2 = "/relationships/attachedTemplate" ascii

      $c1 = "Target=\"mhtml:http" nocase
      $c2 = "!x-usc:http" nocase
      $c3 = "TargetMode=\"External\"" nocase
   condition:
      uint32(0) == 0x6D783F3C
      and filesize < 10KB
      and 1 of ($b*)
      and all of ($c*)
}

rule CVE_2021_40444_MHTML
{
   meta:
      old_name = "EXPL_MAL_MalDoc_OBFUSCT_MHTML_CVE_2021_40444_1"
      description = "Detects suspicious office reference files including an obfuscated MHTML reference exploiting CVE-2021-40444"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://twitter.com/decalage2/status/1438946225190014984?s=20"
      date = "2021-09-18"
      score = 90
      hash = "84674acffba5101c8ac518019a9afe2a78a675ef3525a44dceddeed8a0092c69"
   strings:
      $h1 = "<?xml " ascii wide
      $s1 = "109;&#104;&#116;&#109;&#108;&#58;&#104;&#116;&#109;&#108" ascii wide
   condition:
      filesize < 25KB and all of them
}


rule CVE_2021_40444_XML_2
{
   meta:
      old_name = "EXPL_XML_Encoded_CVE_2021_40444"
      author = "James E.C, Proofpoint"
      description = "Detects possible CVE-2021-40444 with no encoding, HTML/XML entity (and hex notation) encoding, or all 3"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18"
      modified = "2021-09-19"
      score = 70
      hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E" // document.xml
      hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69" // original .docx
   strings:
      $h1 = "<?xml " ascii wide
      $t_xml_r = /Target[\s]{0,20}=[\s]{0,20}\["']([Mm]|&#(109|77|x6d|x4d);)([Hh]|&#(104|72|x68|x48);)([Tt]|&#(116|84|x74|x54);)([Mm]|&#(109|77|x6d|x4d);)([Ll]|&#(108|76|x6c|x4c);)(:|&#58;|&#x3a)/
      $t_mode_r = /TargetMode[\s]{0,20}=[\s]{0,20}\["']([Ee]|&#(x45|x65|69|101);)([Xx]|&#(x58|x78|88|120);)([Tt]|&#(x74|x54|84|116);)/
   condition:
      filesize < 500KB and $h1 and all of ($t_*)
}

/* not directly related to CVE-2021-40444 */
rule CVE_2021_40444_XML_3
{
   meta:
      old_name = "SUSP_OBFUSC_Indiators_XML_OfficeDoc_CVE_2021_40444_1 / Windows CVE"
      author = "Florian Roth (Nextron Systems)"
      description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18"
      score = 65
      hash = "13DE9F39B1AD232E704B5E0B5051800FCD844E9F661185ACE8287A23E9B3868E" // document.xml
      hash = "84674ACFFBA5101C8AC518019A9AFE2A78A675EF3525A44DCEDDEED8A0092C69" // original .docx
   strings:
      $h1 = "<?xml " ascii wide

      $xml_e = "Target=\"&#" ascii wide
      $xml_mode_1 = "TargetMode=\"&#" ascii wide
   condition:
      filesize < 500KB and $h1 and 1 of ($xml*)
}


rule CVE_2015_2545_3
{
   meta:
      old_name = "Exp_EPS_CVE_2015_2545"
      description = "Detects EPS Word Exploit CVE-2015-2545"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research-ME"
      date = "2017-07-19"
      score = 70
   strings:
      $s1 = "word/media/image1.eps" ascii
      $s2 = "-la;7(la+" ascii
   condition:
      uint16(0) == 0x4b50 and ( $s1 and #s2 > 20 )
}


rule CVE_2017_11882_1
{
    meta:
	  old_name = "EXP_potential_CVE_2017_11882"
      author = "ReversingLabs"
      reference = "https://www.reversinglabs.com/newsroom/news/reversinglabs-yara-rule-detects-cobalt-strike-payload-exploiting-cve-2017-11882.html"
    strings:
        $docfilemagic = { D0 CF 11 E0 A1 B1 1A E1 }
        $equation1 = "Equation Native" wide ascii
        $equation2 = "Microsoft Equation 3.0" wide ascii
        $mshta = "mshta"
        $http  = "http://"
        $https = "https://"
        $cmd   = "cmd" fullword
        $pwsh  = "powershell"
        $exe   = ".exe"
        $address = { 12 0C 43 00 }
    condition:
        uint16(0) == 0xcfd0 and $docfilemagic at 0 and
        any of ($mshta, $http, $https, $cmd, $pwsh, $exe) and any of ($equation1, $equation2) and $address
}

rule CVE_2020_0688
{
   meta:
      old_name = "VUL_Exchange_CVE_2020_0688"
      description = "Detects static validation key used by Exchange server in web.config"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://www.thezdi.com/blog/2020/2/24/cve-2020-0688-remote-code-execution-on-microsoft-exchange-server-through-fixed-cryptographic-keys"
      date = "2020-02-26"
      score = 60
   strings:
      $h1 = "<?xml "
      $x1 = "<machineKey validationKey=\"CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF\"" ascii wide
   condition:
      filesize <= 300KB and $h1 at 0 and $x1
}

rule CVE_2012_0158_2
{
	meta:
		old_name = "Office_as_MHTML_CVE_2012_0158"
		description = "Detects an Microsoft Office saved as a MHTML file (false positives are possible but rare; many matches on CVE-2012-0158)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-28"
		score = 40
		reference = "https://www.trustwave.com/Resources/SpiderLabs-Blog/Malicious-Macros-Evades-Detection-by-Using-Unusual-File-Format/"
		hash1 = "8391d6992bc037a891d2e91fd474b91bd821fe6cb9cfc62d1ee9a013b18eca80"
		hash2 = "1ff3573fe995f35e70597c75d163bdd9bed86e2238867b328ccca2a5906c4eef"
		hash3 = "d44a76120a505a9655f0224c6660932120ef2b72fee4642bab62ede136499590"
		hash4 = "5b8019d339907ab948a413d2be4bdb3e5fdabb320f5edc726dc60b4c70e74c84"
	strings:
		$s1 = "Content-Transfer-Encoding: base64" ascii fullword
		$s2 = "Content-Type: application/x-mso" ascii fullword

		$x1 = "QWN0aXZlTWltZQA" ascii 	// Base64 encoded 'ActiveMime'
		$x2 = "0M8R4KGxGuE" ascii 		// Base64 encoded office header D0CF11E0A1B11AE1..
	condition:
		uint32be(0) == 0x4d494d45 // "MIME" header
		and all of ($s*) and 1 of ($x*)
}

rule CVE_2015_2545_4
{
    meta:
		old_name = "HWP_eps_CVE_2015_2545"
        hash1 = "a68169aba0691c337241ea1049d8d848765dcfc35a9e43897c51379979b48455"
        KicomAV = "Exploit.HWP.CVE-2015-2545"
    strings:
        $regex1 = /[0-9A-Fa-f]{200}/
        $regex2 = /3.{46}D>\s+token\s+pop\s+exch\s+pop\s+exec\b/ nocase
    condition:
        $regex1 in (0..4096) and filesize < 20KB and all of them
}

rule CVE_2017_8759_CRLF
{
   meta:
      old_name = "CVE_2017_8759_CRLF"
      description = "Detects attempts to exploit CVE-2017-8759 CRLF injection in WSDL file"
      author = "Rich Warren"
      reference = "https://www.fireeye.com/blog/threat-research/2017/09/zero-day-used-to-distribute-finspy.html"
      date = "2017-09-17"
   strings:
      $s1 = /<soap:address location=\";\r?\n/ ascii wide nocase
   condition:
      $s1
}

rule CVE_2017_8759_PPSX
{
  meta:
    author = "David Cannings & Rich Warren"
    decription = "OOXML Presentation containing WSDL moniker (CVE-2017-8759)"
    
  strings:
    $root = "<?xml" wide ascii
    $schema_01 = "schemas.openxmlformats.org" wide ascii
    $schema_02 = "officeDocument/2006/relationships" wide ascii
    
    $s = /Target\s*=\s*["']?soap:wsdl=http/ wide ascii
    
  condition:
    $root and any of ($schema*) and $s
}