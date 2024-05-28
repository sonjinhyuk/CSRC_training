rule SUSP_OBFUSC_Indiators_XML_OfficeDoc_Sep21_2 : Windows CVE {
   meta:
      author = "Florian Roth (Nextron Systems)"
      description = "Detects suspicious encodings in fields used in reference files found in weaponized MS Office documents"
      reference = "https://twitter.com/sudosev/status/1439205606129377282"
      date = "2021-09-18"
      score = 65
   strings:
      $h1 = "<?xml " ascii wide
      $a1 = "Target" ascii wide
      $a2 = "TargetMode" ascii wide
      $xml_e = "&#x0000" ascii wide
   condition:
      filesize < 500KB and all of them
}

/*
  Version 0.0.2 2014/12/16
  Source code put in public domain by Didier Stevens, no Copyright
  https://DidierStevens.com
  Use at your own risk

  These are YARA rules to detect shellcode, translated from XORSearch's wildcard rules,
  which themselves were developed based on Frank Boldewin's shellcode detector used in OfficeMalScanner.

  Shortcomings, or todo's ;-) :
    Remaining XORSearch wildcard rules:
      GetEIP method 2:10:EB(J;1)E8(J;4)(B;01011???)
      GetEIP method 3:10:E9(J;4)E8(J;4)(B;01011???)

  History:
    2014/12/15: start
    2014/12/16: extra documentation
*/

/*
XORSearch wildcard rule(s):
    API Hashing:10:AC84C07407C1CF0D01C7EBF481FF
    API Hashing bis:10:AC84C07407C1CF0701C7EBF481FF
*/
rule maldoc_API_hashing
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Function prolog signature:10:558BEC83C4
    Function prolog signature:10:558BEC81EC
    Function prolog signature:10:558BECEB
    Function prolog signature:10:558BECE8
    Function prolog signature:10:558BECE9
*/
rule maldoc_function_prolog_signature
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {55 8B EC 81 EC}
        $a2 = {55 8B EC 83 C4}
        $a3 = {55 8B EC E8}
        $a4 = {55 8B EC E9}
        $a5 = {55 8B EC EB}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Structured exception handling :10:648B(B;00???101)00000000
    Structured exception handling bis:10:64A100000000
*/
rule maldoc_structured_exception_handling
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 00 00 00 00}
        $a2 = {64 A1 00 00 00 00}
    condition:
        any of them
}

/*
XORSearch wildcard rule(s):
    Find kernel32 base method 2:10:31(B;11A??A??)(B;10100A??)30648B(B;00B??A??)
*/
rule maldoc_find_kernel32_base_method_2
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {31 ?? ?? 30 64 8B ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 1) >= 0xC0) and (((uint8(@a[i] + 1) & 0x38) >> 3) == (uint8(@a[i] + 1) & 0x07)) and ((uint8(@a[i] + 2) & 0xF8) == 0xA0) and (uint8(@a[i] + 6) <= 0x3F) and (((uint8(@a[i] + 6) & 0x38) >> 3) != (uint8(@a[i] + 6) & 0x07)))
}

/*
XORSearch wildcard rule(s):
    Find kernel32 base method 3:10:6830000000(B;01011A??)648B(B;00B??A??)
*/
rule maldoc_find_kernel32_base_method_3
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {68 30 00 00 00 (58|59|5A|5B|5C|5D|5E|5F) 64 8B ??}
    condition:
        for any i in (1..#a): (((uint8(@a[i] + 5) & 0x07) == (uint8(@a[i] + 8) & 0x07)) and (uint8(@a[i] + 8) <= 0x3F) and (((uint8(@a[i] + 8) & 0x38) >> 3) != (uint8(@a[i] + 8) & 0x07)))
}

/*
XORSearch wildcard rule(s):
    GetEIP method 1:10:E800000000(B;01011???)
*/
rule maldoc_getEIP_method_1
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {E8 00 00 00 00 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        $a
}

/*
XORSearch wildcard rule(s):
    GetEIP method 4 FLDZ/FSTENV [esp-12]:10:D9EED97424F4(B;01011???)
    GetEIP method 4:10:D9EE9BD97424F4(B;01011???)
*/
rule maldoc_getEIP_method_4
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {D9 EE D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
        $a2 = {D9 EE 9B D9 74 24 F4 (58|59|5A|5B|5C|5D|5E|5F)}
    condition:
        any of them
}


/*
XORSearch wildcard rule(s):
    Suspicious strings:2:str=UrlDownloadToFile
    Suspicious strings:2:str=GetTempPath
    Suspicious strings:2:str=GetWindowsDirectory
    Suspicious strings:2:str=GetSystemDirectory
    Suspicious strings:2:str=WinExec
    Suspicious strings:2:str=ShellExecute
    Suspicious strings:2:str=IsBadReadPtr
    Suspicious strings:2:str=IsBadWritePtr
    Suspicious strings:2:str=CreateFile
    Suspicious strings:2:str=CloseHandle
    Suspicious strings:2:str=ReadFile
    Suspicious strings:2:str=WriteFile
    Suspicious strings:2:str=SetFilePointer
    Suspicious strings:2:str=VirtualAlloc
    Suspicious strings:2:str=GetProcAddr
    Suspicious strings:2:str=LoadLibrary
*/
rule maldoc_suspicious_strings
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a01 = "CloseHandle"
        $a02 = "CreateFile"
        $a03 = "GetProcAddr"
        $a04 = "GetSystemDirectory"
        $a05 = "GetTempPath"
        $a06 = "GetWindowsDirectory"
        $a07 = "IsBadReadPtr"
        $a08 = "IsBadWritePtr"
        $a09 = "LoadLibrary"
        $a10 = "ReadFile"
        $a11 = "SetFilePointer"
        $a12 = "ShellExecute"
        $a13 = "UrlDownloadToFile"
        $a14 = "VirtualAlloc"
        $a15 = "WinExec"
        $a16 = "WriteFile"
    condition:
        any of them
}


rule Office_AutoOpen_Macro {
	meta:
		description = "Detects an Microsoft Office file that contains the AutoOpen Macro function"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2015-05-28"
		score = 40
		hash1 = "4d00695d5011427efc33c9722c61ced2"
		hash2 = "63f6b20cb39630b13c14823874bd3743"
		hash3 = "66e67c2d84af85a569a04042141164e6"
		hash4 = "a3035716fe9173703941876c2bde9d98"
		hash5 = "7c06cab49b9332962625b16f15708345"
		hash6 = "bfc30332b7b91572bfe712b656ea8a0c"
		hash7 = "25285b8fe2c41bd54079c92c1b761381"
	strings:
		$s1 = "AutoOpen" ascii fullword
		$s2 = "Macros" wide fullword
	condition:
		(
			uint32be(0) == 0xd0cf11e0 or 	// DOC, PPT, XLS
			uint32be(0) == 0x504b0304		// DOCX, PPTX, XLSX (PKZIP)
		)
		and all of ($s*) and filesize < 300000
}

rule Docm_in_PDF {
   meta:
      description = "Detects an embedded DOCM in PDF combined with OpenAction"
      license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2017-05-15"
   strings:
      $a1 = /<<\/Names\[\([\w]{1,12}.docm\)/ ascii
      $a2 = "OpenAction" ascii fullword
      $a3 = "JavaScript" ascii fullword
   condition:
      uint32(0) == 0x46445025 and all of them
}


// YARA rules Office DDE
// NVISO 2017/10/10 - 2017/10/12
// https://sensepost.com/blog/2017/macro-less-code-exec-in-msword/

/* slowing down scanning
rule Office_DDEAUTO_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 60
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.{1,1000}?\b[Dd][Dd][Ee][Aa][Uu][Tt][Oo]\b.{1,1000}?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}

rule Office_DDE_field {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 40
   strings:
      $a = /<w:fldChar\s+?w:fldCharType="begin"\/>.+?\b[Dd][Dd][Ee]\b.+?<w:fldChar\s+?w:fldCharType="end"\/>/
   condition:
      $a
}
*/

rule Office_OLE_DDEAUTO {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 30
   strings:
      $a = /\x13\s*DDEAUTO\b[^\x14]+/ nocase
   condition:
      uint32be(0) == 0xD0CF11E0 and $a
}

rule Office_OLE_DDE {
   meta:
      description = "Detects DDE in MS Office documents"
      author = "NVISO Labs"
      reference = "https://blog.nviso.be/2017/10/11/detecting-dde-in-ms-office-documents/"
      date = "2017-10-12"
      score = 50
   strings:
      $a = /\x13\s*DDE\b[^\x14]+/ nocase

      $r1 = { 52 00 6F 00 6F 00 74 00 20 00 45 00 6E 00 74 00 72 00 79 }
      $r2 = "Adobe ARM Installer"
   condition:
      uint32be(0) == 0xD0CF11E0 and $a and not 1 of ($r*)
}

rule SUSP_Office_Dropper_Strings {
   meta:
      description = "Detects Office droppers that include a notice to enable active content"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2018-09-13"
   strings:
      $a1 = "_VBA_PROJECT" wide

      $s1 = "click enable editing" fullword ascii
      $s2 = "click enable content" fullword ascii
      $s3 = "\"Enable Editing\"" fullword ascii
      $s4 = "\"Enable Content\"" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 500KB and $a1 and 1 of ($s*)
}

rule SUSP_EnableContent_String_Gen {
   meta:
      description = "Detects suspicious string that asks to enable active content in Office Doc"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-12"
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
   strings:
      $e1 = "Enable Editing" fullword ascii
      $e2 = "Enable Content" fullword ascii
      $e3 = "Enable editing" fullword ascii
      $e4 = "Enable content" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and (
            $e1 in (0..3000) or
            $e2 in (0..3000) or
            $e3 in (0..3000) or
            $e4 in (0..3000) or
            2 of them
      )
}

rule SUSP_WordDoc_VBA_Macro_Strings {
   meta:
      description = "Detects suspicious strings in Word Doc that indcate malicious use of VBA macros"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-02-12"
      score = 60
      hash1 = "525ba2c8d35f6972ac8fcec8081ae35f6fe8119500be20a4113900fe57d6a0de"
   strings:
      $a1 = "\\Microsoft Shared\\" ascii
      $a2 = "\\VBA\\" ascii
      $a3 = "Microsoft Office Word" fullword ascii
      $a4 = "PROJECTwm" fullword wide

      $s1 = "AppData" fullword ascii
      $s2 = "Document_Open" fullword ascii
      $s3 = "Project1" fullword ascii
      $s4 = "CreateObject" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 800KB and all of them
}

rule SUSP_OfficeDoc_VBA_Base64Decode {
   meta:
      description = "Detects suspicious VBA code with Base64 decode functions"
      author = "Florian Roth (Nextron Systems)"
      reference = "https://github.com/cpaton/Scripting/blob/master/VBA/Base64.bas"
      date = "2019-06-21"
      score = 70
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
   strings:
      $s1 = "B64_CHAR_DICT" ascii
      $s2 = "Base64Decode" ascii
      $s3 = "Base64Encode" ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 60KB and 2 of them
}

rule SUSP_VBA_FileSystem_Access {
   meta:
      description = "Detects suspicious VBA that writes to disk and is activated on document open"
      author = "Florian Roth (Nextron Systems)"
      reference = "Internal Research"
      date = "2019-06-21"
      score = 60
      hash1 = "52262bb315fa55b7441a04966e176b0e26b7071376797e35c80aa60696b6d6fc"
   strings:
      $s1 = "\\Common Files\\Microsoft Shared\\" wide
      $s2 = "Scripting.FileSystemObject" ascii

      $a1 = "Document_Open" ascii
      $a2 = "WScript.Shell" ascii
      $a3 = "AutoOpen" fullword ascii
   condition:
      uint16(0) == 0xcfd0 and filesize < 100KB and all of ($s*) and 1 of ($a*)
}

rule SUSP_Excel_IQY_RemoteURI_Syntax {
   meta:
      description = "Detects files with Excel IQY RemoteURI syntax"
      author = "Nick Carr"
      score = 65
      reference = "https://twitter.com/ItsReallyNick/status/1030330473954897920"
      date = "2018-08-17"
   strings:
      $URL = "http"
   condition:
      uint32(0) == 0x0d424557 and uint32(4) == 0x0a0d310a
      and filesize < 1MB
      and $URL
}

rule SUSP_Macro_Sheet_Obfuscated_Char {
   meta:
      description = "Finding hidden/very-hidden macros with many CHAR functions"
      author = "DissectMalware"
      date = "2020-04-07"
      score = 65
      hash1 = "0e9ec7a974b87f4c16c842e648dd212f80349eecb4e636087770bc1748206c3b"
      reference = "https://twitter.com/DissectMalware/status/1247595433305800706"
   strings:
      $ole_marker = {D0 CF 11 E0 A1 B1 1A E1}  
      $s1 = "Excel" fullword ascii
      $macro_sheet_h1 = {85 00 ?? ?? ?? ?? ?? ?? 01 01}
      $macro_sheet_h2 = {85 00 ?? ?? ?? ?? ?? ?? 02 01}    
      $char_func = {06 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 1E 3D  00 41 6F 00}
   condition:
      $ole_marker at 0 and 1 of ($macro_sheet_h*) and #char_func > 10 and $s1
}


rule IsPeFile {
meta:
    ref = "https://github.com/godaddy/yara-rules/blob/master/example.yara"
strings:
		$mz = "MZ"

	condition:
		$mz at 0 and uint32(uint32(0x3C)) == 0x4550
}

rule Hwp_Malware1
{
meta:
	author = "Kei Choi (hanul93@gmail.com)"
	date = "2017-08-23"
	KicomAV = "Trojan.PS.Agent.yra"
strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $string1 = "1 bitshift add" nocase
        $string2 = "(KERNEL32.DLL)" nocase
        $string3 = "(VirtualProtect)" nocase
        $string4 = "(ExitProcess)" nocase
    condition:
        all of them
}


rule Hwp_Malware2
{
meta:
	author = "Kei Choi (hanul93@gmail.com)"
	date = "2017-08-23"
	KicomAV = "Trojan.PS.Agent.yrb"
strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $regex2 = "90909090"
        $string1 = "putinterval def" nocase
        $string2 = "repeat" nocase
    condition:
        $regex1 in (0..256) and $regex2 in (0x17000..filesize) and (2 of ($string1, $string2))
}


rule Hwp_Malware3
{
meta:
	author = "Kei Choi (hanul93@gmail.com)"
	date = "2017-08-23"
	KicomAV = "Trojan.PS.Agent.yrc"
    strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $string1 = "4 mod get xor put" nocase
        $string2 = "exec" nocase
    condition:
        all of them
}


rule WannaCry : Ransomware
{
meta:
	author = "Kei Choi"
	date = "2018-04-04"
    KicomAV = "Trojan-Ransom.Win32.Wanna.gen"
	description = "Ransomware_WannaCry Yara Rule"
	hash0 = "a4cbf2307cafc733506e465b5a686307"
	hash1 = "f4856b368dc74f04adb9c4548993f148"
	hash2 = "04e1e9bacc659ae64fc2ae3a637a2daa"
	hash3 = "b1d52d54af3002b6775258a28bb38953"
	hash4 = "77a5be0a7d0c0ded340269d2ca9b8b94"
	hash5 = "aa089f31594076f4a1a4f5c76656a9db"
	hash6 = "4dcdb23838a010aa05f81447e826e65e"
	hash7 = "0bee63f915fe72daee9360f8f168bc64"
	hash8 = "c969cab67a026fb98309b62d35d6c605"
	hash9 = "ae72a3d3b9ee295436ba281171c50538"
	hash10 = "3503df16479880fdf484ace875ff3588"
	hash11 = "d69044b6e7fb5dfa6e07b4dfa0e06d15"
	hash12 = "9f2f3a01ddfbd0ddc65083f6472aa16c"
	sample_filetype = "exe"
	yaragenerator = "https://github.com/Xen0ph0n/YaraGenerator"
strings:
	$string0 = "gcblhgnjinjinjinjilhgjgfjfe"
	$string1 = "}yxfbagcb"
	$string2 = "V22dN::t"
	$string3 = "\\WINDOWS" wide
	$string4 = "XhHpSeA"
	$string5 = "_Tidy@"
	$string6 = "qnn]YXeaaifenjisontpoplkkgfplkqmlokjhdc"
	$string7 = "kgfhdciedfba"
	$string8 = "s.wnry"
	$string9 = "Amazon"
	$string10 = "$8,4-6'96$:."
	$string11 = "mihhdcgcbgcbgcbgcbgbaxts"
	$string12 = "1exception@@UAE@XZ"
	$string13 = "OMMuss"
	$string14 = "$allocator@G@2@@std@@2IB"
	$string15 = "Qkkbal"
	$string16 = "CryptImportKey"
condition:
	16 of them and IsPeFile
}


rule APT34_Malware_Exeruner {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "c75c85acf0e0092d688a605778425ba4cb2a57878925eee3dc0f4dd8d636a27a"
      KicomAV = "Trojan-Dropper.MSIL.Agent.gen"
   strings:
      $x1 = "\\obj\\Debug\\exeruner.pdb" ascii
      $x2 = "\"wscript.shell`\")`nShell0.run" wide
      $x3 = "powershell.exe -exec bypass -enc \" + ${global:$http_ag} +" wide
      $x4 = "/c powershell -exec bypass -window hidden -nologo -command " fullword wide
      $x5 = "\\UpdateTasks\\JavaUpdatesTasksHosts\\" wide
      $x6 = "schtasks /create /F /ru SYSTEM /sc minute /mo 1 /tn" wide
      $x7 = "UpdateChecker.ps1 & ping 127.0.0.1" wide
      $s8 = "exeruner.exe" fullword wide
      $s9 = "${global:$address1} = $env:ProgramData + \"\\Windows\\Microsoft\\java\";" fullword wide
      $s10 = "C:\\ProgramData\\Windows\\Microsoft\\java" fullword wide
      $s11 = "function runByVBS" fullword wide
      $s12 = "$84e31856-683b-41c0-81dd-a02d8b795026" fullword ascii
      $s13 = "${global:$dns_ag} = \"aQBmACAAKAAoAEcAZQB0AC0AVwBtAGk" wide
   condition:
      IsPeFile and filesize < 100KB and 1 of them
}

rule APT34_Malware_HTA {
   meta:
      description = "Detects APT 34 malware"
      author = "Florian Roth"
      reference = "https://www.fireeye.com/blog/threat-research/2017/12/targeted-attack-in-middle-east-by-apt34.html"
      date = "2017-12-07"
      hash1 = "f6fa94cc8efea0dbd7d4d4ca4cf85ac6da97ee5cf0c59d16a6aafccd2b9d8b9a"
      KicomAV = "Trojan.VBS.Powbow.gen"
   strings:
      $x1 = "WshShell.run \"cmd.exe /C C:\\ProgramData\\" ascii
      $x2 = ".bat&ping 127.0.0.1 -n 6 > nul&wscript  /b" ascii
      $x3 = "cmd.exe /C certutil -f  -decode C:\\ProgramData\\" ascii
      $x4 = "a.WriteLine(\"set Shell0 = CreateObject(" ascii
      $x5 = "& vbCrLf & \"Shell0.run" ascii

      $s1 = "<title>Blog.tkacprow.pl: HTA Hello World!</title>" fullword ascii
      $s2 = "<body onload=\"test()\">" fullword ascii
   condition:
      filesize < 60KB and ( 1 of ($x*) or all of ($s*) )
}

rule Trojan_JS_Malware1 {
   meta:
      hash1 = "000461e3edf7eee69ed45f0831858db2b0636f3059d31162040015d1330a0cee"
      KicomAV = "Trojan.JS.Generic"
   strings:

      $regex1 = /[0-9A-Fa-f]{500}/
      
      $hex1 = "function"
      $hex2 = "eval(eval"

   condition:
       $hex1 in (0..4096) and all of them
      
}

rule HWP_Trojan_Agent1 {
    meta:
        hash1 = "cd6a12cc693e98e4f47d2161e9fe99d04895472d964575c749bbdd460f0fefdc"
        KicomAV = "Exploit.HWP.Agent"
    strings:
        $regex1 = /[0-9A-Fa-f]{200}/
        $regex2 = /\bcopy\s*get\s*\d{1,}\s*xor\s+put\s+ar\s*}for\b/ nocase
    condition:
        $regex1 in (0..4096) and filesize < 20KB and all of them
}

rule maldoc_indirect_function_call_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF 75 ?? FF 55 ??}
    condition:
        for any i in (1..#a): (uint8(@a[i] + 2) == uint8(@a[i] + 5))
}

rule maldoc_indirect_function_call_2 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B5 ?? ?? ?? ?? FF 95 ?? ?? ?? ??}
    condition:
        for any i in (1..#a): ((uint8(@a[i] + 2) == uint8(@a[i] + 8)) and (uint8(@a[i] + 3) == uint8(@a[i] + 9)) and (uint8(@a[i] + 4) == uint8(@a[i] + 10)) and (uint8(@a[i] + 5) == uint8(@a[i] + 11)))
}

rule maldoc_indirect_function_call_3 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a = {FF B7 ?? ?? ?? ?? FF 57 ??}
    condition:
        $a
}

rule maldoc_find_kernel32_base_method_1 : maldoc
{
    meta:
        author = "Didier Stevens (https://DidierStevens.com)"
    strings:
        $a1 = {64 8B (05|0D|15|1D|25|2D|35|3D) 30 00 00 00}
        $a2 = {64 A1 30 00 00 00}
    condition:
        any of them
}

rule mwi_document: exploitdoc maldoc
{
    meta:
        description = "MWI generated document"
        author = "@Ydklijnsma"
        source = "http://blog.0x3a.com/post/117760824504/analysis-of-a-microsoft-word-intruder-sample"

      strings:
        $field_creation_tag = "{\\field{\\*\\fldinst { INCLUDEPICTURE"
        $mwistat_url = ".php?id="
        $field_closing_tag = "\\\\* MERGEFORMAT \\\\d}}{\\fldrslt}}"

    condition:
        all of them
}

rule macrocheck : maldoc
{
    meta:
        Author      = "Fireeye Labs"
        Date        = "2014/11/30" 
        Description = "Identify office documents with the MACROCHECK credential stealer in them.  It can be run against .doc files or VBA macros extraced from .docx files (vbaProject.bin files)."
        Reference   = "https://www.fireeye.com/blog/threat-research/2014/11/fin4_stealing_insid.html"

    strings:
        $PARAMpword = "pword=" ascii wide
        $PARAMmsg = "msg=" ascii wide
        $PARAMuname = "uname=" ascii
        $userform = "UserForm" ascii wide
        $userloginform = "UserLoginForm" ascii wide
        $invalid = "Invalid username or password" ascii wide
        $up1 = "uploadPOST" ascii wide
        $up2 = "postUpload" ascii wide
 
    condition:
        all of ($PARAM*) or (($invalid or $userloginform or $userform) and ($up1 or $up2))
}

rule Embedded_EXE_Cloaking : maldoc {
    meta:
        description = "Detects an embedded executable in a non-executable file"
        author = "Florian Roth"
        date = "2015/02/27"
        score = 80
    strings:
        $noex_png = { 89 50 4E 47 }
        $noex_pdf = { 25 50 44 46 }
        $noex_rtf = { 7B 5C 72 74 66 31 }
        $noex_jpg = { FF D8 FF E0 }
        $noex_gif = { 47 49 46 38 }
        $mz  = { 4D 5A }
        $a1 = "This program cannot be run in DOS mode"
        $a2 = "This program must be run under Win32"       
    condition:
        (
            ( $noex_png at 0 ) or
            ( $noex_pdf at 0 ) or
            ( $noex_rtf at 0 ) or
            ( $noex_jpg at 0 ) or
            ( $noex_gif at 0 )
        )
        and
        for any i in (1..#mz): ( @a1 < ( @mz[i] + 200 ) or @a2 < ( @mz[i] + 200 ) )
}

rule malicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 5
		
	strings:
		$magic = { 25 50 44 46 }
		
		$reg0 = /Creator.?\(yen vaw\)/
		$reg1 = /Title.?\(who cis\)/
		$reg2 = /Author.?\(ser pes\)/
	condition:
		$magic at 0 and all of ($reg*)
}

rule suspicious_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1.\d{1}/
	condition:
		$magic at 0 and not $ver
}

rule suspicious_creation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$create0 = /CreationDate \(D:20101015142358\)/
		$create1 = /CreationDate \(2008312053854\)/
	condition:
		$magic at 0 and $header and 1 of ($create*)
}

rule suspicious_title : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$title0 = "who cis"
		$title1 = "P66N7FF"
		$title2 = "Fohcirya"
	condition:
		$magic at 0 and $header and 1 of ($title*)
}

rule suspicious_author : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 4
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/

		$author0 = "Ubzg1QUbzuzgUbRjvcUb14RjUb1"
		$author1 = "ser pes"
		$author2 = "Miekiemoes"
		$author3 = "Nsarkolke"
	condition:
		$magic at 0 and $header and 1 of ($author*)
}

rule suspicious_producer : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$producer0 = /Producer \(Scribus PDF Library/
		$producer1 = "Notepad"
	condition:
		$magic at 0 and $header and 1 of ($producer*)
}

rule suspicious_creator : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$header = /%PDF-1\.(3|4|6)/
		
		$creator0 = "yen vaw"
		$creator1 = "Scribus"
		$creator2 = "Viraciregavi"
	condition:
		$magic at 0 and $header and 1 of ($creator*)
}

rule possible_exploit : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/JavaScript /
		$attrib3 = /\/ASCIIHexDecode/
		$attrib4 = /\/ASCII85Decode/

		$action0 = /\/Action/
		$action1 = "Array"
		$shell = "A"
		$cond0 = "unescape"
		$cond1 = "String.fromCharCode"
		
		$nop = "%u9090%u9090"
	condition:
		$magic at 0 and (2 of ($attrib*)) or ($action0 and #shell > 10 and 1 of ($cond*)) or ($action1 and $cond0 and $nop)
}

rule shellcode_blob_metadata : PDF
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "When there's a large Base64 blob inserted into metadata fields it often indicates shellcode to later be decoded"
                weight = 4
        strings:
                $magic = { 25 50 44 46 }

                $reg_keyword = /\/Keywords.?\(([a-zA-Z0-9]{200,})/ //~6k was observed in BHEHv2 PDF exploits holding the shellcode
                $reg_author = /\/Author.?\(([a-zA-Z0-9]{200,})/
                $reg_title = /\/Title.?\(([a-zA-Z0-9]{200,})/
                $reg_producer = /\/Producer.?\(([a-zA-Z0-9]{200,})/
                $reg_creator = /\/Creator.?\(([a-zA-Z0-9]{300,})/
                $reg_create = /\/CreationDate.?\(([a-zA-Z0-9]{200,})/

        condition:
                $magic at 0 and 1 of ($reg*)
}

rule suspicious_js : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/OpenAction /
		$attrib1 = /\/JavaScript /

		$js0 = "eval"
		$js1 = "Array"
		$js2 = "String.fromCharCode"
		
	condition:
		$magic at 0 and all of ($attrib*) and 2 of ($js*)
}

rule suspicious_launch_action : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$attrib0 = /\/Launch/
		$attrib1 = /\/URL /
		$attrib2 = /\/Action/
		$attrib3 = /\/F /

	condition:
		$magic at 0 and 3 of ($attrib*)
}

rule suspicious_embed : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "https://feliam.wordpress.com/2010/01/13/generic-pdf-exploit-hider-embedpdf-py-and-goodbye-av-detection-012010/"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		
		$meth0 = /\/Launch/
		$meth1 = /\/GoTo(E|R)/ //means go to embedded or remote
		$attrib0 = /\/URL /
		$attrib1 = /\/Action/
		$attrib2 = /\/Filespec/
		
	condition:
		$magic at 0 and 1 of ($meth*) and 2 of ($attrib*)
}

rule suspicious_obfuscation : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$reg = /\/\w#[a-zA-Z0-9]{2}#[a-zA-Z0-9]{2}/
		
	condition:
		$magic at 0 and #reg > 5
}

rule invalid_XObject_js : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "XObject's require v1.4+"
		ref = "https://blogs.adobe.com/ReferenceXObjects/"
		version = "0.1"
		weight = 2
		
	strings:
		$magic = { 25 50 44 46 }
		$ver = /%PDF-1\.[4-9]/
		
		$attrib0 = /\/XObject/
		$attrib1 = /\/JavaScript/
		
	condition:
		$magic at 0 and not $ver and all of ($attrib*)
}

rule js_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JavaScript was introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 2
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule JBIG2_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "JBIG2 was introduced in v1.4"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JBIG2Decode/
				$ver = /%PDF-1\.[4-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule FlateDecode_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "Flate was introduced in v1.2"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/FlateDecode/
				$ver = /%PDF-1\.[2-9]/

        condition:
                $magic at 0 and $js and not $ver
}

rule embed_wrong_version : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		description = "EmbeddedFiles were introduced in v1.3"
		ref = "http://wwwimages.adobe.com/www.adobe.com/content/dam/Adobe/en/devnet/pdf/pdfs/pdf_reference_1-7.pdf"
		version = "0.1"
		weight = 1
		
        strings:
                $magic = { 25 50 44 46 }
				$embed = /\/EmbeddedFiles/
				$ver = /%PDF-1\.[3-9]/

        condition:
                $magic at 0 and $embed and not $ver
}

rule js_splitting : PDF
{
        meta:
                author = "Glenn Edwards (@hiddenillusion)"
                version = "0.1"
                description = "These are commonly used to split up JS code"
                weight = 2
                
        strings:
                $magic = { 25 50 44 46 }
				$js = /\/JavaScript/
                $s0 = "getAnnots"
                $s1 = "getPageNumWords"
                $s2 = "getPageNthWord"
                $s3 = "this.info"
                                
        condition:
                $magic at 0 and $js and 1 of ($s*)
}

rule BlackHole_v2 : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://fortknoxnetworks.blogspot.no/2012/10/blackhhole-exploit-kit-v-20-url-pattern.html"
		weight = 3
		
	strings:
		$magic = { 25 50 44 46 }
		$content = "Index[5 1 7 1 9 4 23 4 50"
		
	condition:
		$magic at 0 and $content
}


/*
rule XDP_embedded_PDF : PDF
{
	meta:
		author = "Glenn Edwards (@hiddenillusion)"
		version = "0.1"
		ref = "http://blog.9bplus.com/av-bypass-for-malicious-pdfs-using-xdp"
        weight = 1		

	strings:
		$s1 = "<pdf xmlns="
		$s2 = "<chunk>"
		$s3 = "</pdf>"
		$header0 = "%PDF"
		$header1 = "JVBERi0"

	condition:
		all of ($s*) and 1 of ($header*)
}
*/