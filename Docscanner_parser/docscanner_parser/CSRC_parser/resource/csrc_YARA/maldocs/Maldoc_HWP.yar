rule Contains_PE_file{
    strings:
		$string1 = "MZ"
		$string2 = "!This program cannot be run in DOS mode"
		
    condition:
		all of them

}


rule HWP_JScript{
	meta:
		description = "HWP JavaScript Detect"
	strings:
		$string1 = "ActiveXObject" nocase
		$string2 = "GetSpecialFolder" nocase
		$string3 = "WriteText" nocase
		$string4 = "SaveToFile" nocase
		$string5 = "WriteAll" nocase
		$string6 = "Run" nocase fullword
	condition:
		($string1 and $string2 and $string3 and $string4) or 
		($string1 and $string6) or 
		($string1 and $string2 and $string5 and $string6)
		
}


rule HWP_iframe {
    meta:
        description = "iframe tag Insertion"
    strings:
        $string1 = "<iframe src=" 
		$string2 = "width=0"
		$string3 = "height=0"
		$string4 = "</iframe>"
    condition:
        all of them
}


rule HWP_XF_Sic {
	meta:
		description = "HWP XF/Sic MS Excel Detect"
	strings:
		$string1 = "Classic.Poppy by VicodinES"
		$string2 = "An Excel Formula Macro Virus" 
    condition:
        all of them
}


rule HWP_excel {
	meta:
		description = "한글 문서 개체 연결 삽입(엑셀 차트)"
	strings:
		$string1 = "auto_open" nocase
		$string2 = "check_files" nocase
		$string3 = "SaveAs" nocase
	condition:
		all of them
}

rule HWP_Malware_EPS {
    meta:
        author = "HWP EPS File Detect"
    strings:
        $regex1 = /<[0-9A-Fa-f]{500,}/
        $string1 = "4 mod get xor put" nocase
        $string2 = "exec"
        $string3 = "/concatstrings" nocase
        $string4 = "dup dup 4 2 roll copy length" nocase
		$string5 = "and"
		$string6 = "get xor"
		$string7 = "string dup"
		$string8 = "putinterval"
		$string9 = "repeat"
		$string10 = "aload"
		$string11 = ".eqproc"
		$string12 = "{lt} put"
		$string13 = "get closefile"
    condition:
        ($regex1 and 1 of ($string1, $string2, $string3, $string4)) or $string2 or ($string2 and $string5 and $string6) or ($string7 and $string8 and $string9) or ($string10 and $string11 and $string12 and $string13)
}


rule HWP_malicious_API{
	meta:
		description = "HWP OLE Detect"
	strings:
		$string1 = "UrlDownloadToFile"
		$string2 = "GetTempPath"
		$string3 = "GetWindowsDirectory"
		$string4 = "GetSystemDirectory"
		$string5 = "ShellExecute"
		$string6 = "IsBadReadPtr"
		$string7 = "CreafeFile"
		$string8 = "CreateHandle"
		$string9 = "ReadFile"
		$string10 = "WriteFile"
		$string11 = "SetFilePointer"
		$string12 = "VirtualAlloc"
		$string13 = "GetProcAddress"
		$string14 = "LoadLibrary"
		$string15 = "GetProcAddr"
		$string16 = "WinExec"
		$string17 = "Execute"
    condition:
        any of them
}


rule HWP_powershell_API{
	meta:
		description = "Scans for powershell function name"
	strings:
		$string1 = "IEX" nocase
		$string2 = "downloaddata" nocase
	condition:
		($string1 and $string2) or $string2
}


rule detect_shellcode{
    meta:
        description = "Rule to detect Shellcode in the BinData"

    strings:
        $a1 = {AC 84 C0 74 07 C1 CF 0D 01 C7 EB F4 81 FF}
        $a2 = {AC 84 C0 74 07 C1 CF 07 01 C7 EB F4 81 FF}
        $a3 = {30 32 38 46 43 42 37 44 44}
        $a4 = {39 30 30 30 30 33 30 30 30 30 30 30 30 34 30 30 30 30 30 30 46 46 46 46 30 30 30 30 42}

    condition:
        any of them
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

rule apt_NK_Lazarus_SKOlympics_EPS
{
	meta:
		author = "JAG-S, Insikt Group, RF"
		desc = "CN terms in PostScript loader"
		TLP = "Green"
		version = "1.0"
		md5 = "231fe349faa7342f33402c562f93a270"
	strings:
		$eps_strings1 = "/yinzi { token pop exch pop } bind def" ascii wide
		$eps_strings2 = "/yaoshi <A3E6E7BB> def" ascii wide
		$eps_strings8 = /\/yaoshi <[A-F0-9]{8}> def/ ascii wide
		$eps_strings3 = "/yima{" ascii wide
		$eps_strings4 = "/funcA exch def" ascii wide
		$eps_strings5 = "0 1 funcA length 1 sub {" ascii wide
		$eps_strings6 = "/funcB exch def" ascii wide
		$eps_strings7 = "funcA funcB 2 copy get yaoshi funcB 4 mod get xor put" ascii wide
	condition:
		6 of them
}

rule Hwp_Malware1 {
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

rule Hwp_Malware2 {
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

rule Hwp_Malware3 {
	meta:
		author = "Kei Choi (hanul93@gmail.com)"
		date = "2017-08-23"
		KicomAV = "Trojan.PS.Agent.yrc"
	strings:
		$regex1 = /<[0-9A-Fa-f]{500,}/
		$string1 = "4 mod get xor put" nocase
		$string2 = "exec" nocase
		$string3 = "/concatstrings" nocase
		$string4 = "dup dup 4 2 roll copy length" nocase
		$string5 = "and"
		$string6 = "get xor"
	condition:
		($regex1 and 1 of ($string*)) or ($string2 and $string5 and $string6)
}

rule apt_NK_Lazarus_Fall2017_payload_minCondition {
	meta:
		desc = "Minimal condition set to detect payloads from Fall 2017 Lazarus Campaign against Cryptocurrency Exchanges and Friends of MOFA 11"
		author = "JAGS, Insikt Group, Recorded Future"
		version = "2.0"
		TLP = "Green"
		md5 = "46d1d1f6e396a1908471e8a8d8b38417"
		md5 = "6b061267c7ddeb160368128a933d38be"
		md5 = "afa40517d264d1b03ac5c4d2fef8fc32"
		md5 = "c270eb96deaf27dd2598bc4e9afd99da"
		md5 = "d897b4b8e729a408f64911524e8647db"
		md5 = "e1cc2dcb40e729b2b61cf436d20d8ee5"
	strings:
		$sub1800115A0 = {488D542460488D8DB005000041FF9424882000004C8BE84883F8FF0F84EA010000488D8DC007000033D241B800400000E8}
		$sub18000A720 = {33C0488BBC2498020000488B9C2490020000488B8D600100004833CCE8}
	condition:
		uint16(0) == 0x5A4D and filesize < 5MB
		and
		any of them
}

rule SUSP_XORed_MSDOS_Stub_Message {
	meta:
		description = "Detects suspicious XORed MSDOS stub message"
		author = "Florian Roth"
		reference = "https://yara.readthedocs.io/en/latest/writingrules.html#xor-strings"
		date = "2019-10-28"
		score = 55
	strings:
		$xo1 = "This program cannot be run in DOS mode" xor ascii wide
		$xo2 = "This program must be run under Win32" xor ascii wide
		$xof1 = "This program cannot be run in DOS mode" ascii wide
		$xof2 = "This program must be run under Win32" xor ascii wide
	condition:
		1 of ($xo*) and not 1 of ($xof*)
}