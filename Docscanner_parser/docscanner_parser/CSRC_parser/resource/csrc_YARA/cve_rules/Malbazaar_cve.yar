rule CVE_2017_11882_2
{
    meta:
		old_name = "INDICATOR_OLE_EXPLOIT_CVE_2017_11882_1"
        description = "detects OLE documents potentially exploiting CVE-2017-11882"
        author = "ditekSHen"
    strings:
        $s1 = { d0 cf 11 e0 a1 b1 1a e1 }
        $s2 = { 02 ce 02 00 00 00 00 00 c0 00 00 00 00 00 00 46 }
        $s3 = "ole10native" wide nocase
        $s4 = "Root Entry" wide
    condition:
        uint16(0) == 0xcfd0 and all of them
}

rule CVE_2021_40444_XML_4
{
    meta:
		old_name = "cve_2021_40444_document_rels_xml"
        author = "Jeremy Brown / @alteredbytes"
        reference = "https://twitter.com/AlteredBytes/status/1435811407249952772"
    strings:
        $a = /^<\?xml\sversion="\d\.\d"/
        $b = /Type="http:\/\/[^"]+\/relationships\/(oleObject|attachedTemplate)"/
        $c = /Target="mhtml:https?:\/\/[^!]+!x-usc:https?:\/\/[^"]+"/ nocase
        $d = /TargetMode="External"/
    condition:
        $a at 0 and all of them
}