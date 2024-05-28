/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/
rule Big_Numbers0
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 20:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{20}/ fullword ascii
	condition:
		$c0
}

rule Big_Numbers1
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 32:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{32}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers2
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 48:sized"
		date = "2016-07"
	strings:
		$c0 = /[0-9a-fA-F]{48}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers3
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 64:sized"
		date = "2016-07"
	strings:
        	$c0 = /[0-9a-fA-F]{64}/ fullword wide ascii
	condition:
		$c0
}

rule Big_Numbers4
{
	meta:
		author = "_pusher_"
		description = "Looks for big numbers 128:sized"
		date = "2016-08"
	strings:
        	$c0 = /[0-9a-fA-F]{128}/ fullword wide ascii
	condition:
		$c0
}

rule CRC32c_poly_Constant {
	meta:
		author = "_pusher_"
		description = "Look for CRC32c (Castagnoli) [poly]"
		date = "2016-08"
	strings:
		$c0 = { 783BF682 }
	condition:
		$c0
}

rule CRC32_poly_Constant {
	meta:
		author = "_pusher_"
		description = "Look for CRC32 [poly]"
		date = "2015-05"
		version = "0.1"
	strings:
		$c0 = { 2083B8ED }
	condition:
		$c0
}

rule CRC32_table {
	meta:
		author = "_pusher_"
		description = "Look for CRC32 table"
		date = "2015-05"
		version = "0.1"
	strings:
		$c0 = { 00 00 00 00 96 30 07 77 2C 61 0E EE BA 51 09 99 19 C4 6D 07 }
	condition:
		$c0
}

rule BLOWFISH_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for Blowfish constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { D1310BA6 }
		$c1 = { A60B31D1 }	
		$c2 = { 98DFB5AC }
		$c3 = { ACB5DF98 }
		$c4 = { 2FFD72DB }
		$c5 = { DB72FD2F }
		$c6 = { D01ADFB7 }
		$c7 = { B7DF1AD0 }
		$c8 = { 4B7A70E9 }
		$c9 = { E9707A4B }
		$c10 = { F64C261C }
		$c11 = { 1C264CF6 }
	condition:
		6 of them
}

rule MD5_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for MD5 constants"
		date = "2014-01"
		version = "0.2"
	strings:
		// Init constants
		$c0 = { 67452301 }
		$c1 = { efcdab89 }
		$c2 = { 98badcfe }
		$c3 = { 10325476 }
		$c4 = { 01234567 }
		$c5 = { 89ABCDEF }
		$c6 = { FEDCBA98 }
		$c7 = { 76543210 }
		// Round 2
		$c8 = { F4D50d87 }
		$c9 = { 78A46AD7 }
	condition:
		5 of them
}


rule RIPEMD160_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for RIPEMD-160 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
	condition:
		5 of them
}

rule SHA1_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA1 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 67452301 }
		$c1 = { EFCDAB89 }
		$c2 = { 98BADCFE }
		$c3 = { 10325476 }
		$c4 = { C3D2E1F0 }
		$c5 = { 01234567 }
		$c6 = { 89ABCDEF }
		$c7 = { FEDCBA98 }
		$c8 = { 76543210 }
		$c9 = { F0E1D2C3 }
		//added by _pusher_ 2016-07 - last round
		$c10 = { D6C162CA }
	condition:
		5 of them
}

rule SHA512_Constants {
	meta:
		author = "phoul (@phoul)"
		description = "Look for SHA384/SHA512 constants"
		date = "2014-01"
		version = "0.1"
	strings:
		$c0 = { 428a2f98 }
		$c1 = { 982F8A42 }
		$c2 = { 71374491 }
		$c3 = { 91443771 }
		$c4 = { B5C0FBCF }
		$c5 = { CFFBC0B5 }
		$c6 = { E9B5DBA5 }
		$c7 = { A5DBB5E9 }
		$c8 = { D728AE22 }
		$c9 = { 22AE28D7 }
	condition:
		5 of them
}

rule SHA2_BLAKE2_IVs {
	meta:
		author = "spelissier"
		description = "Look for SHA2/BLAKE2/Argon2 IVs"
		date = "2019-12"
		version = "0.1"
	strings:
		$c0 = { 67 E6 09 6A }
		$c1 = { 85 AE 67 BB }
		$c2 = { 72 F3 6E 3C }
		$c3 = { 3A F5 4F A5 }
		$c4 = { 7F 52 0E 51 }
		$c5 = { 8C 68 05 9B }
		$c6 = { AB D9 83 1F }
		$c7 = { 19 CD E0 5B }

	condition:
		all of them
}

rule DES_sbox
{	meta:
		author = "_pusher_"
		date = "2015-05"
		description = "DES [sbox]"
	strings:
		$c0 = { 00 04 01 01 00 00 00 00 00 00 01 00 04 04 01 01 04 00 01 01 04 04 01 00 04 00 00 00 00 00 01 00 00 04 00 00 00 04 01 01 04 04 01 01 00 04 00 00 04 04 00 01 04 00 01 01 00 00 00 01 04 00 00 00 }
	condition:
		$c0
}

rule RijnDael_AES
{	meta:
		author = "_pusher_"
		description = "RijnDael AES"
		date = "2016-06"
	strings:
		$c0 = { A5 63 63 C6 84 7C 7C F8 }
	condition:
		$c0
}

rule RijnDael_AES_CHAR
{	meta:
		author = "_pusher_"
		description = "RijnDael AES (check2) [char]"
		date = "2016-06"
	strings:
		$c0 = { 63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76 CA 82 C9 7D FA 59 47 F0 AD D4 A2 AF 9C A4 72 C0 }
	condition:
		$c0
}

rule BASE64_table {
	meta:
		author = "_pusher_"
		description = "Look for Base64 table"
		date = "2015-07"
		version = "0.1"
	strings:
		$c0 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6E 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 2B 2F }
	condition:
		$c0
}

rule Delphi_FormShow {
	meta:
		author = "_pusher_"
		description = "Look for Form.Show function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 8B D8 B2 01 8B C3 E8 ?? ?? ?? ?? 8B C3 E8 ?? ?? ?? ?? 5B C3 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 48 89 D9 B2 01 E8 ?? ?? ?? ?? 48 89 D9 E8 ?? ?? ?? ?? 48 83 C4 20 5B C3 }
	condition:
		any of them
}

rule Delphi_CompareCall {
	meta:
		author = "_pusher_"
		description = "Look for Compare string function"
		date = "2016-07"
	strings:
		$c0 = { 53 56 57 89 C6 89 D7 39 D0 0F 84 8F 00 00 00 85 F6 74 68 85 FF 74 6B 8B 46 FC 8B 57 FC 29 D0 77 02 01 C2 52 C1 EA 02 74 26 8B 0E 8B 1F 39 D9 75 58 4A 74 15 8B 4E 04 8B 5F 04 39 D9 75 4B 83 C6 08 83 C7 08 4A 75 E2 EB 06 83 C6 04 83 C7 04 5A 83 E2 03 74 22 8B 0E 8B 1F 38 D9 75 41 4A 74 17 38 FD 75 3A 4A 74 10 81 E3 00 00 FF 00 81 E1 00 00 FF 00 39 D9 75 27 01 C0 EB 23 8B 57 FC 29 D0 EB 1C 8B 46 FC 29 D0 EB 15 5A 38 D9 75 10 38 FD 75 0C C1 E9 10 C1 EB 10 38 D9 75 02 38 FD 5F 5E 5B C3 }
		//newer delphi
		$c1 = { 39 D0 74 30 85 D0 74 22 8B 48 FC 3B 4A FC 75 24 01 C9 01 C8 01 CA F7 D9 53 8B 1C 01 3B 1C 11 75 07 83 C1 04 78 F3 31 C0 5B C3}
		//x64
		$c2 = { 41 56 41 55 57 56 53 48 83 EC 20 48 89 D3 48 3B CB 75 05 48 33 C0 EB 74 48 85 C9 75 07 8B 43 FC F7 D8 EB 68 48 85 DB 75 05 8B 41 FC EB 5E 8B 79 FC 44 8B 6B FC 89 FE 41 3B F5 7E 03 44 89 EE E8 ?? ?? ?? ?? 49 89 C6 48 89 D9 E8 ?? ?? ?? ?? 48 89 C1 85 F6 7E 30 41 0F B7 06 0F B7 11 2B C2 85 C0 75 29 83 FE 01 74 1E 41 0F B7 46 02 0F B7 51 02 2B C2 85 C0 75 15 49 83 C6 04 48 83 C1 04 83 EE 02 85 F6 7F D0 90 8B C7 41 2B C5 48 83 C4 20 5B 5E 5F 41 5D 41 5E C3 }
 	condition:
		any of them
}

rule Delphi_Copy {
	meta:
		author = "_pusher_"
		description = "Look for Copy function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 85 C0 74 2D 8B 58 FC 85 DB 74 26 4A 7C 1B 39 DA 7D 1F 29 D3 85 C9 7C 19 39 D9 7F 11 01 C2 8B 44 24 08 E8 ?? ?? ?? ?? EB 11 31 D2 EB E5 89 D9 EB EB 8B 44 24 08 E8 ?? ?? ?? ?? 5B C2 04 00 }
		//x64 rad
		$c1 = { 53 48 83 EC 20 48 89 CB 44 89 C0 48 33 C9 48 85 D2 74 03 8B 4A FC 83 F8 01 7D 05 48 33 C0 EB 09 83 E8 01 3B C1 7E 02 89 C8 45 85 C9 7D 05 48 33 C9 EB 0A 2B C8 41 3B C9 7E 03 44 89 C9 49 89 D8 48 63 C0 48 8D 14 42 89 C8 4C 89 C1 41 89 C0 E8 ?? ?? ?? ?? 48 89 D8 48 83 C4 20 5B C3 }
	condition:
		any of them
}

rule Delphi_StrToInt {
	meta:
		author = "_pusher_"
		description = "Look for StrToInt function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 53 56 83 C4 F4 8B D8 8B D4 8B C3 E8 ?? ?? ?? ?? 8B F0 83 3C 24 00 74 19 89 5C 24 04 C6 44 24 08 0B 8D 54 24 04 A1 ?? ?? ?? ?? 33 C9 E8 ?? ?? ?? ?? 8B C6 83 C4 0C 5E 5B C3 }
		//x64 rad
		$c1 = { 55 56 53 48 83 EC 40 48 8B EC 48 89 CB 48 89 D9 48 8D 55 3C E8 ?? ?? ?? ?? 89 C6 83 7D 3C 00 74 1B 48 89 5D 20 C6 45 28 11 48 8B 0D ?? ?? ?? ?? 48 8D 55 20 4D 33 C0 E8 ?? ?? ?? ?? 89 F0 48 8D 65 40 5B 5E 5D C3 }
	condition:
		any of them
}

rule Delphi_DecodeDate {
	meta:
		author = "_pusher_"
		description = "Look for DecodeDate (DecodeDateFully) function"
		date = "2016-06"
		version = "0.1"
	strings:
		$c0 = { 55 8B EC 83 C4 E8 53 56 89 4D F4 89 55 F8 89 45 FC 8B 5D 08 FF 75 10 FF 75 0C 8D 45 E8 E8 ?? ?? ?? ?? 8B 4D EC 85 C9 7F 24 8B 45 FC 66 C7 00 00 00 8B 45 F8 66 C7 00 00 00 8B 45 F4 66 C7 00 00 00 66 C7 03 00 00 33 D2 E9 F2 00 00 00 8B C1 BE 07 00 00 00 99 F7 FE 42 66 89 13 49 66 BB 01 00 81 F9 B1 3A 02 00 7C 13 81 E9 B1 3A 02 00 66 81 C3 90 01 81 F9 B1 3A 02 00 7D ED 8D 45 F2 50 8D 45 F0 66 BA AC 8E 91 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 AC 8E 66 6B 45 F0 64 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA B5 05 E8 ?? ?? ?? ?? 66 8B 45 F0 C1 E0 02 66 03 D8 8D 45 F2 50 8D 4D F0 0F B7 45 F2 66 BA 6D 01 E8 ?? ?? ?? ?? 66 83 7D F0 04 75 0A 66 FF 4D F0 66 81 45 F2 6D 01 66 03 5D F0 8B C3 E8 ?? ?? ?? ?? 8B D0 33 C0 8A C2 8D 04 40 8D 34 C5 ?? ?? ?? ?? 66 B8 01 00 0F B7 C8 66 8B 4C 4E FE 66 89 4D F0 66 8B 4D F2 66 3B 4D F0 72 0B 66 8B 4D F0 66 29 4D F2 40 EB DF 8B 4D FC 66 89 19 8B 4D F8 66 89 01 66 8B 45 F2 40 8B 4D F4 66 89 01 8B C2 5E 5B 8B E5 5D C2 0C 00 }
		//x64
		$c1 = { 55 41 55 57 56 53 48 83 EC 30 48 8B EC 48 89 D3 4C 89 C6 4C 89 CF E8 ?? ?? ?? ?? 48 8B C8 48 C1 E9 20 85 C9 7F 23 66 C7 03 00 00 66 C7 06 00 00 66 C7 07 00 00 48 8B 85 80 00 00 00 66 C7 00 00 00 48 33 C0 E9 19 01 00 00 4C 8B 85 80 00 00 00 41 C7 C1 07 00 00 00 8B C1 99 41 F7 F9 66 83 C2 01 66 41 89 10 83 E9 01 66 41 BD 01 00 81 F9 B1 3A 02 00 7C 14 81 E9 B1 3A 02 00 66 41 81 C5 90 01 81 F9 B1 3A 02 00 7D EC 90 66 BA AC 8E 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E AC 8E 66 6B 45 2C 64 66 44 03 E8 0F B7 4D 2E 66 BA B5 05 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 48 0F B7 45 2C 03 C0 03 C0 66 44 03 E8 0F B7 4D 2E 66 BA 6D 01 4C 8D 45 2C 4C 8D 4D 2E E8 ?? ?? ?? ?? 66 83 7D 2C 04 75 0B 66 83 6D 2C 01 66 81 45 2E 6D 01 66 44 03 6D 2C 44 89 E9 E8 ?? ?? ?? ?? 48 8D 0D ?? ?? ?? ?? 48 0F B6 D0 48 8D 14 52 48 8D 14 D1 66 B9 01 00 4C 0F B7 C1 4E 0F B7 44 42 FE 66 44 89 45 2C 4C 0F B7 45 2E 66 44 3B 45 2C 72 10 4C 0F B7 45 2C 66 44 29 45 2E 66 }
	condition:
		any of them
}

rule VC8_Random {
	meta:
		author = "_pusher_"
		description = "Look for Random function"
		date = "2016-01"
		version = "0.1"
	strings:
		$c0 = { E8 ?? ?? ?? ?? 8B 48 14 69 C9 FD 43 03 00 81 C1 C3 9E 26 00 89 48 14 8B C1 C1 E8 10 25 FF 7F 00 00 C3 }
	condition:
		$c0
}

rule Chacha_256_constant {
    meta:
		author = "spelissier"
		description = "Look for 256-bit key Chacha stream cipher constant"
		date = "2019-12"
		reference = "https://tools.ietf.org/html/rfc8439#page-8"
	strings:
		$c0 = "expand 32-byte k"
		$split1 = "expand 3"
		$split2 = "2-byte k"
	condition:
		$c0 or ( $split1 and $split2 )
}

rule ecc_order {
    meta:
		author = "spelissier"
		description = "Look for known Elliptic curve orders"
		date = "2021-07"
		version = "0.2"
	strings:
		$secp192k1 = { FF FF FF FF FF FF FF FF FF FF FF FE 26 F2 FC 17 0F 69 46 6A 74 DE FD 8D}
		$secp192r1 = { FF FF FF FF FF FF FF FF FF FF FF FF 99 DE F8 36 14 6B C9 B1 B4 D2 28 31}
		$secp224k1 = { 01 00 00 00 00 00 00 00 00 00 00 00 00 00 01 DC E8 D2 EC 61 84 CA F0 A9 71 76 9F B1 F7}
		$secp224r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF 16 A2 E0 B8 F0 3E 13 DD 29 45 5C 5C 2A 3D}
		$secp256k1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FE BA AE DC E6 AF 48 A0 3B BF D2 5E 8C D0 36 41 41 }
		$prime256v1 = { FF FF FF FF 00 00 00 00 FF FF FF FF FF FF FF FF BC E6 FA AD A7 17 9E 84 F3 B9 CA C2 FC 63 25 51 }
		$secp384r1 = { FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF C7 63 4D 81 F4 37 2D DF 58 1A 0D B2 48 B0 A7 7A EC EC 19 6A CC C5 29 73 }
		$bls12_381_r = { 01 00 00 00 FF FF FF FF FE 5B FE FF 02 A4 BD 53 05 D8 A1 09 08 D8 39 33 48 7D 9D 29 53 A7 ED 73}
	condition:
		any of them
}