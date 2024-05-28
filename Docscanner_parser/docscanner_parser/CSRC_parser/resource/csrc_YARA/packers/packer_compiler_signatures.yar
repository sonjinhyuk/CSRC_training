/*
    This Yara ruleset is under the GNU-GPLv2 license (http://www.gnu.org/licenses/gpl-2.0.html) and open to any user or organization, as long as you use it under this license.
*/

import "pe"
import "math"

rule IsPE32 : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x18) == 0x010B
}

rule IsDLL : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		(uint16(uint32(0x3C)+0x16) & 0x2000) == 0x2000

}

rule IsWindowsGUI : PECheck
{
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint16(uint32(0x3C)+0x5C) == 0x0002
}

rule HasOverlay : PECheck
{
	meta: 
		author="_pusher_"
		description = "Overlay Check"
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		//stupid check if last section is 0		
		//not (pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) == 0x0 and

		(pe.sections[pe.number_of_sections-1].raw_data_offset+pe.sections[pe.number_of_sections-1].raw_data_size) < filesize
		
}

rule HasRichSignature : PECheck
{
	meta: 
		author = "_pusher_"
		description = "Rich Signature Check"
		date="2016-07"
	strings:	
		$a0 = "Rich" ascii
	condition:
		// MZ signature at offset 0 and ...
		uint16(0) == 0x5A4D and
		// ... PE signature at offset stored in MZ header at 0x3C
		uint32(uint32(0x3C)) == 0x00004550 and
		(for any of ($a*) : ($ in (0x0..uint32(0x3c) )))
}

rule IsSuspicious
{
	meta:
		author="_pusher_"
		date = "2016-07"
		description="Might be PE Virus"
	condition:
		uint32(0x20) == 0x20202020	
}