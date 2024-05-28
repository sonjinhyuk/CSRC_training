rule find_mz_file
{
    meta:
        description = "Find MZ file"
    strings:
        $mz = {4D 5A}
		$pe = {50 45 00 00}
    condition:
        $mz and $pe
}