rule Suspicious_String_Download {
    strings:
        $s1 = "http://" nocase
        $s2 = "https://" nocase
    condition:
        any of ($s*)
}

rule UPX_Packed {
    meta:
        description = "Detect UPX packed files by section names"
    condition:
        for any i in (0..filesize) : (uint32(i) == 0x6050000) or (for any section in pe.sections : section.name == "UPX0" or section.name == "UPX1")
}