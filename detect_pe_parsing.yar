rule detect_pe_parsing {
    meta:
        author = "winterknife"
        description = "Detect IoCs associated with manual PE parsing"
        version = "1.0"
        date = "2025-11-30"
        modified = "2025-12-01"
        sharing = "TLP:BLACK"

    strings:
        /*
        66 81 38 4D 5A    | cmp word ptr ds:[rax], 0x5A4D
        66 81 3B 4D 5A    | cmp word ptr ds:[rbx], 0x5A4D
        66 81 39 4D 5A    | cmp word ptr ds:[rcx], 0x5A4D
        66 81 3A 4D 5A    | cmp word ptr ds:[rdx], 0x5A4D
        66 81 3E 4D 5A    | cmp word ptr ds:[rsi], 0x5A4D
        66 81 3F 4D 5A    | cmp word ptr ds:[rdi], 0x5A4D
        66 41 81 38 4D 5A | cmp word ptr ds:[r8], 0x5A4D
        66 41 81 39 4D 5A | cmp word ptr ds:[r9], 0x5A4D
        66 41 81 3A 4D 5A | cmp word ptr ds:[r10], 0x5A4D
        66 41 81 3B 4D 5A | cmp word ptr ds:[r11], 0x5A4D
        66 41 81 3E 4D 5A | cmp word ptr ds:[r14], 0x5A4D
        66 41 81 3F 4D 5A | cmp word ptr ds:[r15], 0x5A4D
        */
        $code_1 = { 66 81 (38 | 3B | 39 | 3A | 3E | 3F) 4D 5A }
        $code_2 = { 66 41 81 (38 | 39 | 3A | 3B | 3E | 3F) 4D 5A }
        /*
        3D 4D 5A 00 00    | cmp eax, 0x5A4D
        81 F8 4D 5A 00 00 | cmp eax, 0x5A4D
        */
        $code_3 = { 3D 4D 5A 00 00 }
        $code_4 = { 81 F? 4D 5A 00 00 }
        /*
        81 3C 01 50 45 00 00    | cmp dword ptr ds:[rcx+rax*1], 0x4550
        81 3C 0A 50 45 00 00    | cmp dword ptr ds:[rdx+rcx*1], 0x4550
        41 81 3C 00 50 45 00 00 | cmp dword ptr ds:[r8+rax*1], 0x4550
        43 81 3C 18 50 45 00 00 | cmp dword ptr ds:[r8+r11*1], 0x4550
        */
        $code_5 = { 81 3C ?? 50 45 00 00 }
        $code_6 = { (41 | 43) 81 3C ?? 50 45 00 00 }
        /*
        3D 50 45 00 00    | cmp eax, 0x4550
        81 F8 50 45 00 00 | cmp eax, 0x4550
        */
        $code_7 = { 3D 50 45 00 00 }
        $code_8 = { 81 F? 50 45 00 00 }
        /*
        81 38 50 45 00 00    | cmp dword ptr ds:[rax], 0x4550
        41 81 38 50 45 00 00 | cmp dword ptr ds:[r8], 0x4550
        */
        $code_9 = { 81 3? 50 45 00 00 }
        $code_10 = { 41 81 3? 50 45 00 00 }

    condition:
        any of them
}
