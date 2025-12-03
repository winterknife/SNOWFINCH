rule detect_teb_access {
    meta:
        author = "winterknife"
        description = "Detect 64-bit TEB access using some commonly used techniques"
        version = "1.0"
        date = "2025-12-03"
        modified = "2025-12-03"
        sharing = "TLP:BLACK"

    strings:
        /*
        65 48 8B 04 25 30 00 00 00 | mov rax, qword ptr gs:[0x0000000000000030]
        */
        $code_1 = { 65 48 8B ?? 25 30 00 00 00 }
        /*
        B8 30 00 00 00       | mov eax, 0x30
        41 B8 30 00 00 00    | mov r8d, 0x30
        48 C7 C0 30 00 00 00 | mov rax, 0x30
        49 C7 C0 30 00 00 00 | mov r8, 0x30
        65 67 48 8B 00       | mov rax, qword ptr gs:[eax]
        65 48 8B 00          | mov rax, qword ptr gs:[rax]
        */
        $code_2 = { (B? 30 00 00 00 | 41 B? 30 00 00 00 | (48 | 49) C7 C? 30 00 00 00) (65 67 4? 8B ?? | 65 4? 8B ??) }
        /*
        6A 30          | push 0x30
        58             | pop rax
        41 58          | pop r8
        65 67 48 8B 00 | mov rax, qword ptr gs:[eax]
        65 48 8B 00    | mov rax, qword ptr gs:[rax]
        */
        $code_3 = { 6A 30 (5? | 41 5?) (65 67 4? 8B ?? | 65 4? 8B ??) }
        /*
        31 C0             | xor eax, eax
        45 31 C0          | xor r8d, r8d
        48 31 C0          | xor rax, rax
        4D 31 C0          | xor r8, r8
        65 67 48 8B 40 30 | mov rax, qword ptr gs:[eax+0x30]
        65 48 8B 40 30    | mov rax, qword ptr gs:[rax+0x30]
        */
        $code_4 = { (31 ?? | (45 | 48 | 4D) 31 ??) (65 67 4? 8B ?? 30 | 65 4? 8B ?? 30) }
        /*
        83 C0 30       | add eax, 0x30
        41 83 C0 30    | add r8d, 0x30
        48 83 C0 30    | add rax, 0x30
        49 83 C0 30    | add r8, 0x30
        65 67 48 8B 00 | mov rax, qword ptr gs:[eax]
        65 48 8B 00    | mov rax, qword ptr gs:[rax]
        */
        $code_5 = { (83 C? 30 | (41 | 48 | 49) 83 C? 30) (65 67 4? 8B ?? | 65 4? 8B ??) }

    condition:
        any of them
}
