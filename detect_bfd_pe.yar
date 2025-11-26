import "pe"

rule detect_bfd_pe {
    meta:
        author = "winterknife"
        description = "Detect binaries linked with bfd"
        version = "1.0"
        date = "2025-11-25"
        modified = "2025-11-25"
        sharing = "TLP:BLACK"

    condition:
        // PE file
        pe.is_pe
        and
        (
            // GNU ld (GNU Binutils) 2.30
            // Copyright (C) 2018 Free Software Foundation, Inc.
            pe.linker_version.major == 2
            and
            pe.linker_version.minor >= 30
        )
        and
        // As far as I know, only the bfd linker is capable of producing such binaries
        pe.characteristics & pe.LINE_NUMS_STRIPPED != 0
}
