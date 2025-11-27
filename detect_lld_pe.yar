import "pe"

rule detect_lld_pe {
    meta:
        author = "winterknife"
        description = "Detect binaries linked with lld"
        version = "1.0"
        date = "2025-11-27"
        modified = "2025-11-27"
        sharing = "TLP:BLACK"

    condition:
        // PE file
        pe.is_pe
        and
        // BFD linker (and LLD linker) are incapable of emitting the PE Rich header
        not defined pe.rich_signature.length
        and
        (
            // LLD linker sets {Major,Minor}LinkerVersion to 14.0
            // https://github.com/llvm/llvm-project/blob/682f292d2caec5b71f8ce6c641114fee446ba49f/lld/COFF/Writer.cpp#L1895
            // https://github.com/llvm/llvm-project/blob/682f292d2caec5b71f8ce6c641114fee446ba49f/lld/COFF/Writer.cpp#L1896
            pe.linker_version.major == 14
            and
            pe.linker_version.minor == 0
        )
        // MSVC linker in Visual Studio 2015 with the /EMITTOOLVERSIONINFO:NO linker switch?
}
