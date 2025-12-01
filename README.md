# SNOWFINCH

## BRIEF

Project `SNOWFINCH` is a miscellaneous collection of [YARA-X](https://virustotal.github.io/yara-x/) rules.

## CATALOG

### LINKER DETECTION

| Rule | Purpose | Notes |
| ---- | ------- | ----- |
| [detect_bfd_pe.yar](./detect_bfd_pe.yar) | Detect binaries linked with bfd | Maybe compiled using MinGW GCC toolchain |
| [detect_lld_pe.yar](./detect_lld_pe.yar) | Detect binaries linked with lld | Maybe compiled using LLVM/Clang toolchain |

### GENERIC

| Rule | Purpose | Notes |
| ---- | ------- | ----- |
| [detect_pe_parsing.yar](./detect_pe_parsing.yar) | Detect IoCs associated with manual PE parsing | Won't work with crappy malware that doesn't bother to check the header sigs |