/*
  ============================================================================
  KDF Engine Detection Pack (E-700U) — Public Ruleset
  ============================================================================

  Author
    - TITAN Softwork Solutions
*/

import "pe"

rule KDF_RS_Resolver_PEB_Ldr_InLoadOrder_Traversal
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "PEB module enumeration"
    confidence  = "high"
    severity    = "medium"
    description = "Syscall-map init enumerates loaded modules via PEB->Ldr->InLoadOrderModuleList and walks Flink entries."

  strings:
    $peb_walk = {
      65 48 8B 04 25 60 00 00 00   /* mov rax, [gs:0x60]        */
      48 8B 40 18                  /* mov rax, [rax+0x18]       */
      48 8B 40 10                  /* mov rax, [rax+0x10]       */
      31 C9                        /* xor ecx, ecx              */
      6A 01                        /* push 1                    */
      5A                           /* pop rdx                   */
      49 89 C0                     /* mov r8, rax               */
      4D 8B 00                     /* mov r8, [r8] (Flink walk) */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $peb_walk
}


rule KDF_RS_Resolver_PE_ExportDir_Parse_Offset88
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "manual export parsing"
    confidence  = "high"
    severity    = "high"
    description = "Syscall-map init validates MZ/PE and resolves IMAGE_EXPORT_DIRECTORY using OptionalHeader DataDirectory[EXPORT] offset (0x88) on AMD64."

  strings:
    $exp_parse = {
      66 41 81 3C 24 4D 5A          /* cmp word [r12], 'MZ'                    */
      0F 85 ?? ?? ?? ??             /* jne ...                                */
      4D 63 4C 24 3C                /* movsxd r9, dword [r12+0x3c]             */
      43 81 3C 0C 50 45 00 00       /* cmp dword [r12+r9], 'PE\0\0'            */
      0F 85 ?? ?? ?? ??             /* jne ...                                */
      47 8B 8C 0C 88 00 00 00       /* mov r9d, dword [r12+r9+0x88] (EXPORT DD)*/
      4D 85 C9                      /* test r9, r9                            */
      74 ??                         /* je ...                                 */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $exp_parse
}


rule KDF_RS_Resolver_ExportStub_Probe_4C4DB8_Flow
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "syscall-stub probing"
    confidence  = "high"
    severity    = "high"
    description = "Syscall-map init probes exported function entrypoints via first-byte classification (0x4C/0x4D/0xB8) before deeper checks."

  strings:
    $probe_flow = {
      47 0F B6 3C 34              /* movzx r15d, byte [r12+r14]      */
      41 83 FF 4C                 /* cmp r15d, 0x4C                  */
      74 ??                       /* je ...                          */
      41 83 FF 4D                 /* cmp r15d, 0x4D                  */
      74 ??                       /* je ...                          */
      41 81 FF B8 00 00 00        /* cmp r15d, 0xB8                  */
      75 ??                       /* jne ...                         */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $probe_flow
}


rule KDF_RS_Resolver_ExportStub_Probe_8BD1B8_SecondaryChecks
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "syscall-stub probing"
    confidence  = "very-high"
    severity    = "high"
    description = "Syscall-map init performs byte-wise secondary checks for a canonical Nt syscall stub shape (.. 8B D1 B8) using indexed byte compares."

  strings:
    $sec_checks = {
      43 80 7C 34 01 8B            /* cmp byte [r12+r14+1], 0x8B */
      75 ??                        /* jne ...                    */
      43 80 7C 34 02 D1            /* cmp byte [r12+r14+2], 0xD1 */
      75 ??                        /* jne ...                    */
      43 80 7C 34 03 B8            /* cmp byte [r12+r14+3], 0xB8 */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $sec_checks
}


rule KDF_RS_Resolver_SyscallCandidateThreshold_0x1E
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "candidate threshold gate"
    confidence  = "medium-high"
    severity    = "medium"
    description = "Syscall-map init counts candidate stubs and gates on a >=0x1E threshold inside the export-scan loop."

  strings:
    $thresh = {
      FF C3                       /* inc ebx            */
      83 FB 1E                    /* cmp ebx, 0x1E      */
      7E ??                       /* jle ...            */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $thresh
}


rule KDF_RS_Resolver_VectorTriplesStride18_Store
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "vector triple packing"
    confidence  = "medium-high"
    severity    = "medium"
    description = "Syscall-map init packs per-export metadata into a vector of 0x18-byte tuples (name ptr, length, stub ptr)."

  strings:
    $triple_pack = {
      48 6B CA 18                 /* imul rcx, rdx, 0x18           */
      4C 89 34 08                 /* mov  [rax+rcx], r14           */
      4C 89 7C 08 08              /* mov  [rax+rcx+8], r15         */
      4C 8B 45 E8                 /* mov  r8, [rbp-0x18] (stub ptr)*/
      4C 89 44 08 10              /* mov  [rax+rcx+0x10], r8       */
      48 FF C2                    /* inc  rdx                      */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $triple_pack
}


rule KDF_RS_Resolver_DualRawTableInit_HashbrownStyle
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    technique   = "dual map init"
    confidence  = "medium"
    severity    = "low"
    description = "Syscall-map init initializes two hash-table backends in sequence (capacity set from discovered syscall candidates)."

  strings:
    $dual_init = {
      C6 45 ?? 01                 /* mov byte [rbp+/-off], 1 (guard flag) */
      48 8D 4D ??                 /* lea rcx, [rbp+/-off]                 */
      48 89 F2                    /* mov rdx, rsi                         */
      E8 ?? ?? ?? ??              /* call ... (with_capacity_in)          */
      C6 45 ?? 01                 /* mov byte [rbp+/-off], 1              */
      48 8D 4D ??                 /* lea rcx, [rbp+/-off]                 */
      48 89 F2                    /* mov rdx, rsi                         */
      E8 ?? ?? ?? ??              /* call ... (with_capacity_in)          */
    }

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    $dual_init
}


rule KDF_RS_Resolver_KfInitializeSyscallMaps_Composite
{
  meta:
    family      = "KDF"
    variant     = "Rust"
    component   = "resolver/syscall-map"
    confidence  = "very-high"
    severity    = "critical"
    description = "Composite: KDF Rust syscall-map initializer (PEB module walk + export dir parse + syscall stub probe + metadata packing)."
    guidance    = "Recommended for alerting; keep component rules enabled for enrichment and triage."

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    filesize < 12MB and
    KDF_RS_Resolver_PEB_Ldr_InLoadOrder_Traversal and
    KDF_RS_Resolver_PE_ExportDir_Parse_Offset88 and
    KDF_RS_Resolver_ExportStub_Probe_4C4DB8_Flow and
    KDF_RS_Resolver_ExportStub_Probe_8BD1B8_SecondaryChecks and
    (
      KDF_RS_Resolver_VectorTriplesStride18_Store or
      KDF_RS_Resolver_SyscallCandidateThreshold_0x1E or
      KDF_RS_Resolver_DualRawTableInit_HashbrownStyle
    )
}


rule KDF_UNIFIED_AnyStrongSignal
{
  meta:
    family      = "KDF"
    variant     = "Unified"
    component   = "unified/strong-signal"
    confidence  = "very-high"
    severity    = "critical"
    description = "Unified alert: strong composite match for KDF syscall resolver behavior."

  condition:
    pe.is_pe and pe.machine == pe.MACHINE_AMD64 and
    (
      KDF_RS_Resolver_KfInitializeSyscallMaps_Composite or
      (
        /* fallback: resolver core invariants without full composite */
        KDF_RS_Resolver_PEB_Ldr_InLoadOrder_Traversal and
        KDF_RS_Resolver_PE_ExportDir_Parse_Offset88 and
        1 of (
          KDF_RS_Resolver_ExportStub_Probe_4C4DB8_Flow,
          KDF_RS_Resolver_ExportStub_Probe_8BD1B8_SecondaryChecks,
          KDF_RS_Resolver_VectorTriplesStride18_Store
        )
      )
    )
}