/*
 * svmhvctl.c - the ring-3 side of the hypervisor's control channel.
 *
 * The driver exposes nothing: no device, no IOCTL, no doorbell in memory that
 * anything but the hypervisor itself can reach.  This talks to it by executing
 * CPUID with a private leaf and a key, and reads the answers back out of the
 * registers.  See hvasm.asm for why that needs assembler.
 *
 * Output is deliberately flat "key=value" lines, one record per line, so the MCP
 * server can parse it without guessing.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "svmhvctl.h"

/* The magic in RAX is the whole access check; see svm.h. */
#define SVMHV_HYPERCALL_MAGIC   0x53564D485643414CULL

#define HV_PING                 0
#define HV_WRITE_REQUEST        1
#define HV_SUBMIT               2
#define HV_POLL                 3
#define HV_READ_SNAPSHOT        4
#define HV_READ_REQUEST         5
#define HV_READ_TRACE           6
#define HV_TRACE_STATE          7
#define HV_UNLOAD               8
#define HV_SIGNATURE            9
#define HV_TRACE_CONSUMED       10

#define HV_OK                   0
#define HV_ABSENT               0xFFFFFFFFFFFFFFFFULL   /* VMMCALL raised #UD */
#define HV_READ_WINDOW          48

/* Mirrors svmhvctl.h's view of the driver; see the C_ASSERTs there. */
#define SNAP_STATS              16
#define SNAP_HISTOGRAM          656
#define SNAP_HOOKS              2728
#define SNAP_SELFTEST           6832
#define SNAP_SIZE               7000

#define REQ_TARGET              0
#define REQ_DETOUR              8
#define REQ_PROLOG              16
#define REQ_ACTION              20
#define REQ_KIND                24
#define REQ_FILTER_COUNT        28
#define REQ_FILTERS             32
#define REQ_SHELLCODE_SIZE      128
#define REQ_TRAMPOLINE          136
#define REQ_GPA                 144
#define REQ_HOOKID              152
#define REQ_PROCNAME            160
#define REQ_CAPCOUNT            176
#define REQ_SPOOFCOUNT          180
#define REQ_CAPTURES            184
#define REQ_SPOOFS              216
#define REQ_BLOCK               280
#define REQ_BLOCKVALUE          288
#define REQ_TARGET_PID          132
#define REQ_SHELLCODE           296

/*
 * The hook half of the request block.  The memory fields sit above it and are
 * not read by any hook command, so a hook submit still only has to push these
 * 1320 bytes across the channel a qword at a time.
 */
#define REQ_SIZE                1320

/* The memory half; see SVMHV_HOOK_REQUEST. */
#define REQ_MEM_ADDRESS         1320
#define REQ_MEM_LENGTH          1328
#define REQ_MEM_PID             1332
#define REQ_MEM_RETURNED        1336
#define REQ_MEM_DATA            1344
#define REQ_MEM_MAX             4096

typedef struct _HV_REGS
{
    unsigned __int64 Rax, Rbx, Rcx, Rdx, Rsi, Rdi, R8, R9;
} HV_REGS;

extern void AsmHypercall(HV_REGS* Regs);

/* --------------------------------------------------------------- channel */

static unsigned __int64 Call(unsigned __int64 command, unsigned __int64 a,
                             unsigned __int64 b, HV_REGS* out)
{
    HV_REGS regs;

    memset(&regs, 0, sizeof(regs));
    regs.Rax = SVMHV_HYPERCALL_MAGIC;
    regs.Rbx = command;
    regs.Rdx = a;
    regs.Rsi = b;

    /*
     * With no hypervisor of ours loaded, VMMCALL is #UD - which is the whole
     * point of the instruction being a safe channel, but it means the very
     * first call is how we discover the driver is absent.  Catching it here
     * covers every command rather than just the presence probe.
     */
    __try
    {
        AsmHypercall(&regs);
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        memset(&regs, 0, sizeof(regs));
        regs.Rax = HV_ABSENT;
    }

    if (out != NULL)
    {
        *out = regs;
    }
    return regs.Rax;
}

static int Present(void)
{
    HV_REGS regs;

    if (Call(HV_PING, 0, 0, &regs) != HV_OK)
    {
        return 0;
    }
    return regs.Rbx == SVMHV_CONTROL_MAGIC;
}

/* Read Length bytes from one of the driver's structures, 48 at a time. */
static int ReadBlock(unsigned __int64 command, unsigned __int64 index,
                     unsigned __int64 offset, unsigned char* out,
                     unsigned int length)
{
    unsigned int done = 0;

    while (done < length)
    {
        HV_REGS regs;
        unsigned __int64 window[6];
        unsigned int chunk = length - done;
        unsigned __int64 status;

        if (command == HV_READ_TRACE)
        {
            status = Call(command, index, offset + done, &regs);
        }
        else
        {
            status = Call(command, offset + done, 0, &regs);
        }
        if (status != HV_OK)
        {
            fprintf(stderr, "hypercall %llu failed at offset %llu: status %llu\n",
                    command, offset + done, status);
            return 0;
        }

        window[0] = regs.Rbx; window[1] = regs.Rdx; window[2] = regs.Rsi;
        window[3] = regs.Rdi; window[4] = regs.R8;  window[5] = regs.R9;

        if (chunk > HV_READ_WINDOW)
        {
            chunk = HV_READ_WINDOW;
        }
        memcpy(out + done, window, chunk);
        done += chunk;
    }

    return 1;
}

/* Fill the request block a qword at a time, then ring the doorbell and wait. */
static int Submit(unsigned int command, const unsigned char* request,
                  unsigned int requestLength, unsigned char* result)
{
    HV_REGS regs;
    unsigned int offset;
    unsigned __int64 sequence;
    int attempt;

    for (offset = 0; offset < requestLength; offset += 8)
    {
        unsigned __int64 value;
        memcpy(&value, request + offset, sizeof(value));
        if (Call(HV_WRITE_REQUEST, offset, value, NULL) != HV_OK)
        {
            fprintf(stderr, "could not write the request at offset %u\n", offset);
            return 0;
        }
    }

    if (Call(HV_SUBMIT, command, 0, &regs) != HV_OK)
    {
        fprintf(stderr, "the hypervisor refused the command\n");
        return 0;
    }
    sequence = regs.Rbx;

    /* The worker polls every 100 ms. */
    for (attempt = 0; attempt < 60; attempt++)
    {
        Sleep(50);
        if (Call(HV_POLL, 0, 0, &regs) == HV_OK && regs.Rbx >= sequence)
        {
            printf("status=0x%08x\n", (unsigned int)regs.Rdx);
            if (result != NULL)
            {
                ReadBlock(HV_READ_REQUEST, 0, 0, result, REQ_SIZE);
            }
            return (unsigned int)regs.Rdx == 0;
        }
    }

    fprintf(stderr, "the control worker never acknowledged the command\n");
    return 0;
}

/*
 * Memory commands, which use the same doorbell but touch only the six fields
 * above REQ_SIZE.  Writing the whole request block for a 16-byte read would be
 * 680 hypercalls to carry 16 bytes; the driver ignores the hook fields for
 * these commands, so leaving them alone is both correct and 200 times cheaper.
 */
static int SubmitMemory(unsigned int command, unsigned __int64 address,
                        unsigned int length, unsigned int pid,
                        const unsigned char* input, unsigned char* out,
                        unsigned int* returned)
{
    HV_REGS regs;
    unsigned __int64 sequence;
    unsigned __int64 packed;
    unsigned int offset;
    int attempt;

    if (length == 0 || length > REQ_MEM_MAX)
    {
        length = REQ_MEM_MAX;
    }

    if (Call(HV_WRITE_REQUEST, REQ_MEM_ADDRESS, address, NULL) != HV_OK)
    {
        fprintf(stderr, "could not write the memory address\n");
        return 0;
    }

    /* MemoryLength and MemoryProcessId share one qword. */
    packed = (unsigned __int64)length | ((unsigned __int64)pid << 32);
    if (Call(HV_WRITE_REQUEST, REQ_MEM_LENGTH, packed, NULL) != HV_OK)
    {
        fprintf(stderr, "could not write the memory length\n");
        return 0;
    }

    for (offset = 0; input != NULL && offset < length; offset += 8)
    {
        unsigned __int64 value = 0;
        unsigned int chunk = length - offset;

        memcpy(&value, input + offset, (chunk > 8) ? 8 : chunk);
        if (Call(HV_WRITE_REQUEST, REQ_MEM_DATA + offset, value, NULL) != HV_OK)
        {
            fprintf(stderr, "could not write the payload at %u\n", offset);
            return 0;
        }
    }

    if (Call(HV_SUBMIT, command, 0, &regs) != HV_OK)
    {
        fprintf(stderr, "the hypervisor refused the command\n");
        return 0;
    }
    sequence = regs.Rbx;

    for (attempt = 0; attempt < 60; attempt++)
    {
        Sleep(50);
        if (Call(HV_POLL, 0, 0, &regs) != HV_OK || regs.Rbx < sequence)
        {
            continue;
        }

        printf("status=0x%08x\n", (unsigned int)regs.Rdx);

        /* Read the count first: it says how much of the buffer is meaningful,
           and a short transfer is a normal outcome rather than an error. */
        {
            unsigned char header[8];

            if (!ReadBlock(HV_READ_REQUEST, 0, REQ_MEM_RETURNED, header,
                           sizeof(header)))
            {
                return 0;
            }
            memcpy(returned, header, 4);
        }

        if (*returned > length)
        {
            *returned = length;
        }
        if (out != NULL && *returned != 0 &&
            !ReadBlock(HV_READ_REQUEST, 0, REQ_MEM_DATA, out, *returned))
        {
            return 0;
        }
        return 1;
    }

    fprintf(stderr, "the control worker never acknowledged the command\n");
    return 0;
}

/* ---------------------------------------------------------------- modules */

/*
 * The loaded kernel module list, with bases, from user mode.
 *
 * This deliberately does not go through the driver.  NtQuerySystemInformation
 * already answers it for anyone running elevated, and a client that can be
 * given the answer without adding a kernel code path should be.  The bases are
 * what make everything else addressable: with one, the PE headers can be read
 * with "svmhvctl read" and every export walked out of them, which is how a
 * caller turns a name into an address without a symbol server.
 */
#define SYSTEM_MODULE_INFORMATION   11

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID  MappedBase;
    PVOID  ImageBase;
    ULONG  ImageSize;
    ULONG  Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef LONG (__stdcall *PFN_NT_QUERY_SYSTEM_INFORMATION)(
    ULONG SystemInformationClass, PVOID SystemInformation,
    ULONG SystemInformationLength, PULONG ReturnLength);

static int PrintModules(void)
{
    PFN_NT_QUERY_SYSTEM_INFORMATION query;
    RTL_PROCESS_MODULES* modules;
    HMODULE ntdll;
    ULONG needed = 0;
    ULONG i;
    LONG status;

    ntdll = GetModuleHandleA("ntdll.dll");
    query = (ntdll != NULL)
          ? (PFN_NT_QUERY_SYSTEM_INFORMATION)(void*)
                GetProcAddress(ntdll, "NtQuerySystemInformation")
          : NULL;
    if (query == NULL)
    {
        fprintf(stderr, "NtQuerySystemInformation is not available\n");
        return 0;
    }

    /* Ask for the size, then allow for the list growing between the two calls. */
    query(SYSTEM_MODULE_INFORMATION, NULL, 0, &needed);
    if (needed == 0)
    {
        fprintf(stderr, "the module list reported no size\n");
        return 0;
    }
    needed += 16 * sizeof(RTL_PROCESS_MODULE_INFORMATION);

    modules = (RTL_PROCESS_MODULES*)malloc(needed);
    if (modules == NULL)
    {
        fprintf(stderr, "out of memory for the module list\n");
        return 0;
    }

    status = query(SYSTEM_MODULE_INFORMATION, modules, needed, &needed);
    if (status < 0)
    {
        fprintf(stderr, "NtQuerySystemInformation failed: 0x%08lx\n",
                (unsigned long)status);
        free(modules);
        return 0;
    }

    printf("modules=%lu\n", (unsigned long)modules->NumberOfModules);
    for (i = 0; i < modules->NumberOfModules; i++)
    {
        const RTL_PROCESS_MODULE_INFORMATION* m = &modules->Modules[i];
        const char* name = (const char*)m->FullPathName + m->OffsetToFileName;

        printf("module base=0x%llx size=0x%lx name=%s path=%s\n",
               (unsigned long long)(ULONG_PTR)m->ImageBase,
               (unsigned long)m->ImageSize, name, (const char*)m->FullPathName);
    }

    free(modules);
    return 1;
}

/* A hex dump with the ASCII column, which is what makes a dump readable. */
static void PrintDump(unsigned __int64 base, const unsigned char* data,
                      unsigned int length)
{
    unsigned int i;

    printf("bytes=%u\n", length);
    for (i = 0; i < length; i += 16)
    {
        unsigned int j;
        unsigned int run = (length - i > 16) ? 16 : length - i;

        printf("%016llx  ", base + i);
        for (j = 0; j < 16; j++)
        {
            if (j < run) { printf("%02x ", data[i + j]); }
            else         { printf("   "); }
        }
        printf(" ");
        for (j = 0; j < run; j++)
        {
            unsigned char c = data[i + j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("\n");
    }
}

static void BuildRequest(unsigned char* request, unsigned __int64 target,
                         unsigned int kind, unsigned int action,
                         unsigned int prolog, unsigned __int64 detour,
                         const unsigned char* shellcode, unsigned int shellcodeSize)
{
    memset(request, 0, REQ_SIZE);
    memcpy(request + REQ_TARGET, &target, 8);
    memcpy(request + REQ_DETOUR, &detour, 8);
    memcpy(request + REQ_PROLOG, &prolog, 4);
    memcpy(request + REQ_ACTION, &action, 4);
    memcpy(request + REQ_KIND, &kind, 4);
    memcpy(request + REQ_SHELLCODE_SIZE, &shellcodeSize, 4);
    if (shellcode != NULL && shellcodeSize != 0)
    {
        memcpy(request + REQ_SHELLCODE, shellcode, shellcodeSize);
    }
}

static void ReportHook(const unsigned char* request)
{
    unsigned __int64 trampoline;
    unsigned __int64 gpa;
    unsigned int hookId;

    memcpy(&trampoline, request + REQ_TRAMPOLINE, 8);
    memcpy(&gpa, request + REQ_GPA, 8);
    memcpy(&hookId, request + REQ_HOOKID, 4);

    printf("hookid=%u\ngpa=0x%llx\ntrampoline=0x%llx\n", hookId, gpa, trampoline);
}


/* ----------------------------------------------------------- hook options */

/*
 * Everything past the positional arguments is optional and named, because the
 * combinations are what make a hook useful: which process, which caller, what to
 * dereference, what to replace.  Parsed into the request block the driver reads.
 *
 *   --process NAME          only when this image is the current process
 *   --pid N                 only this process id
 *   --caller BASE SIZE      only when the return address is inside that range,
 *                           which is how you say "only when this driver calls it"
 *   --filter S:OP:VAL[:MASK]  S is 0-7, or pid/tid/ret/irql
 *   --capture ARG:TYPE[:LEN]  ansi|wide|unicode|objattr|bytes
 *   --spoof ARG:VALUE       replace an argument on the way through
 *   --block VALUE           do not call the original; return VALUE
 */
static unsigned int SubjectFromName(const char* text)
{
    if (_stricmp(text, "pid") == 0)  { return SVMHV_SUBJECT_PID; }
    if (_stricmp(text, "tid") == 0)  { return SVMHV_SUBJECT_TID; }
    if (_stricmp(text, "ret") == 0)  { return SVMHV_SUBJECT_RETURN; }
    if (_stricmp(text, "irql") == 0) { return SVMHV_SUBJECT_IRQL; }
    return (unsigned int)strtoul(text, NULL, 0);
}

static unsigned int ComparisonFromName(const char* text)
{
    if (_stricmp(text, "ne") == 0)    { return SVMHV_CMP_NOT_EQUAL; }
    if (_stricmp(text, "above") == 0) { return SVMHV_CMP_ABOVE; }
    if (_stricmp(text, "below") == 0) { return SVMHV_CMP_BELOW; }
    if (_stricmp(text, "bits") == 0)  { return SVMHV_CMP_BITS_SET; }
    if (_stricmp(text, "range") == 0) { return SVMHV_CMP_IN_RANGE; }
    return SVMHV_CMP_EQUAL;
}

static unsigned int CaptureFromName(const char* text)
{
    if (_stricmp(text, "ansi") == 0)    { return SVMHV_CAPTURE_ANSI; }
    if (_stricmp(text, "wide") == 0)    { return SVMHV_CAPTURE_WIDE; }
    if (_stricmp(text, "unicode") == 0) { return SVMHV_CAPTURE_UNICODE; }
    if (_stricmp(text, "objattr") == 0) { return SVMHV_CAPTURE_OBJATTR; }
    if (_stricmp(text, "bytes") == 0)   { return SVMHV_CAPTURE_BYTES; }
    return SVMHV_CAPTURE_NONE;
}

/* Split "a:b:c" in place; returns how many fields were found. */
static int SplitFields(char* text, char* fields[], int maximum)
{
    int count = 0;

    fields[count++] = text;
    while (*text != '\0' && count < maximum)
    {
        if (*text == ':')
        {
            *text = '\0';
            fields[count++] = text + 1;
        }
        text++;
    }
    return count;
}

static void AddFilter(unsigned char* request, unsigned int subject,
                      unsigned int comparison, unsigned __int64 value,
                      unsigned __int64 mask)
{
    unsigned int count;

    memcpy(&count, request + REQ_FILTER_COUNT, 4);
    if (count >= SVMHV_MAX_FILTERS)
    {
        fprintf(stderr, "too many filters; the limit is %u\n", SVMHV_MAX_FILTERS);
        return;
    }

    {
        unsigned char* slot = request + REQ_FILTERS + count * 24;
        memcpy(slot + 0, &subject, 4);
        memcpy(slot + 4, &comparison, 4);
        memcpy(slot + 8, &mask, 8);
        memcpy(slot + 16, &value, 8);
    }
    count++;
    memcpy(request + REQ_FILTER_COUNT, &count, 4);
}

static int ApplyOptions(unsigned char* request, int argc, char** argv, int index)
{
    for (; index < argc; index++)
    {
        const char* option = argv[index];

        if (_stricmp(option, "--process") == 0 && index + 1 < argc)
        {
            char* name = argv[++index];
            memset(request + REQ_PROCNAME, 0, SVMHV_PROCESS_NAME_MAX);
            strncpy_s((char*)(request + REQ_PROCNAME), SVMHV_PROCESS_NAME_MAX,
                      name, SVMHV_PROCESS_NAME_MAX - 1);
        }
        else if (_stricmp(option, "--in-process") == 0 && index + 1 < argc)
        {
            /* Which address space Target lives in.  Required for a user-mode
               target and meaningless for a kernel one; --pid is a different
               thing entirely, and filters *recording* rather than resolving
               the address. */
            const unsigned int pid = (unsigned int)strtoul(argv[++index], NULL, 0);
            memcpy(request + REQ_TARGET_PID, &pid, 4);
        }
        else if (_stricmp(option, "--pid") == 0 && index + 1 < argc)
        {
            AddFilter(request, SVMHV_SUBJECT_PID, SVMHV_CMP_EQUAL,
                      strtoull(argv[++index], NULL, 0), 0);
        }
        else if (_stricmp(option, "--caller") == 0 && index + 2 < argc)
        {
            const unsigned __int64 base = strtoull(argv[++index], NULL, 16);
            const unsigned __int64 size = strtoull(argv[++index], NULL, 0);
            AddFilter(request, SVMHV_SUBJECT_RETURN, SVMHV_CMP_IN_RANGE,
                      base, base + size);
        }
        else if (_stricmp(option, "--filter") == 0 && index + 1 < argc)
        {
            char* fields[4];
            const int count = SplitFields(argv[++index], fields, 4);

            if (count < 3)
            {
                fprintf(stderr, "--filter wants SUBJECT:OP:VALUE[:MASK]\n");
                return 0;
            }
            AddFilter(request, SubjectFromName(fields[0]),
                      ComparisonFromName(fields[1]),
                      strtoull(fields[2], NULL, 0),
                      (count > 3) ? strtoull(fields[3], NULL, 0) : 0);
        }
        else if (_stricmp(option, "--capture") == 0 && index + 1 < argc)
        {
            char* fields[3];
            const int count = SplitFields(argv[++index], fields, 3);
            unsigned int captures;

            memcpy(&captures, request + REQ_CAPCOUNT, 4);
            if (count < 2 || captures >= SVMHV_MAX_CAPTURES)
            {
                fprintf(stderr, "--capture wants ARG:TYPE[:LEN], max %u\n",
                        SVMHV_MAX_CAPTURES);
                return 0;
            }
            {
                unsigned char* slot = request + REQ_CAPTURES + captures * 16;
                const unsigned int argument = (unsigned int)strtoul(fields[0], NULL, 0);
                const unsigned int type = CaptureFromName(fields[1]);
                const unsigned int length =
                    (count > 2) ? (unsigned int)strtoul(fields[2], NULL, 0) : 0;

                memcpy(slot + 0, &argument, 4);
                memcpy(slot + 4, &type, 4);
                memcpy(slot + 8, &length, 4);
            }
            captures++;
            memcpy(request + REQ_CAPCOUNT, &captures, 4);
        }
        else if (_stricmp(option, "--spoof") == 0 && index + 1 < argc)
        {
            char* fields[2];
            const int count = SplitFields(argv[++index], fields, 2);
            unsigned int spoofs;

            memcpy(&spoofs, request + REQ_SPOOFCOUNT, 4);
            if (count < 2 || spoofs >= SVMHV_MAX_SPOOFS)
            {
                fprintf(stderr, "--spoof wants ARG:VALUE, max %u\n",
                        SVMHV_MAX_SPOOFS);
                return 0;
            }
            {
                unsigned char* slot = request + REQ_SPOOFS + spoofs * 16;
                const unsigned int argument = (unsigned int)strtoul(fields[0], NULL, 0);
                const unsigned __int64 value = strtoull(fields[1], NULL, 0);

                memcpy(slot + 0, &argument, 4);
                memcpy(slot + 8, &value, 8);
            }
            spoofs++;
            memcpy(request + REQ_SPOOFCOUNT, &spoofs, 4);
        }
        else if (_stricmp(option, "--block") == 0 && index + 1 < argc)
        {
            const unsigned int block = 1;
            const unsigned __int64 value = strtoull(argv[++index], NULL, 0);

            memcpy(request + REQ_BLOCK, &block, 4);
            memcpy(request + REQ_BLOCKVALUE, &value, 8);
        }
        else
        {
            fprintf(stderr, "unrecognised option: %s\n", option);
            return 0;
        }
    }

    return 1;
}

/* ----------------------------------------------------------------- views */

static void PrintStats(void)
{
    unsigned char raw[SNAP_SIZE];
    SVMHV_STATS stats;
    unsigned int i;

    if (!ReadBlock(HV_READ_SNAPSHOT, 0, SNAP_STATS, (unsigned char*)&stats,
                   sizeof(stats)))
    {
        return;
    }
    (void)raw;

    printf("cpus=%u\noptions=0x%04x\nactive_hooks=%u\nsplit_pages=%u\n",
           stats.CpuCount, stats.Options, stats.ActiveHooks,
           stats.NptSplitPagesUsed);
    printf("npt_coverage=%llu\nexits=%llu\ncpuid_exits=%llu\nmsr_exits=%llu\n",
           stats.NptCoverageBytes, stats.Exits, stats.CpuidExits, stats.MsrExits);
    printf("npf_exits=%llu\nhook_switches=%llu\nhypercalls=%llu\n",
           stats.NpfExits, stats.HookSwitches, stats.Hypercalls);
    printf("overhead_cycles=%llu\nhidden_cycles=%llu\n",
           stats.OverheadCycles, stats.HiddenCycles);
    printf("native_cpuid=%llu\nhidden_per_exit=%llu\n",
           stats.NativeCpuidCycles, stats.HiddenPerExit);
    printf("trace_records=%llu\ntrace_dropped=%llu\ntrace_filtered=%llu\n",
           stats.TraceRecords, stats.TraceDropped, stats.TraceFiltered);
    for (i = 0; i < stats.CpuCount && i < SVMHV_MAX_REPORTED_CPUS; i++)
    {
        printf("cpu%u_exits=%llu\n", i, stats.PerCpuExits[i]);
    }
}

static void PrintHooks(void)
{
    SVMHV_HOOK_LIST list;
    unsigned int i;

    if (!ReadBlock(HV_READ_SNAPSHOT, 0, SNAP_HOOKS, (unsigned char*)&list,
                   sizeof(list)))
    {
        return;
    }

    printf("hooks=%u\n", list.Count);
    for (i = 0; i < list.Count && i < SVMHV_MAX_HOOK_RECORDS; i++)
    {
        const SVMHV_HOOK_INFO* hook = &list.Hooks[i];
        printf("hook id=%u active=%u kind=%u action=%u target=0x%llx gpa=0x%llx "
               "detour=0x%llx trampoline=0x%llx prolog=%u hits=%llu filters=%u\n",
               hook->HookId, hook->Active, hook->Kind, hook->Action,
               hook->Target, hook->Gpa, hook->Detour, hook->Trampoline,
               hook->PrologLength, hook->Hits, hook->FilterCount);
    }
}

static void PrintHistogram(void)
{
    SVMHV_EXIT_HISTOGRAM histogram;
    unsigned int i;

    if (!ReadBlock(HV_READ_SNAPSHOT, 0, SNAP_HISTOGRAM,
                   (unsigned char*)&histogram, sizeof(histogram)))
    {
        return;
    }

    printf("cpus=%u\n", histogram.CpuCount);
    for (i = 0; i < SVMHV_EXIT_CODE_SLOTS; i++)
    {
        if (histogram.Counts[i] != 0)
        {
            printf("exit code=0x%03x count=%llu\n", i, histogram.Counts[i]);
        }
    }
    printf("exit code=0x400 count=%llu\n", histogram.NestedPageFaults);
    printf("invalid=%llu\n", histogram.Invalid);
}

static void PrintSelfTest(void)
{
    SVMHV_SELFTEST test;
    unsigned int i;

    if (!ReadBlock(HV_READ_SNAPSHOT, 0, SNAP_SELFTEST, (unsigned char*)&test,
                   sizeof(test)))
    {
        return;
    }

    printf("passed=0x%04x\nvictim_plain=0x%08x\nvictim_hooked=0x%08x\n"
           "victim_unhooked=0x%08x\ndetour_hits=%u\ntrampoline_result=0x%08x\n",
           test.Passed, test.VictimPlain, test.VictimHooked,
           test.VictimUnhooked, test.DetourHits, test.TrampolineResult);
    printf("cpus_hooked=%u\ncpus_missed=%u\ntraced_records=%u\n",
           test.CpusHooked, test.CpusMissed, test.TracedRecords);
    printf("efer=0x%llx\ncpuid_cycles=%llu\nbaseline_cycles=%llu\n",
           test.EferSeenByGuest, test.CpuidCycles, test.BaselineCycles);
    printf("arg_result=0x%llx\n", test.ArgVictimResult);
    for (i = 0; i < 4; i++)
    {
        printf("traced_arg%u=0x%llx\n", i, test.TracedArguments[i]);
    }
    printf("original_bytes=");
    for (i = 0; i < 16; i++) { printf("%02x", test.OriginalBytes[i]); }
    printf("\nhooked_bytes=");
    for (i = 0; i < 16; i++) { printf("%02x", test.BytesWhileHooked[i]); }
    printf("\n");
}

static void PrintTrace(unsigned int count)
{
    HV_REGS regs;
    unsigned __int64 produced;
    unsigned __int64 records;
    unsigned __int64 recordSize;
    unsigned __int64 first;
    unsigned __int64 index;

    if (Call(HV_TRACE_STATE, 0, 0, &regs) != HV_OK)
    {
        fprintf(stderr, "no trace ring\n");
        return;
    }
    produced = regs.Rbx;
    records = regs.Rdx;
    recordSize = regs.Rsi;

    printf("produced=%llu\nring_records=%llu\nrecord_size=%llu\n",
           produced, records, recordSize);
    if (produced == 0 || records == 0)
    {
        return;
    }
    if (count > produced) { count = (unsigned int)produced; }
    if (count > records)  { count = (unsigned int)records; }

    first = produced - count;
    for (index = first; index < produced; index++)
    {
        SVMHV_TRACE_RECORD record;

        if (!ReadBlock(HV_READ_TRACE, index % records, 0,
                       (unsigned char*)&record, sizeof(record)))
        {
            return;
        }
        printf("trace seq=%llu type=%u hook=%u cpu=%u pid=%u tid=%u irql=%u "
               "spoofed=%u proc=%.15s "
               "tsc=%llu rip=0x%llx rsp=0x%llx ret=0x%llx gpa=0x%llx err=0x%llx "
               "a0=0x%llx a1=0x%llx a2=0x%llx a3=0x%llx s0=0x%llx s1=0x%llx",
               record.Sequence, record.Type, record.HookId, record.Processor,
               record.ProcessId, record.ThreadId, record.Irql,
               record.Spoofed,
               (record.ProcessName[0] != 0) ? record.ProcessName : "-",
               record.Tsc,
               record.Rip, record.Rsp, record.ReturnAddress, record.Gpa,
               record.ErrorCode, record.Arguments[0], record.Arguments[1],
               record.Arguments[2], record.Arguments[3],
               record.StackArguments[0], record.StackArguments[1]);

        /* Captures go out as hex so the client can decide what they were. */
        {
            unsigned int c;
            for (c = 0; c < SVMHV_MAX_CAPTURES; c++)
            {
                unsigned int b;
                if (record.CaptureLength[c] == 0) { continue; }
                printf(" cap%u=", c);
                for (b = 0; b < record.CaptureLength[c] &&
                            b < SVMHV_CAPTURE_MAX; b++)
                {
                    printf("%02x", record.CaptureData[c][b]);
                }
            }
        }
        printf("\n");
    }

    /*
     * Tell the driver how far we got.  Nothing else moves its consumer index,
     * and until something does it has to assume every record it overwrites was
     * lost - which makes the dropped count in "status" meaningless.
     */
    (void)Call(HV_TRACE_CONSUMED, produced, 0, NULL);
}

/* ------------------------------------------------------------------ main */

static int ParseHex(const char* text, unsigned char* out, unsigned int maximum)
{
    unsigned int count = 0;

    while (*text != '\0' && count < maximum)
    {
        char pair[3];
        while (*text == ' ' || *text == ',') { text++; }
        if (*text == '\0') { break; }
        if (text[1] == '\0') { return -1; }
        pair[0] = text[0];
        pair[1] = text[1];
        pair[2] = '\0';
        out[count++] = (unsigned char)strtoul(pair, NULL, 16);
        text += 2;
    }

    return (int)count;
}

static void Usage(void)
{
    printf(
        "svmhvctl - talks to svmhv through its CPUID control channel\n\n"
        "  svmhvctl present\n"
        "  svmhvctl status | hooks | histogram | selftest-result\n"
        "  svmhvctl trace [count]\n"
        "  svmhvctl selftest\n"
        "  svmhvctl trace-reset\n"
        "  svmhvctl hook-trace  <target> <prolog>\n"
        "  svmhvctl hook-detour <target> <prolog> <detour>\n"
        "  svmhvctl hook-shellcode <target> <prolog> <hexbytes>\n"
        "  svmhvctl modules\n"
        "  svmhvctl driverobj <name>\n"
        "  svmhvctl read  <address> [length] [pid]\n"
        "  svmhvctl readphys <gpa> [length]\n"
        "  svmhvctl write <address> <hexbytes> [pid]\n"
        "  svmhvctl watch <target> write|access\n"
        "  svmhvctl unhook <target>\n\n"
        "Hook options, after the positional arguments:\n"
        "  --process NAME        only when NAME is the current process\n"
        "  --pid N               only this process id\n"
        "  --in-process N        Target is a user address in this process;\n"
        "                        required for one, ignored for a kernel address\n"
        "  --caller BASE SIZE    only when the caller is inside that range,\n"
        "                        i.e. only when that driver calls it\n"
        "  --filter S:OP:V[:M]   S = 0-7 | pid | tid | ret | irql,\n"
        "                        OP = eq|ne|above|below|bits|range\n"
        "  --capture ARG:TYPE    TYPE = ansi|wide|unicode|objattr|bytes[:LEN]\n"
        "  --spoof ARG:VALUE     replace an argument on the way through\n"
        "  --block VALUE         do not call the original; return VALUE\n\n"
        "Addresses are hex, with or without 0x. <prolog> is how many bytes at\n"
        "the target may be overwritten, rounded UP to an instruction boundary,\n"
        "minimum 14 - get it wrong and you corrupt the function.\n");
}

int main(int argc, char** argv)
{
    unsigned char request[REQ_SIZE];
    unsigned char result[REQ_SIZE];

    if (argc < 2)
    {
        Usage();
        return 1;
    }

    if (!Present())
    {
        printf("present=0\n");
        fprintf(stderr, "svmhv is not loaded, or was built with "
                        "STEALTHV_CONTROL_INTERFACE 0\n");
        return 1;
    }

    if (_stricmp(argv[1], "present") == 0)
    {
        printf("present=1\n");
        return 0;
    }
    if (_stricmp(argv[1], "status") == 0)          { PrintStats();     return 0; }
    if (_stricmp(argv[1], "hooks") == 0)           { PrintHooks();     return 0; }
    if (_stricmp(argv[1], "histogram") == 0)       { PrintHistogram(); return 0; }
    if (_stricmp(argv[1], "selftest-result") == 0) { PrintSelfTest();  return 0; }

    if (_stricmp(argv[1], "trace") == 0)
    {
        PrintTrace((argc > 2) ? (unsigned int)strtoul(argv[2], NULL, 0) : 40);
        return 0;
    }

    if (_stricmp(argv[1], "selftest") == 0)
    {
        if (!Submit(SVMHV_CMD_SELFTEST, request, 0, NULL)) { return 2; }
        PrintSelfTest();
        return 0;
    }

    if (_stricmp(argv[1], "trace-reset") == 0)
    {
        return Submit(SVMHV_CMD_TRACE_RESET, request, 0, NULL) ? 0 : 2;
    }

    if (_stricmp(argv[1], "unhook") == 0 && argc >= 3)
    {
        BuildRequest(request, strtoull(argv[2], NULL, 16), SVMHV_HOOK_EXEC,
                     SVMHV_ACTION_TRACE, 14, 0, NULL, 0);
        return Submit(SVMHV_CMD_HOOK_REMOVE, request, REQ_SIZE, NULL) ? 0 : 2;
    }

    if (_stricmp(argv[1], "hook-trace") == 0 && argc >= 4)
    {
        BuildRequest(request, strtoull(argv[2], NULL, 16), SVMHV_HOOK_EXEC,
                     SVMHV_ACTION_TRACE,
                     (unsigned int)strtoul(argv[3], NULL, 0), 0, NULL, 0);
        if (!ApplyOptions(request, argc, argv, 4)) { return 1; }
        if (!Submit(SVMHV_CMD_HOOK_INSTALL, request, REQ_SIZE, result)) { return 2; }
        ReportHook(result);
        return 0;
    }

    if (_stricmp(argv[1], "hook-detour") == 0 && argc >= 5)
    {
        BuildRequest(request, strtoull(argv[2], NULL, 16), SVMHV_HOOK_EXEC,
                     SVMHV_ACTION_DETOUR,
                     (unsigned int)strtoul(argv[3], NULL, 0),
                     strtoull(argv[4], NULL, 16), NULL, 0);
        if (!ApplyOptions(request, argc, argv, 5)) { return 1; }
        if (!Submit(SVMHV_CMD_HOOK_INSTALL, request, REQ_SIZE, result)) { return 2; }
        ReportHook(result);
        return 0;
    }

    if (_stricmp(argv[1], "hook-shellcode") == 0 && argc >= 5)
    {
        unsigned char shellcode[SVMHV_MAX_SHELLCODE];
        const int size = ParseHex(argv[4], shellcode, sizeof(shellcode));

        if (size <= 0)
        {
            fprintf(stderr, "could not parse the shellcode bytes\n");
            return 1;
        }
        BuildRequest(request, strtoull(argv[2], NULL, 16), SVMHV_HOOK_EXEC,
                     SVMHV_ACTION_SHELLCODE,
                     (unsigned int)strtoul(argv[3], NULL, 0), 0,
                     shellcode, (unsigned int)size);
        if (!ApplyOptions(request, argc, argv, 5)) { return 1; }
        if (!Submit(SVMHV_CMD_HOOK_INSTALL, request, REQ_SIZE, result)) { return 2; }
        ReportHook(result);
        return 0;
    }

    if (_stricmp(argv[1], "modules") == 0)
    {
        return PrintModules() ? 0 : 2;
    }

    if (_stricmp(argv[1], "driverobj") == 0 && argc >= 3)
    {
        unsigned char data[REQ_MEM_MAX] = { 0 };
        unsigned int returned = 0;
        const size_t length = strlen(argv[2]);

        if (length == 0 || length >= 64)
        {
            fprintf(stderr, "driver name must be 1-63 characters\n");
            return 1;
        }
        memcpy(data, argv[2], length);

        /*
         * 64, not the name length.  SubmitMemory uses one length for both
         * directions, and what comes back here is an eight-byte pointer rather
         * than an echo of what went in - passing the name's length would clamp
         * the answer away.
         */
        if (!SubmitMemory(SVMHV_CMD_DRIVER_OBJECT, 0, 64,
                          0, data, data, &returned))
        {
            return 2;
        }
        if (returned < 8)
        {
            fprintf(stderr, "no driver object came back\n");
            return 2;
        }
        {
            unsigned __int64 address;
            memcpy(&address, data, 8);
            printf("driver_object=0x%llx\n", address);
        }
        return 0;
    }

    if ((_stricmp(argv[1], "read") == 0 ||
         _stricmp(argv[1], "readphys") == 0) && argc >= 3)
    {
        unsigned char data[REQ_MEM_MAX];
        unsigned int returned = 0;
        const unsigned __int64 address = strtoull(argv[2], NULL, 16);
        const unsigned int length = (argc >= 4)
                                  ? (unsigned int)strtoul(argv[3], NULL, 0) : 64;
        const unsigned int pid = (argc >= 5)
                               ? (unsigned int)strtoul(argv[4], NULL, 0) : 0;
        const unsigned int command = (_stricmp(argv[1], "readphys") == 0)
                                   ? SVMHV_CMD_READ_PHYSICAL
                                   : SVMHV_CMD_READ_MEMORY;

        if (!SubmitMemory(command, address, length, pid, NULL, data, &returned))
        {
            return 2;
        }
        PrintDump(address, data, returned);
        return 0;
    }

    if (_stricmp(argv[1], "write") == 0 && argc >= 4)
    {
        unsigned char data[REQ_MEM_MAX];
        unsigned int returned = 0;
        const unsigned __int64 address = strtoull(argv[2], NULL, 16);
        const int size = ParseHex(argv[3], data, sizeof(data));
        const unsigned int pid = (argc >= 5)
                               ? (unsigned int)strtoul(argv[4], NULL, 0) : 0;

        if (size <= 0)
        {
            fprintf(stderr, "could not parse the bytes to write\n");
            return 1;
        }
        if (!SubmitMemory(SVMHV_CMD_WRITE_MEMORY, address, (unsigned int)size,
                          pid, data, NULL, &returned))
        {
            return 2;
        }
        printf("written=%u\n", returned);
        return 0;
    }

    if (_stricmp(argv[1], "watch") == 0 && argc >= 4)
    {
        unsigned int kind;

        if (_stricmp(argv[3], "write") == 0)       { kind = SVMHV_HOOK_WRITE; }
        else if (_stricmp(argv[3], "access") == 0) { kind = SVMHV_HOOK_ACCESS; }
        else { fprintf(stderr, "mode must be write or access\n"); return 1; }

        BuildRequest(request, strtoull(argv[2], NULL, 16), kind,
                     SVMHV_ACTION_TRACE, 0, 0, NULL, 0);
        if (!ApplyOptions(request, argc, argv, 4)) { return 1; }
        if (!Submit(SVMHV_CMD_HOOK_INSTALL, request, REQ_SIZE, result)) { return 2; }
        ReportHook(result);
        return 0;
    }

    Usage();
    return 1;
}
