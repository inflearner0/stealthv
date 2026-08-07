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

#define SVMHV_CPUID_CONTROL     0x4FFFFFFD
#define SVMHV_CONTROL_KEY       0x3C9F17B2

#define HV_PING                 0
#define HV_WRITE_REQUEST        1
#define HV_SUBMIT               2
#define HV_POLL                 3
#define HV_READ_SNAPSHOT        4
#define HV_READ_REQUEST         5
#define HV_READ_TRACE           6
#define HV_TRACE_STATE          7

#define HV_OK                   0
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
#define REQ_SHELLCODE           296
#define REQ_SIZE                1320

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
    regs.Rax = SVMHV_CPUID_CONTROL;
    regs.Rcx = SVMHV_CONTROL_KEY;
    regs.Rbx = command;
    regs.Rdx = a;
    regs.Rsi = b;

    AsmHypercall(&regs);

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
        "  svmhvctl watch <target> write|access\n"
        "  svmhvctl unhook <target>\n\n"
        "Hook options, after the positional arguments:\n"
        "  --process NAME        only when NAME is the current process\n"
        "  --pid N               only this process id\n"
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
        fprintf(stderr, "svmhv is not loaded, or its ControlInterface is off\n");
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
