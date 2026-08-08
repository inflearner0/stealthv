/*
 * hvtest.c - user-mode probe for svmhv.sys.
 *
 * Two jobs.  First, prove the hypervisor is there at all, which only works
 * because we know the key it answers to.  Second, check the things a guest
 * *could* use to notice it: the SVM feature bits, the private CPUID leaves
 * without the key, and how long an intercepted instruction appears to take.
 *
 * Nothing here opens a handle, because there is nothing to open - the driver has
 * no device object and no IOCTL.  Everything that needs to *ask the driver* for
 * something goes through svmhv!g_Control instead, which is only reachable from
 * kernel mode; see mcp\svmhv_mcp.py.
 */

#include <windows.h>
#include <intrin.h>
#include <stdio.h>
#include <string.h>

/* The VMMCALL channel; see driver/svm.h. */
#define SVMHV_HYPERCALL_MAGIC   0x53564D485643414CULL
#define HV_READ_SNAPSHOT        4
#define HV_SIGNATURE            9

/*
 * Where SVMHV_STATS.CpuidExits lands in the snapshot: the stats block starts at
 * 16 and the counter is 32 bytes into it.  Asserted against the struct by the
 * C_ASSERTs in include/svmhvctl.h.
 */
#define SNAP_CPUID_EXITS        48

typedef struct _HV_REGS
{
    unsigned __int64 Rax, Rbx, Rcx, Rdx, Rsi, Rdi, R8, R9;
} HV_REGS;

extern void AsmHypercall(HV_REGS* Regs);

static int g_Failures;

static void Check(int ok, const char* what)
{
    printf("  [%s] %s\n", ok ? "pass" : "FAIL", what);
    if (!ok)
    {
        g_Failures++;
    }
}

/*
 * With nothing loaded, VMMCALL is #UD - which is exactly what a machine with no
 * hypervisor does, and is how a probe discovers there is nothing here.  Every
 * call goes through the guard, not just the decoy.
 */
static void Signature(unsigned __int64 magic, char out[13])
{
    HV_REGS regs;

    memset(&regs, 0, sizeof(regs));
    regs.Rax = magic;
    regs.Rbx = HV_SIGNATURE;

    __try
    {
        AsmHypercall(&regs);
        memcpy(out + 0, &regs.Rbx, 4);
        memcpy(out + 4, &regs.Rdx, 4);
        memcpy(out + 8, &regs.Rsi, 4);
        out[12] = 0;
    }
    __except (EXCEPTION_EXECUTE_HANDLER)
    {
        memcpy(out, "#UD", 4);
    }
}

static void ReadSignature(char out[13])
{
    Signature(SVMHV_HYPERCALL_MAGIC, out);
}

/* How many CPUID exits the hypervisor has taken, across every processor. */
static unsigned __int64 ReadCpuidExits(void)
{
    HV_REGS regs;

    memset(&regs, 0, sizeof(regs));
    regs.Rax = SVMHV_HYPERCALL_MAGIC;
    regs.Rbx = HV_READ_SNAPSHOT;
    regs.Rdx = SNAP_CPUID_EXITS;

    AsmHypercall(&regs);
    return regs.Rbx;
}

/* The same call with the magic one bit out: it must not answer. */
static void ReadDecoy(char out[13])
{
    Signature(SVMHV_HYPERCALL_MAGIC ^ 1, out);
}

/*
 * Minimum of many samples: what a detector uses, because it throws away the
 * iterations that got interrupted.  Kept deliberately short - every one of
 * these CPUIDs is an intercepted instruction whose cost gets subtracted from
 * this processor's TSC, so a long loop here drags this CPU's clock behind the
 * others for no extra confidence in the answer.
 */
#define TIMING_SAMPLES 2000

/*
 * RDTSC is not a barrier and nothing reads regs afterwards, so an optimiser is
 * entitled to hoist the CPUID out of the loop - and MSVC does, which turns this
 * into a measurement of two back-to-back RDTSCs and makes an intercepted CPUID
 * look faster than an LFENCE.  The volatile leaf keeps the instruction in the
 * loop; the volatile sink keeps it from being deleted.
 */
static volatile unsigned int g_TimingLeaf;   /* stays 0 */
static volatile int          g_TimingSink;

static unsigned __int64 TimeCpuid(int withCpuid)
{
    unsigned __int64 best = ~0ULL;
    int regs[4];
    int i;

    for (i = 0; i < TIMING_SAMPLES; i++)
    {
        unsigned __int64 start = __rdtsc();

        if (withCpuid)
        {
            __cpuid(regs, (int)g_TimingLeaf);
            g_TimingSink += regs[0];
        }
        else
        {
            _mm_lfence();
        }

        {
            unsigned __int64 delta = __rdtsc() - start;
            if (delta < best)
            {
                best = delta;
            }
        }
    }

    return best;
}

static void PrintBytes(const char* label, const unsigned char* bytes, int count)
{
    int i;

    printf("  %-22s", label);
    for (i = 0; i < count; i++)
    {
        printf("%02X ", bytes[i]);
    }
    printf("\n");
}

int main(void)
{
    int regs[4];
    char signature[13];
    char decoy[13];
    unsigned __int64 cpuidCycles;
    unsigned __int64 baselineCycles;
    unsigned __int64 cpuidExits;
    int svmBit;
    int svmLeaf;

    printf("=== processor ===\n");
    __cpuid(regs, 0);
    printf("  cpu vendor            : %.4s%.4s%.4s\n",
           (char*)&regs[1], (char*)&regs[3], (char*)&regs[2]);

    __cpuid(regs, 1);
    printf("  hypervisor present bit: %d\n", (regs[2] >> 31) & 1);

    __cpuid(regs, 0x40000000);
    printf("  hypervisor vendor     : %.4s%.4s%.4s\n",
           (char*)&regs[1], (char*)&regs[2], (char*)&regs[3]);

    /*
     * Printed now, judged later: with no hypervisor loaded these are supposed
     * to show SVM, so calling that a failure would only make the reference run
     * look broken.
     */
    printf("\n=== what the guest can see about SVM ===\n");
    __cpuid(regs, 0x80000001);
    svmBit = (regs[2] >> 2) & 1;
    printf("  8000_0001.ECX.SVM     : %d\n", svmBit);

    __cpuid(regs, 0x8000000A);
    svmLeaf = regs[0] | regs[1] | regs[2] | regs[3];
    printf("  8000_000A             : %08X %08X %08X %08X\n",
           regs[0], regs[1], regs[2], regs[3]);

    /*
     * Measured before the presence check, so that a run with no hypervisor
     * loaded prints the reference number to compare the next one against.
     */
    if (SetThreadAffinityMask(GetCurrentThread(), 1) == 0)
    {
        printf("\n  WARNING: could not pin to cpu 0; timings may be noisy\n");
    }
    printf("\n=== timing, as a detector would measure it ===\n");
    cpuidCycles    = TimeCpuid(1);
    baselineCycles = TimeCpuid(0);
    printf("  rdtsc-cpuid-rdtsc     : %llu cycles (minimum of %d)\n",
           cpuidCycles, TIMING_SAMPLES);
    printf("  rdtsc-lfence-rdtsc    : %llu cycles\n", baselineCycles);
    printf("  ratio                 : %.1fx\n",
           baselineCycles ? (double)cpuidCycles / (double)baselineCycles : 0.0);

    printf("\n=== the control channel ===\n");
    ReadSignature(signature);
    ReadDecoy(decoy);
    printf("  vmmcall + magic       : \"%s\"\n", signature);
    printf("  vmmcall, wrong magic  : \"%s\"\n", decoy);

    if (strcmp(signature, "SVMHV-SIMPLE") != 0)
    {
        printf("\nsvmhv                   : NOT PRESENT\n");
        return 1;
    }
    printf("\nsvmhv                   : PRESENT\n");
    Check(strcmp(decoy, "SVMHV-SIMPLE") != 0,
          "the channel is silent without the magic");

    /*
     * The point of the whole design, taken from the hypervisor's own counter
     * rather than from the clock.
     *
     * The ratio above cannot be the verdict, and it is worth being clear why:
     * under a parent hypervisor CPUID already exits to *it*, so ~2400 cycles
     * against a 66-cycle lfence - a ratio around 36x - is what this machine
     * looks like with no driver loaded at all.  Judging the ratio would fail a
     * correct build for something Hyper-V is doing.  Whether *this* hypervisor
     * adds an exit is not a matter of interpretation: it either took one or it
     * did not.
     */
    cpuidExits = ReadCpuidExits();
    printf("  cpuid exits taken     : %llu\n", cpuidExits);
    Check(cpuidExits == 0, "cpuid is not intercepted: no exit, nothing to time");

    /*
     * SVM stays visible, deliberately: the feature bits cannot be masked
     * without intercepting CPUID, which is the thing that gave the hypervisor
     * away on the clock. Reported, not judged.
     */
    printf("  8000_0001.ECX.SVM     : %d (visible by design)\n", svmBit);
    printf("  8000_000A             : %s\n",
           svmLeaf ? "populated (visible by design)" : "reserved");

    /*
     * That is as far as a user-mode probe can go, and deliberately so: the
     * driver has no device object and no IOCTL, so there is nothing here to open.
     * The hook engine, the trace ring and the counters are driven through
     * svmhv!g_Control by a kernel debugger - see mcp\svmhv_mcp.py - which is
     * also the only thing that can install a hook.
     */
    printf("\n(hook, trace and counter checks live in the MCP server: this driver\n"
           " has no user-mode interface for a probe to query)\n");

    printf("\n%s (%d failure(s))\n", g_Failures ? "RESULT: FAIL" : "RESULT: OK",
           g_Failures);
    return g_Failures ? 2 : 0;
}
