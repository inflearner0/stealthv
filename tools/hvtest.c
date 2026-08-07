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

#define CPUID_SIGNATURE_LEAF    0x4FFFFFFF
#define SIGNATURE_KEY           0x7A1D4C5F

static int g_Failures;

static void Check(int ok, const char* what)
{
    printf("  [%s] %s\n", ok ? "pass" : "FAIL", what);
    if (!ok)
    {
        g_Failures++;
    }
}

static void ReadSignature(unsigned int subLeaf, char out[13], unsigned int* eax)
{
    int regs[4];

    __cpuidex(regs, CPUID_SIGNATURE_LEAF, (int)subLeaf);
    memcpy(out + 0, &regs[1], 4);
    memcpy(out + 4, &regs[2], 4);
    memcpy(out + 8, &regs[3], 4);
    out[12] = 0;
    *eax = (unsigned int)regs[0];
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
    unsigned int exits;
    unsigned int decoyEax;
    unsigned int before;
    unsigned int after;
    unsigned __int64 cpuidCycles;
    unsigned __int64 baselineCycles;
    int svmBit;
    int svmLeaf;
    int i;

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

    printf("\n=== private leaves ===\n");
    ReadSignature(SIGNATURE_KEY, signature, &exits);
    ReadSignature(SIGNATURE_KEY ^ 1, decoy, &decoyEax);
    printf("  leaf %08X + key      : \"%s\"\n", CPUID_SIGNATURE_LEAF, signature);
    printf("  leaf %08X, wrong key : \"%s\" (eax %08X)\n",
           CPUID_SIGNATURE_LEAF, decoy, decoyEax);

    if (strcmp(signature, "SVMHV-SIMPLE") != 0)
    {
        printf("\nsvmhv                   : NOT PRESENT\n");
        return 1;
    }
    printf("\nsvmhv                   : PRESENT\n");
    Check(strcmp(decoy, "SVMHV-SIMPLE") != 0,
          "the signature leaf is silent without the key");
    Check(svmBit == 0, "SVM feature bit is hidden");
    Check(svmLeaf == 0, "SVM feature leaf reads as reserved");
    printf("  vm exits on this cpu  : %u\n", exits);

    /* The counter is per-CPU; the thread was pinned to cpu 0 above. */
    ReadSignature(SIGNATURE_KEY, signature, &before);
    for (i = 0; i < 1000; i++)
    {
        __cpuid(regs, 0);
    }
    ReadSignature(SIGNATURE_KEY, signature, &after);

    /* 1000 loop iterations + the trailing signature read = 1001. */
    printf("  after 1000 cpuids     : %u (+%u)\n", after, after - before);
    Check(after - before == 1001, "every cpuid produced exactly one exit");

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
