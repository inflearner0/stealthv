/*
 * ibs.c - AMD Instruction-Based Sampling, polled at exits.  See ibs.h, and in
 * particular the paragraph about why the CPUID gate is the entire safety story.
 */

#include "ibs.h"
#include "svmhv.h"
#include "trace.h"

/* CPUID.8000_0001:ECX[10] - IBS exists at all. */
#define CPUID_EXT_FEATURE_IBS       (1u << 10)

/* CPUID.8000_001B - which parts of it. */
#define CPUID_IBS_FEATURES          0x8000001B
#define CPUID_IBS_FFV               (1u << 0)   /* the leaf itself is valid  */
#define CPUID_IBS_OP_SAM            (1u << 2)   /* op sampling, which is ours */

#define MSR_IBS_OP_CTL              0xC0011033
#define MSR_IBS_OP_RIP              0xC0011034
#define MSR_IBS_OP_DATA             0xC0011035
#define MSR_IBS_OP_DATA3            0xC0011037
#define MSR_IBS_DC_LIN_AD           0xC0011038

/*
 * IBS_OP_CTL.  MaxCnt is the sampling period in micro-ops, held in units of 16
 * - the low four bits of the period are not representable, which is why the arm
 * path rounds rather than validates.
 */
#define IBS_OP_CTL_MAX_CNT_MASK     0xFFFFULL   /* period[19:4]              */
#define IBS_OP_CTL_EN               (1ULL << 17)
#define IBS_OP_CTL_VAL              (1ULL << 18)

/* IBS_OP_DATA3, the part worth recording. */
#define IBS_OP_DATA3_LD_OP          (1ULL << 0)
#define IBS_OP_DATA3_ST_OP          (1ULL << 1)
#define IBS_OP_DATA3_DC_LIN_VALID   (1ULL << 17)

/*
 * The period, in units of 16 micro-ops, that the hardware field can hold.
 * Anything larger silently truncates into the enable bits, so it is clamped.
 */
#define IBS_MAX_PERIOD_UNITS        0xFFFFu
#define IBS_MIN_PERIOD              0x10u

static BOOLEAN       g_Available;
static volatile LONG g_Interval;        /* 0 when disarmed; in micro-ops     */
static volatile LONG64 g_Samples;

VOID SvIbsProbe(VOID)
{
    int regs[4];

    g_Available = FALSE;

    __cpuid(regs, CPUID_EXT_FEATURES);
    if ((((UINT32)regs[2]) & CPUID_EXT_FEATURE_IBS) == 0)
    {
        DbgPrint("svmhv: no IBS on this processor; sampling unavailable\n");
        return;
    }

    /*
     * The feature leaf has to say it is valid before its other bits mean
     * anything - on a part where 8000_001B is not implemented the read returns
     * whatever the highest supported leaf returns, and believing bit 2 of that
     * would arm sampling on hardware that has none.
     */
    __cpuid(regs, CPUID_IBS_FEATURES);
    if ((((UINT32)regs[0]) & CPUID_IBS_FFV) == 0 ||
        (((UINT32)regs[0]) & CPUID_IBS_OP_SAM) == 0)
    {
        DbgPrint("svmhv: IBS present but op sampling is not exposed "
                 "(8000_001B eax %08x); sampling unavailable\n",
                 (UINT32)regs[0]);
        return;
    }

    g_Available = TRUE;
    DbgPrint("svmhv: IBS op sampling available\n");
}

BOOLEAN SvIbsAvailable(VOID)
{
    return g_Available;
}

/* Written on every processor by the DPC below; period is in units of 16. */
static UINT64 g_ArmValue;

static VOID SvIbsArmDpc(_In_ PKDPC Dpc, _In_opt_ PVOID Context,
                        _In_opt_ PVOID SystemArgument1,
                        _In_opt_ PVOID SystemArgument2)
{
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(Context);

    __writemsr(MSR_IBS_OP_CTL, g_ArmValue);

    KeSignalCallDpcSynchronize(SystemArgument2);
    KeSignalCallDpcDone(SystemArgument1);
}

NTSTATUS SvIbsArm(_In_ UINT32 Interval)
{
    UINT32 units;

    if (!g_Available)
    {
        return STATUS_NOT_SUPPORTED;
    }

    if (Interval == 0)
    {
        /*
         * Disarm the flag before the MSRs, so no processor is still polling
         * while they are being cleared - the poll would read a control word
         * with the enable already gone and re-arm it.
         */
        InterlockedExchange(&g_Interval, 0);
        g_ArmValue = 0;
        KeGenericCallDpc(SvIbsArmDpc, NULL);
        return STATUS_SUCCESS;
    }

    if (Interval < IBS_MIN_PERIOD)
    {
        Interval = IBS_MIN_PERIOD;
    }

    units = Interval / 16;
    if (units > IBS_MAX_PERIOD_UNITS)
    {
        units = IBS_MAX_PERIOD_UNITS;
    }
    if (units == 0)
    {
        units = 1;
    }

    g_ArmValue = ((UINT64)units & IBS_OP_CTL_MAX_CNT_MASK) | IBS_OP_CTL_EN;

    /* MSRs first, then the flag: a processor that starts polling has to find
       the counter already running, not the other way round. */
    KeGenericCallDpc(SvIbsArmDpc, NULL);
    InterlockedExchange(&g_Interval, (LONG)(units * 16));
    return STATUS_SUCCESS;
}

VOID SvIbsPoll(_In_ UINT32 Processor, _In_ UINT64 Cr3)
{
    UINT64 control;
    UINT64 rip;
    UINT64 data3;
    UINT64 address = 0;
    UINT64 kind;

    if (g_Interval == 0)
    {
        return;
    }

    control = __readmsr(MSR_IBS_OP_CTL);
    if ((control & IBS_OP_CTL_VAL) == 0)
    {
        return;                         /* nothing has ripened yet */
    }

    rip   = __readmsr(MSR_IBS_OP_RIP);
    data3 = __readmsr(MSR_IBS_OP_DATA3);

    /*
     * The data address is the reason to be here at all, and it is only there
     * for an op that touched memory and whose linear address the processor was
     * able to record.  Reading it unconditionally would hand back the previous
     * sample's address on every op that was neither a load nor a store.
     */
    if ((data3 & (IBS_OP_DATA3_LD_OP | IBS_OP_DATA3_ST_OP)) != 0 &&
        (data3 & IBS_OP_DATA3_DC_LIN_VALID) != 0)
    {
        address = __readmsr(MSR_IBS_DC_LIN_AD);
    }

    kind = ((data3 & IBS_OP_DATA3_ST_OP) != 0) ? 1 : 0;

    SvTraceRegister(SVMHV_TRACE_IBS, rip, Cr3, Processor, address,
                    __readmsr(MSR_IBS_OP_DATA), (UINT32)kind, 0, data3);

    InterlockedIncrement64(&g_Samples);

    /*
     * Re-arm.  Writing the control word with IbsOpVal clear both clears the
     * valid bit and reloads the counter, which is one write rather than two and
     * is what the architecture asks for.
     */
    __writemsr(MSR_IBS_OP_CTL, g_ArmValue);
}

VOID SvIbsState(_Out_ UINT32* Interval, _Out_ UINT64* Samples)
{
    *Interval = (UINT32)InterlockedCompareExchange(&g_Interval, 0, 0);
    *Samples = (UINT64)InterlockedCompareExchange64(&g_Samples, 0, 0);
}
