/*
 * umtarget.exe - something for a user-mode execution hook to hook.
 *
 * Deliberately shaped like the thing the feature exists for rather than like a
 * convenient test: it allocates a private executable page, writes a function
 * into it by hand, and calls it in a loop.  Nothing on disk describes that
 * function, no module list contains it, and its page is MEM_PRIVATE - which is
 * what a manually mapped payload looks like, and what SvHookInstall requires
 * before it will put a stub in a process.
 *
 * The function returns the sum of its four arguments, and the arguments are
 * chosen so a trace record is unmistakable rather than plausible.
 *
 *      umtarget.exe [seconds]
 *
 * It prints the address of the page so a hook can be aimed at it, then loops
 * quietly until the time is up.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>     /* strtoul */
#include <string.h>     /* memcpy  */

/*
 * mov rax, rcx ; add rax, rdx ; add rax, r8 ; add rax, r9 ; ret
 *
 * Fourteen bytes of prologue are needed before a hook can overwrite anything,
 * and this is only eleven - so it is padded with int3 to give the installer
 * room without the padding ever being reached.
 */
static const unsigned char kVictim[] =
{
    0x48, 0x89, 0xC8,               /* mov rax, rcx */
    0x48, 0x01, 0xD0,               /* add rax, rdx */
    0x4C, 0x01, 0xC0,               /* add rax, r8  */
    0x4C, 0x01, 0xC8,               /* add rax, r9  */
    0xC3,                           /* ret          */
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,
};

typedef unsigned __int64 (*VICTIM)(unsigned __int64, unsigned __int64,
                                   unsigned __int64, unsigned __int64);

int main(int argc, char** argv)
{
    const unsigned long seconds = (argc >= 2) ? strtoul(argv[1], NULL, 0) : 120;
    const unsigned long long deadline = GetTickCount64() + seconds * 1000ULL;
    unsigned long long calls = 0;
    unsigned long long wrong = 0;
    VICTIM victim;
    void* page;

    page = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                        PAGE_EXECUTE_READWRITE);
    if (page == NULL)
    {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }

    memcpy(page, kVictim, sizeof(kVictim));
    FlushInstructionCache(GetCurrentProcess(), page, sizeof(kVictim));
    victim = (VICTIM)page;

    printf("pid=%lu\nvictim=0x%llx\n", GetCurrentProcessId(),
           (unsigned long long)(ULONG_PTR)page);
    fflush(stdout);

    while (GetTickCount64() < deadline)
    {
        /*
         * A fresh page each time round, mapped and written and only then run.
         *
         * The single allocation this used to make was a fair model of a manual
         * map and a hopeless way to test one: the sweep has to be armed before
         * the write, and one page out of six gigabytes almost never lands in a
         * range small enough to sweep safely.  Remapping every iteration turns
         * "arm the sweep and hope" into "arm the sweep and wait", which is the
         * difference between a test that works and one that needs luck.
         */
        void* fresh = VirtualAlloc(NULL, 0x1000, MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);

        if (fresh != NULL)
        {
            memcpy(fresh, kVictim, sizeof(kVictim));
            FlushInstructionCache(GetCurrentProcess(), fresh, sizeof(kVictim));
            if (((VICTIM)fresh)(1, 2, 3, 4) != 10)
            {
                wrong++;
            }
            VirtualFree(fresh, 0, MEM_RELEASE);
        }

        /*
         * The result is checked, not discarded.  A hook that corrupted an
         * argument register or the return value would otherwise look exactly
         * like a hook that worked, and "the trace record appeared" is only half
         * of what needs to be true - the other half is that the function still
         * did what it was for.
         */
        const unsigned __int64 result =
            victim(0x1111111111111111ULL, 0x2222222222222222ULL,
                   0x3333333333333333ULL, 0x4444444444444444ULL);

        if (result != 0xAAAAAAAAAAAAAAAAULL)
        {
            wrong++;
        }
        calls++;
        Sleep(10);
    }

    printf("calls=%llu\nwrong=%llu\n", calls, wrong);
    return (wrong != 0) ? 2 : 0;
}
