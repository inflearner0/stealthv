/*
 * mapload.c - a manual mapper, so the manual-map build can be tested.
 *
 * svmhv-manualmap.sys exists for loaders this repository does not contain, and
 * "it compiles and its entry point ignores both parameters" was the whole of
 * what had ever been checked here.  This is the missing half: a driver that
 * maps that image the way a mapper does - allocate, copy sections, relocate,
 * resolve imports by name, call the entry point - and reports what came back.
 *
 * It is deliberately not a loader of the interesting kind.  A real mapper's
 * hard part is getting kernel execution in the first place, usually by driving
 * a vulnerable signed driver; this one is simply loaded as a service on a
 * testsigning machine, which the lab already is.  Everything downstream of
 * "somebody is executing in ring 0" is the same, and that downstream half is
 * the only part svmhv can tell apart.
 *
 * Reporting, in the absence of a debugger: DriverEntry returns whatever the
 * mapped image returned, so `sc start mapload` prints it.  That matters because
 * PowerShell Direct dies the moment the hypervisor comes up - on failure the
 * status comes back through sc, and on success the guest's HTTP agent starts
 * answering, so the two outcomes are distinguishable without a kernel debugger
 * either way.
 *
 * Built by build.ps1 -Fixtures, alongside umtarget.exe.  It is a fixture, not
 * part of the product.
 */

#include <ntddk.h>
#include <ntimage.h>

#define MAPLOAD_TAG         'LpaM'
#define MAPLOAD_IMAGE       L"\\??\\C:\\lab\\svmhv-manualmap.sys"

/*
 * Emulate a mapper that erases the PE headers after copying them.
 *
 * kdmapper and friends do this, and svmhv's SvSetImageExtent has a fallback for
 * exactly that case - it cannot read SizeOfImage from a blank page, so it
 * assumes a span instead.  Both paths are worth running, and which one runs is
 * decided by a file rather than a rebuild: drop C:\lab\wipe.flag to take the
 * fallback.
 */
#define MAPLOAD_FLAG        L"\\??\\C:\\lab\\wipe.flag"

DRIVER_INITIALIZE DriverEntry;

static NTSTATUS MapLoadReadFile(_In_ PCWSTR Path,
                                _Outptr_ UCHAR** Buffer,
                                _Out_ ULONG* Size)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    FILE_STANDARD_INFORMATION info;
    LARGE_INTEGER offset;
    HANDLE file = NULL;
    UCHAR* buffer = NULL;
    NTSTATUS status;

    *Buffer = NULL;
    *Size = 0;

    RtlInitUnicodeString(&name, Path);
    InitializeObjectAttributes(&attributes, &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    status = ZwCreateFile(&file, GENERIC_READ | SYNCHRONIZE, &attributes, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT |
                          FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ZwQueryInformationFile(file, &iosb, &info, sizeof(info),
                                    FileStandardInformation);
    if (!NT_SUCCESS(status))
    {
        ZwClose(file);
        return status;
    }

    if (info.EndOfFile.HighPart != 0 || info.EndOfFile.LowPart == 0)
    {
        ZwClose(file);
        return STATUS_FILE_TOO_LARGE;
    }

    buffer = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, info.EndOfFile.LowPart,
                                     MAPLOAD_TAG);
    if (buffer == NULL)
    {
        ZwClose(file);
        /* Not STATUS_INSUFFICIENT_RESOURCES: that one is reserved for the
           mapped image, so `sc start` reporting it means svmhv said it. */
        return STATUS_QUOTA_EXCEEDED;
    }

    offset.QuadPart = 0;
    status = ZwReadFile(file, NULL, NULL, NULL, &iosb, buffer,
                        info.EndOfFile.LowPart, &offset, NULL);
    ZwClose(file);

    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(buffer, MAPLOAD_TAG);
        return status;
    }

    *Buffer = buffer;
    *Size = info.EndOfFile.LowPart;
    return STATUS_SUCCESS;
}

/*
 * Where it got to, in a file, because there is no debugger here.
 *
 * The first two runs both came back as ERROR_NO_SYSTEM_RESOURCES from
 * `sc start`, which is what this driver returns when its own pool allocation
 * fails *and* what svmhv returns when its resources do not fit - so the one
 * number could not say which of the two had happened, and there is no way to
 * tell from outside.  Every failure below now has a status of its own, and this
 * writes the last stage reached next to it.
 */
static VOID MapLoadNote(_In_ PCSTR Text)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    ULONG length = 0;

    while (Text[length] != '\0')
    {
        length++;
    }

    RtlInitUnicodeString(&name, L"\\??\\C:\\lab\\mapload-stage.txt");
    InitializeObjectAttributes(&attributes, &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    if (NT_SUCCESS(ZwCreateFile(&file, GENERIC_WRITE | SYNCHRONIZE, &attributes,
                                &iosb, NULL, FILE_ATTRIBUTE_NORMAL, 0,
                                FILE_OVERWRITE_IF,
                                FILE_SYNCHRONOUS_IO_NONALERT |
                                FILE_NON_DIRECTORY_FILE, NULL, 0)))
    {
        (VOID)ZwWriteFile(file, NULL, NULL, NULL, &iosb, (PVOID)Text, length,
                          NULL, NULL);
        ZwClose(file);
    }

    DbgPrint("mapload: %s\n", Text);
}

static BOOLEAN MapLoadFileExists(_In_ PCWSTR Path)
{
    UNICODE_STRING name;
    OBJECT_ATTRIBUTES attributes;
    IO_STATUS_BLOCK iosb;
    HANDLE file = NULL;
    NTSTATUS status;

    RtlInitUnicodeString(&name, Path);
    InitializeObjectAttributes(&attributes, &name,
                               OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
                               NULL, NULL);

    status = ZwCreateFile(&file, GENERIC_READ | SYNCHRONIZE, &attributes, &iosb,
                          NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
                          FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT |
                          FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (NT_SUCCESS(status))
    {
        ZwClose(file);
        return TRUE;
    }
    return FALSE;
}

/* Every import this driver has is an ntoskrnl or hal export, which is exactly
   the set MmGetSystemRoutineAddress searches.  An ordinal import would not be,
   and is refused rather than guessed at. */
static NTSTATUS MapLoadResolveImports(_In_ UCHAR* Image,
                                      _In_ const IMAGE_NT_HEADERS64* Nt)
{
    const IMAGE_DATA_DIRECTORY* dir =
        &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    const IMAGE_IMPORT_DESCRIPTOR* descriptor;

    if (dir->Size == 0)
    {
        return STATUS_SUCCESS;
    }

    descriptor = (const IMAGE_IMPORT_DESCRIPTOR*)(Image + dir->VirtualAddress);

    for (; descriptor->Name != 0; descriptor++)
    {
        ULONG64* thunk = (ULONG64*)(Image + descriptor->FirstThunk);
        const ULONG64* original = (descriptor->OriginalFirstThunk != 0)
            ? (const ULONG64*)(Image + descriptor->OriginalFirstThunk)
            : (const ULONG64*)thunk;

        DbgPrint("mapload: imports from %s\n", (const char*)(Image + descriptor->Name));

        for (; *original != 0; original++, thunk++)
        {
            const IMAGE_IMPORT_BY_NAME* byName;
            ANSI_STRING ansi;
            UNICODE_STRING wide;
            PVOID resolved;
            NTSTATUS status;

            if (IMAGE_SNAP_BY_ORDINAL64(*original))
            {
                DbgPrint("mapload: ordinal import, cannot resolve by name\n");
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            byName = (const IMAGE_IMPORT_BY_NAME*)(Image + (*original & 0xFFFFFFFFULL));
            RtlInitAnsiString(&ansi, (PCSZ)byName->Name);

            status = RtlAnsiStringToUnicodeString(&wide, &ansi, TRUE);
            if (!NT_SUCCESS(status))
            {
                return status;
            }

            resolved = MmGetSystemRoutineAddress(&wide);
            RtlFreeUnicodeString(&wide);

            if (resolved == NULL)
            {
                DbgPrint("mapload: unresolved import %s\n", byName->Name);
                return STATUS_PROCEDURE_NOT_FOUND;
            }

            *thunk = (ULONG64)resolved;
        }
    }

    return STATUS_SUCCESS;
}

static VOID MapLoadRelocate(_In_ UCHAR* Image,
                            _In_ const IMAGE_NT_HEADERS64* Nt,
                            _In_ ULONG64 Delta)
{
    const IMAGE_DATA_DIRECTORY* dir =
        &Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    const IMAGE_BASE_RELOCATION* block;
    ULONG done = 0;
    ULONG applied = 0;

    if (Delta == 0 || dir->Size == 0)
    {
        return;
    }

    block = (const IMAGE_BASE_RELOCATION*)(Image + dir->VirtualAddress);

    while (done < dir->Size && block->SizeOfBlock != 0)
    {
        const USHORT* entry = (const USHORT*)(block + 1);
        ULONG count = (block->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) /
                      sizeof(USHORT);
        ULONG i;

        for (i = 0; i < count; i++)
        {
            USHORT type = (USHORT)(entry[i] >> 12);
            USHORT offset = (USHORT)(entry[i] & 0x0FFF);

            if (type == IMAGE_REL_BASED_DIR64)
            {
                ULONG64* patch = (ULONG64*)(Image + block->VirtualAddress + offset);
                *patch += Delta;
                applied++;
            }
        }

        done += block->SizeOfBlock;
        block = (const IMAGE_BASE_RELOCATION*)((const UCHAR*)block + block->SizeOfBlock);
    }

    DbgPrint("mapload: %lu relocations applied (delta %llx)\n", applied, Delta);
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath)
{
    PHYSICAL_ADDRESS lowest;
    PHYSICAL_ADDRESS highest;
    PHYSICAL_ADDRESS boundary;
    const IMAGE_DOS_HEADER* dos;
    const IMAGE_NT_HEADERS64* nt;
    const IMAGE_SECTION_HEADER* section;
    UCHAR* raw = NULL;
    UCHAR* image = NULL;
    ULONG rawSize = 0;
    ULONG i;
    BOOLEAN wipe;
    PDRIVER_INITIALIZE entry;
    NTSTATUS status;

    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);

    /* No DriverUnload on purpose.  If the mapped image virtualised the machine,
       its exit handlers are in memory this driver allocated, and letting the
       service manager unload us would free the ground out from under them. */

    MapLoadNote("entered, reading the image");

    status = MapLoadReadFile(MAPLOAD_IMAGE, &raw, &rawSize);
    if (!NT_SUCCESS(status))
    {
        DbgPrint("mapload: cannot read the image (%08X)\n", status);
        return status;
    }

    dos = (const IMAGE_DOS_HEADER*)raw;
    if (rawSize < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE)
    {
        ExFreePoolWithTag(raw, MAPLOAD_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    nt = (const IMAGE_NT_HEADERS64*)(raw + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
    {
        ExFreePoolWithTag(raw, MAPLOAD_TAG);
        return STATUS_INVALID_IMAGE_FORMAT;
    }

    /*
     * Executable and non-paged, but emphatically not contiguous.
     *
     * The first version asked MmAllocateContiguousNodeMemory for SizeOfImage,
     * copying what hook.c does for its single trampoline page, and it failed:
     * a whole image is about a hundred kilobytes and physically contiguous runs
     * that size are not there for the asking on a fragmented guest.  Windows
     * reported it as ERROR_NO_SYSTEM_RESOURCES from `sc start`, which reads
     * exactly like the mapped driver refusing and is nothing of the kind.
     * Nothing here needs contiguity - only the pages svmhv itself hands to the
     * processor do - so an executable pool allocation is the right tool.
     */
    UNREFERENCED_PARAMETER(lowest);
    UNREFERENCED_PARAMETER(highest);
    UNREFERENCED_PARAMETER(boundary);

    image = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED_EXECUTE,
                                    nt->OptionalHeader.SizeOfImage, MAPLOAD_TAG);
    if (image == NULL)
    {
        ExFreePoolWithTag(raw, MAPLOAD_TAG);
        /* Distinct from the file buffer's failure above, so `sc start` names
           the step: this one comes back as ERROR_NOT_ENOUGH_MEMORY. */
        return STATUS_NO_MEMORY;
    }

    RtlZeroMemory(image, nt->OptionalHeader.SizeOfImage);
    RtlCopyMemory(image, raw, nt->OptionalHeader.SizeOfHeaders);

    section = IMAGE_FIRST_SECTION(nt);
    for (i = 0; i < nt->FileHeader.NumberOfSections; i++)
    {
        if (section[i].SizeOfRawData != 0)
        {
            RtlCopyMemory(image + section[i].VirtualAddress,
                          raw + section[i].PointerToRawData,
                          section[i].SizeOfRawData);
        }
    }

    DbgPrint("mapload: %u sections at %p, %lu bytes, preferred base %llx\n",
             nt->FileHeader.NumberOfSections, image,
             nt->OptionalHeader.SizeOfImage, nt->OptionalHeader.ImageBase);

    MapLoadNote("sections copied, relocating");
    MapLoadRelocate(image, nt, (ULONG64)image - nt->OptionalHeader.ImageBase);

    MapLoadNote("relocated, resolving imports");

    status = MapLoadResolveImports(image, nt);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(image, MAPLOAD_TAG);
        ExFreePoolWithTag(raw, MAPLOAD_TAG);
        return status;
    }

    entry = (PDRIVER_INITIALIZE)(image + nt->OptionalHeader.AddressOfEntryPoint);

    /* Read the flag before the headers go, since both live in this image. */
    wipe = MapLoadFileExists(MAPLOAD_FLAG);
    if (wipe)
    {
        RtlZeroMemory(image, nt->OptionalHeader.SizeOfHeaders);
        DbgPrint("mapload: headers wiped\n");
    }

    ExFreePoolWithTag(raw, MAPLOAD_TAG);

    /*
     * Both parameters NULL, which is the case the manual-map build was written
     * for and the case that would kill the service build instantly.
     */
    DbgPrint("mapload: calling entry at %p with (NULL, NULL)\n", entry);
    MapLoadNote("calling the entry point");
    status = entry(NULL, NULL);
    MapLoadNote(NT_SUCCESS(status) ? "entry returned success"
                                   : "entry returned a failure");
    DbgPrint("mapload: entry returned %08X\n", status);

    if (!NT_SUCCESS(status))
    {
        /* Nothing of it is running, so the image can go back. */
        ExFreePoolWithTag(image, MAPLOAD_TAG);
        return status;
    }

    /* Deliberately leaked: it is a live hypervisor now. */
    return STATUS_SUCCESS;
}
