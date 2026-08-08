/*
 * objects.c - device objects and symbolic links.  See objects.h.
 */

/* Before objects.h, which takes ntddk.h: ntifs.h has to be first of the two. */
#include <ntifs.h>

#include "objects.h"

/*
 * Not in any WDK header, but documented and stable since NT 4.  The directory
 * namespace has no other enumerator: Ob's own are all internal, and the only
 * supported way to list \GLOBAL?? is to open it and ask.
 */
NTSYSAPI NTSTATUS NTAPI ZwQueryDirectoryObject(
    _In_ HANDLE DirectoryHandle,
    _Out_writes_bytes_opt_(Length) PVOID Buffer,
    _In_ ULONG Length,
    _In_ BOOLEAN ReturnSingleEntry,
    _In_ BOOLEAN RestartScan,
    _Inout_ PULONG Context,
    _Out_opt_ PULONG ReturnLength);

typedef struct _SVMHV_DIRECTORY_INFORMATION
{
    UNICODE_STRING Name;
    UNICODE_STRING TypeName;
} SVMHV_DIRECTORY_INFORMATION;

#define SVMHV_OBJECTS_TAG   'jbvS'

/* ------------------------------------------------------------ formatting */

/*
 * A tiny appender rather than RtlStringCchPrintfA.
 *
 * ntstrsafe is a separate library this driver does not link, and pulling it in
 * for four conversions would be the only reason it was there.  Everything below
 * writes into a fixed buffer and stops at the end of it, so a truncated answer
 * is short rather than wrong.
 */
typedef struct _SVMHV_WRITER
{
    CHAR* Buffer;
    ULONG Capacity;
    ULONG Used;
} SVMHV_WRITER;

static VOID SvWriteChar(_Inout_ SVMHV_WRITER* Writer, _In_ CHAR Value)
{
    /* One byte always kept back, so the result is a C string. */
    if (Writer->Used + 1 < Writer->Capacity)
    {
        Writer->Buffer[Writer->Used++] = Value;
        Writer->Buffer[Writer->Used] = '\0';
    }
}

static VOID SvWriteText(_Inout_ SVMHV_WRITER* Writer, _In_ const CHAR* Text)
{
    while (*Text != '\0')
    {
        SvWriteChar(Writer, *Text++);
    }
}

static VOID SvWriteHex(_Inout_ SVMHV_WRITER* Writer, _In_ UINT64 Value)
{
    static const CHAR digits[] = "0123456789abcdef";
    CHAR temp[17];
    int at = 0;

    SvWriteText(Writer, "0x");
    if (Value == 0)
    {
        SvWriteChar(Writer, '0');
        return;
    }

    while (Value != 0 && at < (int)sizeof(temp))
    {
        temp[at++] = digits[Value & 0xF];
        Value >>= 4;
    }
    while (at > 0)
    {
        SvWriteChar(Writer, temp[--at]);
    }
}

static VOID SvWriteDecimal(_Inout_ SVMHV_WRITER* Writer, _In_ ULONG Value)
{
    CHAR temp[11];
    int at = 0;

    if (Value == 0)
    {
        SvWriteChar(Writer, '0');
        return;
    }
    while (Value != 0 && at < (int)sizeof(temp))
    {
        temp[at++] = (CHAR)('0' + (Value % 10));
        Value /= 10;
    }
    while (at > 0)
    {
        SvWriteChar(Writer, temp[--at]);
    }
}

/*
 * Object names are UTF-16 and the channel carries bytes, so they are narrowed
 * here.  Every name in this namespace is ASCII in practice; anything that is
 * not becomes '?' rather than being dropped, so a name that would otherwise
 * vanish silently is at least visible as the wrong length.
 */
static VOID SvWriteUnicode(_Inout_ SVMHV_WRITER* Writer,
                           _In_ const UNICODE_STRING* String)
{
    USHORT i;

    if (String->Buffer == NULL)
    {
        return;
    }

    for (i = 0; i < String->Length / sizeof(WCHAR); i++)
    {
        const WCHAR c = String->Buffer[i];

        /* No newlines: one record per line is the whole parse on the far end. */
        SvWriteChar(Writer, (c >= 0x20 && c < 0x7F) ? (CHAR)c : '?');
    }
}

/* ------------------------------------------------------------ the request */

/*
 * The ASCII name a client puts in MemoryData, checked and converted.  Shared
 * with memory.c's driver lookup in spirit but not in code: this one roots at
 * \Driver only for the device walk, and the buffer it validates is the same
 * buffer the answer goes into, so it has to be copied out first.
 */
static NTSTATUS SvObjectsRequestName(_In_ const SVMHV_HOOK_REQUEST* Request,
                                     _Out_ WCHAR* Path, _In_ ULONG PathChars,
                                     _Out_ UNICODE_STRING* Name)
{
    ANSI_STRING ansi;
    UNICODE_STRING converted;
    NTSTATUS status;
    ULONG i;

    for (i = 0; i < 64 && Request->MemoryData[i] != 0; i++)
    {
        if (Request->MemoryData[i] < 0x20 || Request->MemoryData[i] > 0x7E)
        {
            return STATUS_INVALID_PARAMETER;
        }
    }
    if (i == 0 || i >= 64)
    {
        return STATUS_INVALID_PARAMETER;
    }

    ansi.Buffer = (PCHAR)Request->MemoryData;
    ansi.Length = (USHORT)i;
    ansi.MaximumLength = (USHORT)i;

    status = RtlAnsiStringToUnicodeString(&converted, &ansi, TRUE);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    RtlZeroMemory(Path, PathChars * sizeof(WCHAR));
    Name->Buffer = Path;
    Name->Length = 0;
    Name->MaximumLength = (USHORT)(PathChars * sizeof(WCHAR));

    if (converted.Length >= sizeof(WCHAR) && converted.Buffer[0] != L'\\')
    {
        RtlAppendUnicodeToString(Name, L"\\Driver\\");
    }
    status = RtlAppendUnicodeStringToString(Name, &converted);
    RtlFreeUnicodeString(&converted);
    return status;
}

/* ---------------------------------------------------------------- devices */

extern POBJECT_TYPE* IoDriverObjectType;

NTKERNELAPI NTSTATUS ObReferenceObjectByName(
    _In_ PUNICODE_STRING ObjectName, _In_ ULONG Attributes,
    _In_opt_ PACCESS_STATE AccessState, _In_opt_ ACCESS_MASK DesiredAccess,
    _In_ POBJECT_TYPE ObjectType, _In_ KPROCESSOR_MODE AccessMode,
    _Inout_opt_ PVOID ParseContext, _Out_ PVOID* Object);

/*
 * A device's name, or nothing.
 *
 * Most devices have one; the ones created with a NULL name - which is how a
 * filter attaches without being openable - correctly come back empty, and that
 * absence is itself worth seeing.
 */
static VOID SvObjectsWriteName(_Inout_ SVMHV_WRITER* Writer,
                               _In_ PVOID Object, _Inout_ PVOID Scratch,
                               _In_ ULONG ScratchLength)
{
    POBJECT_NAME_INFORMATION info = (POBJECT_NAME_INFORMATION)Scratch;
    ULONG returned = 0;
    const NTSTATUS status =
        ObQueryNameString(Object, info, ScratchLength, &returned);

    if (!NT_SUCCESS(status) || info->Name.Length == 0)
    {
        SvWriteText(Writer, " name=(unnamed)");
        return;
    }

    SvWriteText(Writer, " name=");
    SvWriteUnicode(Writer, &info->Name);
}

NTSTATUS SvObjectsDevices(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    WCHAR path[128];
    UNICODE_STRING name;
    SVMHV_WRITER writer;
    PDRIVER_OBJECT driver = NULL;
    PDEVICE_OBJECT device;
    PVOID scratch;
    NTSTATUS status;
    ULONG count = 0;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Request->MemoryReturned = 0;

    status = SvObjectsRequestName(Request, path, RTL_NUMBER_OF(path), &name);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    status = ObReferenceObjectByName(&name, OBJ_CASE_INSENSITIVE, NULL, 0,
                                     *IoDriverObjectType, KernelMode, NULL,
                                     (PVOID*)&driver);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    scratch = ExAllocatePool2(POOL_FLAG_PAGED, PAGE_SIZE, SVMHV_OBJECTS_TAG);
    if (scratch == NULL)
    {
        ObDereferenceObject(driver);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(Request->MemoryData, sizeof(Request->MemoryData));
    writer.Buffer = (CHAR*)Request->MemoryData;
    writer.Capacity = sizeof(Request->MemoryData);
    writer.Used = 0;

    /*
     * The chain is only safe to walk with the driver referenced, which is what
     * the lookup above holds: a device cannot be deleted while its driver is
     * still there, and the driver cannot unload while this reference exists.
     */
    for (device = driver->DeviceObject;
         device != NULL;
         device = device->NextDevice)
    {
        PDEVICE_OBJECT attached;
        ULONG depth = 0;

        SvWriteText(&writer, "device ");
        SvWriteHex(&writer, (UINT64)(ULONG_PTR)device);
        SvWriteText(&writer, " type=");
        SvWriteHex(&writer, device->DeviceType);
        SvWriteText(&writer, " flags=");
        SvWriteHex(&writer, device->Flags);
        SvWriteText(&writer, " chars=");
        SvWriteHex(&writer, device->Characteristics);
        SvWriteText(&writer, " ext=");
        SvWriteHex(&writer, (UINT64)(ULONG_PTR)device->DeviceExtension);
        SvWriteText(&writer, " stack=");
        SvWriteDecimal(&writer, (ULONG)device->StackSize);
        SvObjectsWriteName(&writer, device, scratch, PAGE_SIZE);
        SvWriteChar(&writer, '\n');
        count++;

        /*
         * Upwards from here is every filter sitting on this device.  A filter
         * driver has no device of its own in any list a client can find, so
         * this is where one becomes visible - and an unexpected name in this
         * chain is exactly what somebody looking for a filter wants to see.
         */
        for (attached = device->AttachedDevice;
             attached != NULL && depth < 16;
             attached = attached->AttachedDevice, depth++)
        {
            SvWriteText(&writer, "  attached ");
            SvWriteHex(&writer, (UINT64)(ULONG_PTR)attached);
            SvWriteText(&writer, " driver=");
            SvWriteHex(&writer,
                       (UINT64)(ULONG_PTR)attached->DriverObject);
            SvObjectsWriteName(&writer, attached->DriverObject, scratch,
                               PAGE_SIZE);
            SvWriteChar(&writer, '\n');
        }

        /* Out of buffer: say so rather than quietly returning a short list. */
        if (writer.Used + 64 >= writer.Capacity)
        {
            SvWriteText(&writer, "truncated=1\n");
            break;
        }
    }

    SvWriteText(&writer, "devices=");
    SvWriteDecimal(&writer, count);
    SvWriteChar(&writer, '\n');

    ExFreePoolWithTag(scratch, SVMHV_OBJECTS_TAG);
    ObDereferenceObject(driver);

    Request->MemoryReturned = writer.Used;
    return STATUS_SUCCESS;
}

/* --------------------------------------------------------- symbolic links */

/*
 * Where a link points.  Opening it is the only way to ask - the target is not
 * a field of anything reachable from the directory entry.
 */
static VOID SvObjectsWriteTarget(_Inout_ SVMHV_WRITER* Writer,
                                 _In_ UNICODE_STRING* LinkName,
                                 _Inout_ WCHAR* Scratch, _In_ ULONG ScratchBytes)
{
    OBJECT_ATTRIBUTES attributes;
    UNICODE_STRING target;
    HANDLE link = NULL;
    ULONG returned = 0;
    NTSTATUS status;

    InitializeObjectAttributes(&attributes, LinkName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwOpenSymbolicLinkObject(&link, GENERIC_READ, &attributes);
    if (!NT_SUCCESS(status))
    {
        SvWriteText(Writer, "(unreadable)");
        return;
    }

    target.Buffer = Scratch;
    target.Length = 0;
    target.MaximumLength = (USHORT)ScratchBytes;

    status = ZwQuerySymbolicLinkObject(link, &target, &returned);
    ZwClose(link);

    if (!NT_SUCCESS(status))
    {
        SvWriteText(Writer, "(unreadable)");
        return;
    }

    SvWriteUnicode(Writer, &target);
}

NTSTATUS SvObjectsSymbolicLinks(_Inout_ SVMHV_HOOK_REQUEST* Request)
{
    static const UNICODE_STRING directoryName =
        RTL_CONSTANT_STRING(L"\\GLOBAL??");

    OBJECT_ATTRIBUTES attributes;
    SVMHV_WRITER writer;
    HANDLE directory = NULL;
    PVOID buffer;
    WCHAR* targetScratch;
    WCHAR* fullName;
    NTSTATUS status;
    ULONG context = 0;
    ULONG index = 0;
    ULONG written = 0;
    const ULONG start = Request->MemoryProcessId;

    NT_ASSERT(KeGetCurrentIrql() == PASSIVE_LEVEL);

    Request->MemoryReturned = 0;

    InitializeObjectAttributes(&attributes, (PUNICODE_STRING)&directoryName,
                               OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ZwOpenDirectoryObject(&directory, DIRECTORY_QUERY, &attributes);
    if (!NT_SUCCESS(status))
    {
        return status;
    }

    /* One allocation, carved up: the entry buffer, a place to build each
       link's full path, and somewhere for its target to land. */
    buffer = ExAllocatePool2(POOL_FLAG_PAGED, PAGE_SIZE * 3,
                             SVMHV_OBJECTS_TAG);
    if (buffer == NULL)
    {
        ZwClose(directory);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    fullName     = (WCHAR*)((UINT8*)buffer + PAGE_SIZE);
    targetScratch = (WCHAR*)((UINT8*)buffer + PAGE_SIZE * 2);

    RtlZeroMemory(Request->MemoryData, sizeof(Request->MemoryData));
    writer.Buffer = (CHAR*)Request->MemoryData;
    writer.Capacity = sizeof(Request->MemoryData);
    writer.Used = 0;

    /*
     * One entry at a time.  The batching form returns as many as fit and is
     * faster, but each entry then has to be found by walking the buffer, and
     * the layout of that walk is undocumented in exactly the way this file
     * exists to avoid.
     */
    while (NT_SUCCESS(ZwQueryDirectoryObject(directory, buffer, PAGE_SIZE, TRUE,
                                             (BOOLEAN)(index == 0), &context,
                                             NULL)))
    {
        const SVMHV_DIRECTORY_INFORMATION* entry =
            (const SVMHV_DIRECTORY_INFORMATION*)buffer;
        UNICODE_STRING path;

        if (entry->Name.Length == 0)
        {
            break;
        }

        /* Only links: the directory also holds the devices themselves. */
        if (entry->TypeName.Length != sizeof(L"SymbolicLink") - sizeof(WCHAR) ||
            _wcsnicmp(entry->TypeName.Buffer, L"SymbolicLink", 12) != 0)
        {
            index++;
            continue;
        }

        if (index++ < start)
        {
            continue;
        }

        /* Room for one more line, or stop and say where to resume. */
        if (writer.Used + 256 >= writer.Capacity)
        {
            SvWriteText(&writer, "next=");
            SvWriteDecimal(&writer, index - 1);
            SvWriteChar(&writer, '\n');
            break;
        }

        path.Buffer = fullName;
        path.Length = 0;
        path.MaximumLength = PAGE_SIZE;
        RtlAppendUnicodeToString(&path, L"\\GLOBAL??\\");
        RtlAppendUnicodeStringToString(&path, (PUNICODE_STRING)&entry->Name);

        SvWriteText(&writer, "link ");
        SvWriteUnicode(&writer, &entry->Name);
        SvWriteText(&writer, " -> ");
        SvObjectsWriteTarget(&writer, &path, targetScratch, PAGE_SIZE);
        SvWriteChar(&writer, '\n');
        written++;
    }

    SvWriteText(&writer, "links=");
    SvWriteDecimal(&writer, written);
    SvWriteChar(&writer, '\n');

    ExFreePoolWithTag(buffer, SVMHV_OBJECTS_TAG);
    ZwClose(directory);

    Request->MemoryReturned = writer.Used;
    return STATUS_SUCCESS;
}
