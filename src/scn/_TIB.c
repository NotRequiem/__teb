#include <stdio.h>
#include "struct.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _THREAD_BASIC_INFORMATION {
    NTSTATUS  ExitStatus;
    PVOID     TebBaseAddress;
    CLIENT_ID ClientId;
    ULONG_PTR AffinityMask;
    LONG      Priority;
    LONG      BasePriority;
} THREAD_BASIC_INFORMATION, * PTHREAD_BASIC_INFORMATION;

typedef enum _THREADINFOCLASS {
    ThreadBasicInformation = 0x00,
    ThreadTimes = 0x01,
    ThreadPriority = 0x02,
    ThreadBasePriority = 0x03,
    ThreadAffinityMask = 0x04,
    ThreadImpersonationToken = 0x05,
    ThreadDescriptorTableEntry = 0x06,
    ThreadEnableAlignmentFaultFixup = 0x07,
    ThreadEventPair = 0x08,
    ThreadQuerySetWin32StartAddress = 0x09,
    ThreadZeroTlsCell = 0x0A,
    ThreadPerformanceCount = 0x0B,
    ThreadAmILastThread = 0x0C,
    ThreadIdealProcessor = 0x0D,
    ThreadPriorityBoost = 0x0E,
    ThreadSetTlsArrayAddress = 0x0F,
    ThreadIsIoPending = 0x10,
    ThreadHideFromDebugger = 0x11,
    ThreadBreakOnTermination = 0x12,
    ThreadSwitchLegacyState = 0x13,
    ThreadIsTerminated = 0x14,
    ThreadLastSystemCall = 0x15,
    ThreadIoPriority = 0x16,
    ThreadCycleTime = 0x17,
    ThreadPagePriority = 0x18,
    ThreadActualBasePriority = 0x19,
    ThreadTebInformation = 0x1A,
    ThreadCSwitchMon = 0x1B,
    ThreadCSwitchPmu = 0x1C,
    ThreadWow64Context = 0x1D,
    ThreadGroupInformation = 0x1E,
    ThreadUmsInformation = 0x1F,
    ThreadCounterProfiling = 0x20,
    ThreadIdealProcessorEx = 0x21,
    ThreadCpuAccountingInformation = 0x22,
    ThreadSuspendCount = 0x23,
    ThreadHeterogeneousCpuPolicy = 0x24,
    ThreadContainerId = 0x25,
    ThreadNameInformation = 0x26,
    ThreadSelectedCpuSets = 0x27,
    ThreadSystemThreadInformation = 0x28,
    ThreadActualGroupAffinity = 0x29,
    MaxThreadInfoClass
} THREADINFOCLASS;

typedef NTSTATUS(WINAPI* PNT_QUERY_INFORMATION_THREAD)(
    HANDLE ThreadHandle,
    THREADINFOCLASS ThreadInformationClass,
    PVOID ThreadInformation,
    ULONG ThreadInformationLength,
    PULONG ReturnLength
    );

// static void GuidToString(const GUID* guid, char** str) {
//     int bufferSize = snprintf(NULL, 0, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
//         guid->Data1, guid->Data2, guid->Data3,
//         guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
//         guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
//     *str = (char*)malloc(bufferSize + 1);
//     if (*str != NULL) {
//         sprintf_s(*str, bufferSize + 1, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
//             guid->Data1, guid->Data2, guid->Data3,
//             guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
//             guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
//     }
//     else {
//         printf("Memory allocation failed.\n");
//     }
// }

void GuidToString(const GUID* guid, char* str) {
    sprintf_s(str, 39, "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
        guid->Data1, guid->Data2, guid->Data3,
        guid->Data4[0], guid->Data4[1], guid->Data4[2], guid->Data4[3],
        guid->Data4[4], guid->Data4[5], guid->Data4[6], guid->Data4[7]);
}

void printTEBFields(PTEB pTEB) {
    printf("NtTib: %p\n", &pTEB->NtTib);
    printf("EnvironmentPointer: %p\n", pTEB->EnvironmentPointer);
    printf("ClientId.UniqueProcess: %p\n", pTEB->ClientId.UniqueProcess);
    printf("ClientId.UniqueThread: %p\n", pTEB->ClientId.UniqueThread);
    printf("ActiveRpcHandle: %p\n", pTEB->ActiveRpcHandle);
    printf("ThreadLocalStoragePointer: %p\n", pTEB->ThreadLocalStoragePointer);
    printf("ProcessEnvironmentBlock: %p\n", pTEB->ProcessEnvironmentBlock);
    printf("LastErrorValue: %u\n", pTEB->LastErrorValue);
    printf("CountOfOwnedCriticalSections: %u\n", pTEB->CountOfOwnedCriticalSections);
    printf("CsrClientThread: %p\n", pTEB->CsrClientThread);
    printf("Win32ThreadInfo: %p\n", pTEB->Win32ThreadInfo);
    printf("User32Reserved: ");
    for (int i = 0; i < 26; i++) {
        printf("%u ", pTEB->User32Reserved[i]);
    }
    printf("\n");
    printf("UserReserved: ");
    for (int i = 0; i < 5; i++) {
        printf("%u ", pTEB->UserReserved[i]);
    }
    printf("\n");
    printf("WOW32Reserved: %p\n", pTEB->WOW32Reserved);
    printf("CurrentLocale: %u\n", pTEB->CurrentLocale);
    printf("FpSoftwareStatusRegister: %u\n", pTEB->FpSoftwareStatusRegister);
    printf("ReservedForDebuggerInstrumentation: ");
    for (int i = 0; i < 16; i++) {
        printf("%p ", pTEB->ReservedForDebuggerInstrumentation[i]);
    }
    printf("\n");
#ifdef _WIN64
    printf("SystemReserved1: ");
    for (int i = 0; i < 30; i++) {
        printf("%p ", pTEB->SystemReserved1[i]);
    }
    printf("\n");
#else
    printf("SystemReserved1: ");
    for (int i = 0; i < 26; i++) {
        printf("%p ", pTEB->SystemReserved1[i]);
    }
    printf("\n");
#endif
    printf("PlaceholderCompatibilityMode: %c\n", pTEB->PlaceholderCompatibilityMode);
    printf("PlaceholderHydrationAlwaysExplicit: %d\n", pTEB->PlaceholderHydrationAlwaysExplicit);
    printf("PlaceholderReserved: ");
    for (int i = 0; i < 10; i++) {
        printf("%c ", pTEB->PlaceholderReserved[i]);
    }
    printf("\n");
    printf("ProxiedProcessId: %u\n", pTEB->ProxiedProcessId);
    printf("ActivationStack: %p\n", &pTEB->ActivationStack);
    printf("WorkingOnBehalfTicket: ");
    for (int i = 0; i < 8; i++) {
        printf("%u ", pTEB->WorkingOnBehalfTicket[i]);
    }
    printf("\n");
    printf("ExceptionCode: %u\n", pTEB->ExceptionCode);
    printf("ActivationContextStackPointer: %p\n", pTEB->ActivationContextStackPointer);
    printf("InstrumentationCallbackSp: %llu\n", pTEB->InstrumentationCallbackSp);
    printf("InstrumentationCallbackPreviousPc: %llu\n", pTEB->InstrumentationCallbackPreviousPc);
    printf("InstrumentationCallbackPreviousSp: %llu\n", pTEB->InstrumentationCallbackPreviousSp);
#ifdef _WIN64
    printf("TxFsContext: %lu\n", pTEB->TxFsContext);
#endif
    printf("InstrumentationCallbackDisabled: %d\n", pTEB->InstrumentationCallbackDisabled);
#ifndef _WIN64
    printf("SpareBytes: ");
    for (int i = 0; i < 23; i++) {
        printf("%u ", pTEB->SpareBytes[i]);
    }
    printf("\n");
    printf("TxFsContext: %lu\n", pTEB->TxFsContext);
    printf("UnalignedLoadStoreExceptions: %d\n", pTEB->UnalignedLoadStoreExceptions);
#endif
    printf("GdiTebBatch: %p\n", &pTEB->GdiTebBatch);
    printf("RealClientId.UniqueProcess: %p\n", pTEB->RealClientId.UniqueProcess); // normally this is the same as ClientId.UniqueProcess
    printf("RealClientId.UniqueThread: %p\n", pTEB->RealClientId.UniqueThread); // normally this is the same as ClientId.UniqueThread
    printf("GdiCachedProcessHandle: %p\n", pTEB->GdiCachedProcessHandle);
    printf("GdiClientPID: %lu\n", pTEB->GdiClientPID);
    printf("GdiClientTID: %lu\n", pTEB->GdiClientTID);
    printf("GdiThreadLocalInfo: %p\n", pTEB->GdiThreadLocalInfo);
    printf("Win32ClientInfo: ");
    for (int i = 0; i < WIN32_CLIENT_INFO_LENGTH; i++) {
        printf("%lu ", (unsigned long)pTEB->Win32ClientInfo[i]);
    }
    printf("\n");
    printf("glDispatchTable: ");
    for (int i = 0; i < 233; i++) {
        printf("%p ", pTEB->glDispatchTable[i]);
    }
    printf("\n");
    printf("glReserved1: ");
    for (int i = 0; i < 29; i++) {
        printf("%llu ", pTEB->glReserved1[i]);
    }
    printf("\n");
    printf("glReserved2: %p\n", pTEB->glReserved2);
    printf("glSectionInfo: %p\n", pTEB->glSectionInfo);
    printf("glSection: %p\n", pTEB->glSection);
    printf("glTable: %p\n", pTEB->glTable);
    printf("glCurrentRC: %p\n", pTEB->glCurrentRC);
    printf("glContext: %p\n", pTEB->glContext);
    printf("LastStatusValue: %u\n", pTEB->LastStatusValue);
    printf("StaticUnicodeString: %p\n", &pTEB->StaticUnicodeString);
    printf("StaticUnicodeBuffer: "); // this might not print any buffer
    for (int i = 0; i < STATIC_UNICODE_BUFFER_LENGTH; i++) {
        printf("%lc ", pTEB->StaticUnicodeBuffer[i]);
    }
    printf("\n");
    printf("DeallocationStack: %p\n", pTEB->DeallocationStack);
    printf("TlsSlots:\n");
    for (int i = 0; i < TLS_MINIMUM_AVAILABLE; i++) {
        void* data_ptr = (void*)pTEB->TlsSlots[i];
        printf("Slot %d: %p\n", i, data_ptr);
    }
    printf("TlsLinks: %p\n", &pTEB->TlsLinks);
    printf("Vdm: %p\n", pTEB->Vdm);
    printf("ReservedForNtRpc: %p\n", pTEB->ReservedForNtRpc);
    printf("DbgSsReserved: ");
    for (int i = 0; i < 2; i++) {
        printf("%p ", pTEB->DbgSsReserved[i]);
    }
    printf("\n");
    printf("HardErrorMode: %lu\n", pTEB->HardErrorMode);
#ifdef _WIN64
    printf("Instrumentation: ");
    for (int i = 0; i < 11; i++) {
        printf("%p ", pTEB->Instrumentation[i]);
    }
    printf("\n");
#else
    printf("Instrumentation: ");
    for (int i = 0; i < 9; i++) {
        printf("%p ", pTEB->Instrumentation[i]);
    }
    printf("\n");
#endif
    char activityIdStr[40] = { 0 };
    GuidToString(&pTEB->ActivityId, activityIdStr);
    printf("ActivityId: %s\n", activityIdStr);    
    printf("SubProcessTag: %p\n", pTEB->SubProcessTag);
    printf("PerflibData: %p\n", pTEB->PerflibData);
    printf("EtwTraceData: %p\n", pTEB->EtwTraceData);
    printf("WinSockData: %p\n", pTEB->WinSockData);
    printf("GdiBatchCount: %lu\n", pTEB->GdiBatchCount);
    if (pTEB->CurrentIdealProcessor.Group != 0 || pTEB->CurrentIdealProcessor.Number != 0 || pTEB->CurrentIdealProcessor.Reserved != 0) {
        printf("CurrentIdealProcessor: Group=%hu, Number=%hhu, Reserved=%hhu\n",
            pTEB->CurrentIdealProcessor.Group, pTEB->CurrentIdealProcessor.Number, pTEB->CurrentIdealProcessor.Reserved);
    }
    else {
        printf("CurrentIdealProcessor: Group=%hu, Number=%hhu, Reserved=%hhu\n",
            pTEB->CurrentIdealProcessor.Group,
            pTEB->CurrentIdealProcessor.Number,
            pTEB->CurrentIdealProcessor.Reserved);
    }
    printf("IdealProcessorValue: %lu\n", pTEB->IdealProcessorValue);
    printf("ReservedPad0: %hhu\n", pTEB->ReservedPad0);
    printf("ReservedPad1: %hhu\n", pTEB->ReservedPad1);
    printf("ReservedPad2: %hhu\n", pTEB->ReservedPad2);
    printf("IdealProcessor: %hhu\n", pTEB->IdealProcessor);
    printf("GuaranteedStackBytes: %lu\n", pTEB->GuaranteedStackBytes);
    printf("ReservedForPerf: %p\n", pTEB->ReservedForPerf);
    printf("ReservedForOle: %p\n", pTEB->ReservedForOle);
    printf("WaitingOnLoaderLock: %lu\n", pTEB->WaitingOnLoaderLock);
    printf("SavedPriorityState: %p\n", pTEB->SavedPriorityState);
    printf("ReservedForCodeCoverage: %llu\n", pTEB->ReservedForCodeCoverage);
    printf("ThreadPoolData: %p\n", pTEB->ThreadPoolData);
    printf("TlsExpansionSlots: %p\n", pTEB->TlsExpansionSlots);
#ifdef _WIN64
    printf("DeallocationBStore: %p\n", pTEB->DeallocationBStore);
    printf("BStoreLimit: %p\n", pTEB->BStoreLimit);
#endif
    printf("MuiGeneration: %lu\n", pTEB->MuiGeneration);
    printf("IsImpersonating: %lu\n", pTEB->IsImpersonating);
    printf("NlsCache: %p\n", pTEB->NlsCache);
    printf("pShimData: %p\n", pTEB->pShimData);
    printf("HeapData: %lu\n", pTEB->HeapData);
    printf("ActiveFrame: %p\n", pTEB->ActiveFrame);
    printf("CurrentTransactionHandle: %p\n", pTEB->CurrentTransactionHandle);
    printf("FlsData: %p\n", pTEB->FlsData);
    printf("PreferredLanguages: %p\n", pTEB->PreferredLanguages);
    printf("UserPrefLanguages: %p\n", pTEB->UserPrefLanguages);
    printf("MergedPrefLanguages: %p\n", pTEB->MergedPrefLanguages);
    printf("MuiImpersonation: %lu\n", pTEB->MuiImpersonation);
    printf("CrossTebFlags: %u\n", pTEB->CrossTebFlags);
    printf("SpareCrossTebBits: %hu\n", pTEB->SpareCrossTebBits);
    printf("SameTebFlags: %u\n", pTEB->SameTebFlags);
    printf("SafeThunkCall: %hu\n", pTEB->SafeThunkCall);
    printf("InDebugPrint: %hu\n", pTEB->InDebugPrint);
    printf("HasFiberData: %hu\n", pTEB->HasFiberData);
    printf("SkipThreadAttach: %hu\n", pTEB->SkipThreadAttach);
    printf("WerInShipAssertCode: %hu\n", pTEB->WerInShipAssertCode);
    printf("RanProcessInit: %hu\n", pTEB->RanProcessInit);
    printf("ClonedThread: %hu\n", pTEB->ClonedThread);
    printf("SuppressDebugMsg: %hu\n", pTEB->SuppressDebugMsg);
    printf("DisableUserStackWalk: %hu\n", pTEB->DisableUserStackWalk);
    printf("RtlExceptionAttached: %hu\n", pTEB->RtlExceptionAttached);
    printf("InitialThread: %hu\n", pTEB->InitialThread);
    printf("SessionAware: %hu\n", pTEB->SessionAware);
    printf("LoadOwner: %hu\n", pTEB->LoadOwner);
    printf("LoaderWorker: %hu\n", pTEB->LoaderWorker);
    printf("SkipLoaderInit: %hu\n", pTEB->SkipLoaderInit);
    printf("SkipFileAPIBrokering: %hu\n", pTEB->SkipFileAPIBrokering);
    printf("TxnScopeEnterCallback: %p\n", pTEB->TxnScopeEnterCallback);
    printf("TxnScopeExitCallback: %p\n", pTEB->TxnScopeExitCallback);
    printf("TxnScopeContext: %p\n", pTEB->TxnScopeContext);
    printf("LockCount: %lu\n", pTEB->LockCount);
    printf("WowTebOffset: %ld\n", pTEB->WowTebOffset);
    printf("ResourceRetValue: %p\n", pTEB->ResourceRetValue);
    printf("ReservedForWdf: %p\n", pTEB->ReservedForWdf);
    printf("ReservedForCrt: %llu\n", pTEB->ReservedForCrt);
    WCHAR guidString[39];
    int result = StringFromGUID2(&pTEB->EffectiveContainerId, guidString, sizeof(guidString) / sizeof(WCHAR));
    if (result > 0) {
        wprintf(L"EffectiveContainerId: %s\n", guidString);
    }
    else if (result == 0) {
        printf("Failed to convert GUID to string: Buffer too small.\n");
    }
    else {
        printf("Failed to convert GUID to string: Unknown error.\n");
    }
    printf("SpinCallCount: %lu\n", pTEB->SpinCallCount);
    printf("ExtendedFeatureDisableMask: %llu\n", pTEB->ExtendedFeatureDisableMask);
}

void EnumerateThreads()
{
    HMODULE hNtdll = LoadLibraryA("ntdll.dll");
    if (hNtdll == NULL) {
        printf("Failed to load ntdll.dll\n");
        return;
    }

    PNT_QUERY_INFORMATION_THREAD pNtQueryInformationThread = (PNT_QUERY_INFORMATION_THREAD)GetProcAddress(hNtdll, "NtQueryInformationThread");
    if (pNtQueryInformationThread == NULL) {
        printf("Failed to get address of NtQueryInformationThread\n");
        FreeLibrary(hNtdll);
        return;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot of threads\n");
        FreeLibrary(hNtdll);
        return;
    }

    THREADENTRY32 te = { 0 };
    te.dwSize = sizeof(THREADENTRY32);
    if (!Thread32First(hSnapshot, &te)) {
        CloseHandle(hSnapshot);
        FreeLibrary(hNtdll);
        return;
    }

    do {
        if (te.dwSize >= FIELD_OFFSET(THREADENTRY32, th32OwnerProcessID) + sizeof(DWORD) &&
            te.th32OwnerProcessID == GetCurrentProcessId()) {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (hThread != NULL) {
                THREAD_BASIC_INFORMATION tbi = { 0 };
                NTSTATUS status = pNtQueryInformationThread(hThread, ThreadBasicInformation, &tbi, sizeof(tbi), NULL);
                if (NT_SUCCESS(status)) {
                    printf("\n");
                    printf("------------------------------------------------------\n");
                    printf("Analyzing Thread id %lu with TEB Address 0x%p\n", te.th32ThreadID, tbi.TebBaseAddress);
                    printf("------------------------------------------------------\n");
                    printf("\n");

                    printTEBFields((PTEB)tbi.TebBaseAddress);
                }
                else {
                    printf("Failed to query information for thread %lu\n", te.th32ThreadID);
                }
                CloseHandle(hThread);
            }
        }
        te.dwSize = sizeof(THREADENTRY32);
    } while (Thread32Next(hSnapshot, &te));

    CloseHandle(hSnapshot);
    FreeLibrary(hNtdll);
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
    UNREFERENCED_PARAMETER(lpReserved);
    UNREFERENCED_PARAMETER(hModule);

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        AllocConsole();

        FILE* pConsoleStream;
        freopen_s(&pConsoleStream, "CONOUT$", "w", stdout);

        EnumerateThreads();

        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        FreeConsole();
        break;
    }
    return TRUE;
}
