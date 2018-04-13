#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/EfiShell.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/TcgService.h>
#include <IndustryStandard/UefiTcgPlatform.h>


VOID
PrintEventDetail(UINT8 *Detail, UINT32 Size)
{
    UINT8 *d = Detail;
    int Offset = 0;
    int Row = 1;

    Print(L"   Event Detail: %08x: ", Offset);

    for (int i = 0; i < Size; i++) {
        Print(L"%02x", *d++);
        Offset++; Row++;
        if (Row == 17 || Row == 33) {
            Print(L" ");
        }
        if (Row > 48) {
           Row = 1;
           Print(L"\n                 %08x: ", Offset);
        }
    }

    Print(L"\n");
}


VOID
PrintEventType(UINT32 EventType, BOOLEAN Verbose)
{
    Print(L"     Event Type: ");
    if (Verbose) {
        Print(L"%08x ", EventType);
    }
    switch (EventType) {
        case  EV_POST_CODE:                      Print(L"Post Code");
                                                 break;
        case  EV_NO_ACTION:                      Print(L"No Action");
                                                 break;
        case  EV_SEPARATOR:                      Print(L"Separator");
                                                 break;
        case  EV_S_CRTM_CONTENTS:                Print(L"CTRM Contents");
                                                 break;
        case  EV_S_CRTM_VERSION:                 Print(L"CRTM Version");
                                                 break;
        case  EV_CPU_MICROCODE:                  Print(L"CPU Microcode");
                                                 break;
        case  EV_TABLE_OF_DEVICES:               Print(L"Table of Devices");
                                                 break;
        case  EV_EFI_VARIABLE_DRIVER_CONFIG:     Print(L"Variable Driver Config");
                                                 break;
        case  EV_EFI_VARIABLE_BOOT:              Print(L"Variable Boot");
                                                 break;
        case  EV_EFI_BOOT_SERVICES_APPLICATION:  Print(L"Boot Services Application");
                                                 break;
        case  EV_EFI_BOOT_SERVICES_DRIVER:       Print(L"Boot Services Driver");
                                                 break;
        case  EV_EFI_RUNTIME_SERVICES_DRIVER:    Print(L"Runtime Services Driver");
                                                 break;
        case  EV_EFI_GPT_EVENT:                  Print(L"GPT Event");
                                                 break;
        case  EV_EFI_ACTION:                     Print(L"Action");
                                                 break;
        case  EV_EFI_PLATFORM_FIRMWARE_BLOB:     Print(L"Platform Fireware Blob");
                                                 break;
        case  EV_EFI_HANDOFF_TABLES:             Print(L"Handoff Tables");
                                                 break;
        case  EV_EFI_VARIABLE_AUTHORITY:         Print(L"Variable Authority");
                                                 break;
        default:                                 Print(L"Unknown Type");
                                                 break;
    }        
    Print(L"\n");
}


VOID
PrintSHA1(TCG_DIGEST Digest)
{
    Print(L"    SHA1 Digest: " );

    for (int j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
         Print(L"%02x", Digest.digest[j]);
    }

    Print(L"\n");
}


VOID
PrintLog(TCG_PCR_EVENT *Event, BOOLEAN Verbose)
{
    Print(L"Event PCR Index: %u\n", Event->PCRIndex);
    PrintEventType(Event->EventType, Verbose);
    PrintSHA1(Event->Digest);
    Print(L"     Event Size: %d\n", Event->EventSize);
    if (Verbose) {
        PrintEventDetail(Event->Event, Event->EventSize);
    }
    Print(L"\n");
}


EFI_STATUS
GetEventLog(IN CHAR16* Buf)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCG_PROTOCOL *TcgProtocol;   
    EFI_GUID gEfiTcgProtocolGuid = EFI_TCG_PROTOCOL_GUID;

    EFI_PHYSICAL_ADDRESS LogLocation;
    EFI_PHYSICAL_ADDRESS LogLastEntry;
    EFI_PHYSICAL_ADDRESS LogAddress;
    TCG_EFI_BOOT_SERVICE_CAPABILITY BootCapacity;
    TCG_PCR_EVENT *Event = NULL;
    UINT32 FeatureFlag;
    BOOLEAN Verbose = TRUE;

    Status = gBS->LocateProtocol( &gEfiTcgProtocolGuid, 
                                  NULL, 
                                  (VOID **) &TcgProtocol);
    if (EFI_ERROR (Status)) {
        Print(L"Failed to locate EFI_TCG_PROTOCOL [%d]\n", Status);
        return Status;
    }  

    Status = TcgProtocol->StatusCheck( TcgProtocol, 
                                       &BootCapacity,
                                       &FeatureFlag,
                                       &LogLocation,
                                       &LogLastEntry);
    if (EFI_ERROR (Status)) {
        Print(L"ERROR: TcgProtocol StatusCheck Failed [%d]\n", Status);
        return Status;
    }  

    LogAddress = LogLocation;
    if (LogLocation != LogLastEntry) {
        do {
            Event = (TCG_PCR_EVENT *) LogAddress;
            PrintLog(Event, Verbose);
            LogAddress += sizeof(TCG_PCR_EVENT_HDR) + Event->EventSize;
        } while (LogAddress != LogLastEntry);
    }
    PrintLog((TCG_PCR_EVENT *)LogAddress, Verbose);

    return Status;
}
