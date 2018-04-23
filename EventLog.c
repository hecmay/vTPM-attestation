#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/BaseLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <Protocol/EfiShell.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/TcgService.h>
#include <IndustryStandard/UefiTcgPlatform.h>


VOID
PrintEventDetail(UINT8 *Detail, UINT32 Size, CHAR16 *TextBuffer)
{
    UINT8 *d = Detail;
    int Offset = 0;
    int Row = 1;

    CHAR16 Convert[128];
    ZeroMem(Convert, sizeof(Convert));
    UnicodeSPrint(Convert, sizeof(Convert), L"   Event Detail: ");
    StrCatS(TextBuffer, 40960, Convert);

    for (int i = 0; i < Size; i++) {
        ZeroMem(Convert, sizeof(Convert));
        UnicodeSPrint(Convert, sizeof(Convert), L"%02x", *d++);
        StrCatS(TextBuffer, 40960, Convert);
        Offset++; Row++;
        if (Row == 17 || Row == 33) {
            ZeroMem(Convert, sizeof(Convert));
            UnicodeSPrint(Convert, sizeof(Convert), L" ");
            StrCatS(TextBuffer, 40960, Convert);
        }
        if (Row > 48) {
           Row = 1;
        }
    }

    StrCatS(TextBuffer, 40960, L"\n");
}


VOID
PrintEventType(UINT32 EventType, BOOLEAN Verbose, CHAR16 *TextBuffer)
{
    CHAR16 Convert[1024];
    ZeroMem(Convert, sizeof(Convert));
    UnicodeSPrint(Convert, sizeof(Convert), L"     Event Type: ");
    
    switch (EventType) {
        case  EV_POST_CODE:                      StrCatS(Convert, 1024, L"Post Code");
                                                 break;
        case  EV_NO_ACTION:                      StrCatS(Convert, 1024, L"No Action");
                                                 break;
        case  EV_SEPARATOR:                      StrCatS(Convert, 1024, L"Separator");
                                                 break;
        case  EV_S_CRTM_CONTENTS:                StrCatS(Convert, 1024, L"CTRM Contents");
                                                 break;
        case  EV_S_CRTM_VERSION:                 StrCatS(Convert, 1024, L"CRTM Version");
                                                 break;
        case  EV_CPU_MICROCODE:                  StrCatS(Convert, 1024, L"CPU Microcode");
                                                 break;
        case  EV_TABLE_OF_DEVICES:               StrCatS(Convert, 1024, L"Table of Devices");
                                                 break;
        case  EV_EFI_VARIABLE_DRIVER_CONFIG:     StrCatS(Convert, 1024, L"Variable Driver Config");
                                                 break;
        case  EV_EFI_VARIABLE_BOOT:              StrCatS(Convert, 1024, L"Variable Boot");
                                                 break;
        case  EV_EFI_BOOT_SERVICES_APPLICATION:  StrCatS(Convert, 1024, L"Boot Services Application");
                                                 break;
        case  EV_EFI_BOOT_SERVICES_DRIVER:       StrCatS(Convert, 1024, L"Boot Services Driver");
                                                 break;
        case  EV_EFI_RUNTIME_SERVICES_DRIVER:    StrCatS(Convert, 1024, L"Runtime Services Driver");
                                                 break;
        case  EV_EFI_GPT_EVENT:                  StrCatS(Convert, 1024, L"GPT Event");
                                                 break;
        case  EV_EFI_ACTION:                     StrCatS(Convert, 1024, L"Action");
                                                 break;
        case  EV_EFI_PLATFORM_FIRMWARE_BLOB:     StrCatS(Convert, 1024, L"Platform Fireware Blob");
                                                 break;
        case  EV_EFI_HANDOFF_TABLES:             StrCatS(Convert, 1024, L"Handoff Tables");
                                                 break;
        case  EV_EFI_VARIABLE_AUTHORITY:         StrCatS(Convert, 1024, L"Variable Authority");
                                                 break;
        default:                                 StrCatS(Convert, 1024, L"Unknown Type");
                                                 break;
    }        
    StrCatS(Convert, 1024, L"\n");
    StrCatS(TextBuffer, 40960, Convert);
}


VOID
PrintSHA1(TCG_DIGEST Digest, CHAR16 *TextBuffer)
{
    CHAR16 Convert[256];
    ZeroMem(Convert, sizeof(Convert));
    UnicodeSPrint(Convert, sizeof(Convert), L"    SHA1 Digest: " );
    StrCatS(TextBuffer, 40960, Convert);

    for (int j = 0; j < SHA1_DIGEST_SIZE; j++ ) {
        ZeroMem(Convert, sizeof(Convert));
        UnicodeSPrint(Convert, sizeof(Convert), L"%02x", Digest.digest[j]);
        StrCatS(TextBuffer, 40960, Convert);
    }

    StrCatS(Convert, 1024, L"\n");
    StrCatS(TextBuffer, 40960, Convert);
}


VOID
PrintLog(
  TCG_PCR_EVENT  *Event, 
  BOOLEAN        Verbose,
  CHAR16         *TextBuffer  
)
{

    CHAR16 Convert[128];
    ZeroMem(Convert, sizeof(Convert));
    UnicodeSPrint(Convert, sizeof(Convert), L"Event PCR Index: %u\n", Event->PCRIndex);
    StrCatS(TextBuffer, 40960, Convert);

    PrintEventType(Event->EventType, Verbose, TextBuffer);
    PrintSHA1(Event->Digest, TextBuffer);

    ZeroMem(Convert, sizeof(Convert));
    UnicodeSPrint(Convert, sizeof(Convert), L"     Event Size: %d\n", Event->EventSize);
    StrCatS(TextBuffer, 40960, Convert);

    if (Verbose) {
        PrintEventDetail(Event->Event, Event->EventSize, TextBuffer);
    }
    StrCatS(TextBuffer, 40960, (CHAR16*)L"\n");
}


EFI_STATUS
GetEventLog(
  IN CHAR16 *TextBuffer
)
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
            PrintLog(Event, Verbose, TextBuffer);
            LogAddress += sizeof(TCG_PCR_EVENT_HDR) + Event->EventSize;
        } while (LogAddress != LogLastEntry);
    }
    PrintLog((TCG_PCR_EVENT *)LogAddress, Verbose, TextBuffer);

    return Status;
}
