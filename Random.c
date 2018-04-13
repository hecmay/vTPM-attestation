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

#define NO_RANDOM_BYTES 32 

#pragma pack(1)
typedef struct {
    TPM_RQU_COMMAND_HDR Header;
    UINT32              BytesRequested;
} TPM_COMMAND;


typedef struct {
    TPM_RSP_COMMAND_HDR Header;
    UINT32              RandomBytesSize;
    UINT8               RandomBytes[NO_RANDOM_BYTES];
} TPM_RESPONSE;

#pragma pack()
EFI_STATUS
GetRandom(IN UINT32* Nounce)
{
    EFI_STATUS Status = EFI_SUCCESS;
    EFI_TCG_PROTOCOL *TcgProtocol;
    EFI_GUID gEfiTcgProtocolGuid = EFI_TCG_PROTOCOL_GUID;

    TPM_COMMAND  InBuffer;
    TPM_RESPONSE OutBuffer;
    UINT32       InBufferSize;
    UINT32       OutBufferSize;

    Status = gBS->LocateProtocol( &gEfiTcgProtocolGuid, 
                                  NULL, 
                                  (VOID **) &TcgProtocol);
    if (EFI_ERROR (Status)) {
        Print(L"Failed to locate EFI_TCG_PROTOCOL [%d]\n", Status);
        return Status;
    }  

    InBufferSize = sizeof(TPM_COMMAND);
    OutBufferSize = sizeof(TPM_RESPONSE);

    InBuffer.Header.tag       = SwapBytes16(TPM_TAG_RQU_COMMAND);
    InBuffer.Header.paramSize = SwapBytes32(InBufferSize);
    InBuffer.Header.ordinal   = SwapBytes32(TPM_ORD_GetRandom);
    InBuffer.BytesRequested   = SwapBytes32(NO_RANDOM_BYTES);

    Status = TcgProtocol->PassThroughToTpm( TcgProtocol,
                                            InBufferSize,
                                            (UINT8 *)&InBuffer,
                                            OutBufferSize,
                                            (UINT8 *)&OutBuffer);
    if (EFI_ERROR (Status)) {
        Print(L"ERROR: PassThroughToTpm failed [%d]\n", Status);
        return Status;
    }

    if ((OutBuffer.Header.tag != SwapBytes16 (TPM_TAG_RSP_COMMAND)) || (OutBuffer.Header.returnCode != 0)) {
        Print(L"ERROR: TPM command result [%d]\n", SwapBytes32(OutBuffer.Header.returnCode));
        return EFI_DEVICE_ERROR;
    }

    //Print(L"Number of Random Bytes Requested: %d\n", SwapBytes32(InBuffer.BytesRequested));
    //Print(L" Number of Random Bytes Received: %d\n", RandomBytesSize);
    //Print(L"           Ramdom Bytes Received: ");
    //for (int i = 0; i < RandomBytesSize; i++) {
    //    Print(L"%02x ", OutBuffer.RandomBytes[i]);
    //}
    //Print(L"\n");
    //Print(L"Output Nounce: %d\n", SwapBytes32(*((UINT32*)OutBuffer.RandomBytes)));
    *Nounce = SwapBytes32(*((UINT32*)OutBuffer.RandomBytes));
    return Status;
}
