#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <stdlib.h>

#include "RuntimeCrypt.h"

//
// Max Known Digest Size is SHA512 Output (64 bytes) by far
//
#define MAX_DIGEST_SIZE    64

//
// Message string for digest validation
//
CHAR8 *HashData = "www.lab-z.com";

extern EFI_BOOT_SERVICES         *gBS;

///
/// Runtime Cryptographic Protocol GUID.
///
EFI_GUID  gEfiRuntimeCryptProtocolGuid =
                {0xe1475e0c, 0x1746, 0x4802, 
                        { 0x86, 0x2e, 0x1, 0x1c, 0x2c, 0x2d, 0x9d, 0x86 }};
int
EFIAPI
main (
  IN int Argc,
  IN CHAR16 **Argv
  )
{
        EFI_RUNTIME_CRYPT_PROTOCOL  *mCryptProtocol = NULL;
        EFI_STATUS                  Status;
        UINT8                       Digest[MAX_DIGEST_SIZE];      
        UINTN    CtxSize;
        VOID     *HashCtx;
        UINTN    DataSize; 
        UINTN    Index;
        
        DataSize = AsciiStrLen (HashData);        
        //
        // Pointer to the runtime cryptographic protocol.
        //
        Status = gBS->LocateProtocol(
                        &gEfiRuntimeCryptProtocolGuid, 
                        NULL, 
                        (VOID **) &mCryptProtocol);
        if (EFI_ERROR(Status)) {
           Print(L"Can't find the runtime cryptographic protocol\n");
           return Status;
        }
        
        Print (L"- SHA256: \n");

        //
        // SHA256 Digest Validation
        //
        ZeroMem (Digest, MAX_DIGEST_SIZE);
        CtxSize = mCryptProtocol->Sha256GetContextSize ();
        HashCtx = AllocatePool (CtxSize);

        Print (L"Init... \n");
        Status  = mCryptProtocol->Sha256Init (HashCtx);
        if (!Status) {
                Print (L"[Fail]\n");
                return EFI_ABORTED;
        }

        Print (L"Update... \n");
        Status  = mCryptProtocol->Sha256Update (HashCtx, HashData, DataSize);
        if (!Status) {
                Print (L"[Fail]\n");
                return EFI_ABORTED;
        }

        Print (L"Finalize... \n");
        Status  = mCryptProtocol->Sha256Final (HashCtx, Digest);
        if (!Status) {
                Print (L"[Fail]\n");
                return EFI_ABORTED;
        }

        for (Index=0;Index<SHA256_DIGEST_SIZE;Index++) {
                Print (L"%2X  ",Digest[Index]);
        }
        Print (L"\n");
        FreePool (HashCtx);

        return EFI_SUCCESS;
}

