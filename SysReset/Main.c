#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

#include <Protocol/EfiShell.h>
#include <Protocol/LoadedImage.h>

INTN
EFIAPI
ShellAppMain (
          IN UINTN    Argc,
          IN CHAR16   **Argv
          )
{
    EFI_STATUS  Status = EFI_SUCCESS;
    gRT->ResetSystem(EfiResetCold, EFI_SUCCESS, 0, NULL);    
    return Status;
}

