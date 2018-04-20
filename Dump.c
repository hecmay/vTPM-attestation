#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>

// Transmit Passed-in Data to Server
EFI_STATUS TestNetwork (EFI_HANDLE ImageHandle);//, CHAR8 *Buffer);
// Dump the PCR values into the Buffer with Specific Structure && Dump Data into file
EFI_STATUS ExtractPcrValue(CHAR16* Buffer);
// Convert CHAR8 Ascii to CHAR16 Unicode
VOID AsciiToUnicodeSize( CHAR8 *String, UINT8 length, CHAR16 *UniString);
// Encrypt the input Data with SHA256 Alogorithm
EFI_STATUS CryptoData(IN CHAR8 *HashData);
// Test FTP Client
EFI_STATUS TestMtftpConnection (IN EFI_HANDLE ImageHandle);
 

VOID 
CheckStatus (
  IN CHAR16 *Text,
  IN EFI_STATUS Status
  )
{
   if (EFI_ERROR(Status)){
     Print(L"Error Status %d of %s", Status, Text);
   }
   else {
     Print(L"Status Success %d\n", Status);
   }
}

EFI_STATUS
DumpData (
  IN CHAR16 *TextBuffer
  )
{
   UINTN BufferSize;
   EFI_STATUS Status;
   EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
   EFI_FILE_PROTOCOL *Root; // File Handle of the FS Root Directory

   Status = gBS->LocateProtocol( &gEfiSimpleFileSystemProtocolGuid, 
                                 NULL,
                                 (VOID**)&SimpleFileSystem);
   if (EFI_ERROR(Status)) {
     Print(L"Cannot Locate SimpleFileSystem Protocol: %d\n", Status);
     return Status;
   }
   
   // Get the Handle of the FS Root Directory
   Status = SimpleFileSystem->OpenVolume(SimpleFileSystem, &Root);
   if (EFI_ERROR(Status)) {
     Print(L"Failed to acquire the Root Handle: %d\n", Status);
     return Status;
   }
  
   // Open or Create a new file
   EFI_FILE_PROTOCOL *FileHandle = 0;
   //CHAR16 *Buf = (CHAR16*)L"This is the Content\n";
   Status = Root->Open( Root, 
                        &FileHandle,
                        (CHAR16*)L"test.txt",
                        EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                        0);
   
   // Check and write into the file
   CheckStatus(L" EFI_FILE_PROTOCOL Create file \n", Status);
   if (FileHandle && !(EFI_ERROR(Status))) {
     BufferSize = StrLen(TextBuffer) * 2;
     Status = FileHandle->Write(FileHandle, &BufferSize, TextBuffer);
     CheckStatus(L" EFI_FILE_PROTOCOL Write file \n ", Status);    
     Status = FileHandle->Close(FileHandle); 
     return Status;
   }
   return EFI_ABORTED;
}


EFI_STATUS
EFIAPI
ShellAppMain (
  IN UINTN    Argc,
  IN CHAR16   **Argv
  )
{ 
   // Test FileIo Writing
   EFI_STATUS Status;
   CHAR16 *Text = (CHAR16*)L"This is the content\n";
   Status = DumpData(Text);
   if (EFI_ERROR(Status)) {
     Print(L"The Dumping Process Aborted\n");
   }

   // Test Char data extraction 
   CHAR16 Buffer[1024];
   //CHAR16 newBuffer[1024];
   Status = ExtractPcrValue(Buffer);
   if (EFI_ERROR(Status)) {
     Print(L"The Extraction Process Aborted\n");
   }
   else {
     Print(L"Extract Success\n");
     Print(L"Return Result: %s\n", Buffer);
   }
  
   // Test the Cryption
   CHAR8 newBuffer[1024];
   UnicodeStrToAsciiStrS(Buffer, newBuffer, 1024); 
   Status = CryptoData(newBuffer); 
   if (EFI_ERROR(Status)) {
     Print(L"The Encrytion Process Aborted\n");
   }

   Status = TestMtftpConnection (gImageHandle);
   return TestNetwork(gImageHandle);//, Buffer);
}

