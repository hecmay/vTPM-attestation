#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Guid/FileInfo.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/SimpleFileSystem.h>


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

// typedef callback function pointer
typedef VOID (*AccessFileInfo)(EFI_FILE_INFO* FileInfo);

// callback funtion to print out file info
VOID ListFileInfo(EFI_FILE_INFO* FileInfo)
{
    Print(L"Size : %d\nFileSize:%d \nPhysical Size:%d\n",  FileInfo->Size, FileInfo->FileSize, FileInfo->PhysicalSize);
    Print(L"%s\n", FileInfo->FileName);
}

EFI_STATUS
ListDirectory(EFI_FILE_PROTOCOL* Directory, AccessFileInfo Callbk)
{
        UINTN BufferSize;
        UINTN ReadSize;
        EFI_STATUS  Status = 0;
        EFI_FILE_INFO* FileInfo;

        BufferSize = sizeof(EFI_FILE_INFO) + sizeof(CHAR16) * 512;
        Status = gBS->AllocatePool(EfiBootServicesCode, BufferSize, (VOID**)&FileInfo); 
        while(1){
            ReadSize = BufferSize;
            Status = Directory -> Read(Directory, &ReadSize, FileInfo); 
            if(Status == EFI_BUFFER_TOO_SMALL){
                BufferSize = ReadSize;
                Status = gBS -> FreePool(FileInfo);
                if(EFI_ERROR(Status)){
                    Print(L"File Read Directory Error Free: %d\n", Status);
                    break;
                }
                Status = gBS -> AllocatePool( EfiBootServicesCode, BufferSize, (VOID**)&FileInfo); 
                if(EFI_ERROR(Status)){
                    Print(L"File Read Directory Error Allocate: %d\n", Status);
                    break;
                }
                Status = Directory-> Read(Directory, &ReadSize, FileInfo); 
                if(EFI_ERROR(Status)){
                    Print(L"File Read Directory Error Read: %d\n", Status);
                    break;
                }
            }

            if(ReadSize == 0) break;
            if(EFI_ERROR(Status)){
                Print(L"File Read Directory Error: %d\n", Status);
                break;
            }
            Callbk(FileInfo);
        }
        Status = gBS -> FreePool( FileInfo);
        return 0;
}

EFI_STATUS 
GetFileIo( EFI_FILE_PROTOCOL** Root)
{
    EFI_STATUS Status = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *SimpleFileSystem;
    Status = gBS->LocateProtocol(
            &gEfiSimpleFileSystemProtocolGuid,
            NULL,
            (VOID**)&SimpleFileSystem);
    if (EFI_ERROR(Status)) {
        Print(L"Cannot Locate the Simple File System Protocol\n");
        return Status;
    }
    // Get the Handle of the FS Root Directory
    Status = SimpleFileSystem->OpenVolume(SimpleFileSystem, Root);
    return Status;
}

EFI_STATUS
DumpData (
      IN VOID *TextBuffer,
      CONST CHAR16 *Filename,
      IN OUT UINTN *BufSize
      )
{
   //UINTN BufferSize;
   EFI_STATUS Status;
   EFI_FILE_PROTOCOL *Root; // File Handle of the FS Root Directory

   Status = GetFileIo(&Root);   
   if (EFI_ERROR(Status)) {
     Print(L"Failed to Acquire the Root Handle: %d\n", Status);
     return Status;
   }
  
   // Open or Create a new file
   EFI_FILE_PROTOCOL *FileHandle = 0;
   //CHAR16 *Buf = (CHAR16*)L"This is the Content\n";
   Status = Root->Open( Root, 
                        &FileHandle,
                        (CHAR16*)Filename,
                        EFI_FILE_MODE_CREATE | EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                        0);
   
   // Check and write into the file
   CheckStatus(L" EFI_FILE_PROTOCOL Create file \n", Status);
   if (FileHandle && !(EFI_ERROR(Status))) {
     //BufferSize = StrLen(TextBuffer) * 2;
     Status = FileHandle->Write(FileHandle, BufSize, TextBuffer);
     CheckStatus(L" EFI_FILE_PROTOCOL Write file \n ", Status);    
     Status = FileHandle->Close(FileHandle); 
     return Status;
   }
   return EFI_ABORTED;
}

//
// Read Local file Content and Dump to Memeory
//
EFI_STATUS ReadFileToMem (
                      IN OUT CHAR16* Buffer,
                      IN UINTN* BufferSize,
                      IN CHAR16* Filename
                      )
{
    EFI_STATUS  Status = EFI_SUCCESS;
    EFI_FILE_PROTOCOL *Root;
    EFI_FILE_PROTOCOL *SystemFile = 0;

    Status = GetFileIo(&Root);
    Status = Root->Open ( Root,     
                          &SystemFile,
                          (CHAR16*)Filename, 
                          EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE,
                          0);

    Status = SystemFile->Read ( SystemFile,
                                BufferSize,
                                Buffer);
    if(!EFI_ERROR(Status)){
        Print(L"\nFinished Reading Content of %s\n", Filename);
        UINTN Index = (*BufferSize);
        Buffer[Index] = 0;
        Print(L"%d, %s\n", Index, Buffer);
        DumpData(Buffer, (CHAR16*)L"data.log", BufferSize);
    }

    // Test List Directory
    // ListDirectory(Root, ListFileInfo);
    Status = SystemFile->Close(SystemFile);
    return Status;
}

       
