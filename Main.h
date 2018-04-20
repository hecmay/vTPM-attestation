#ifndef __MAIN_HEADER__
#define __MAIN_HEADER__
#ifdef __cplusplus
extern "C"{
#endif
#include <Uefi.h>

// Transmit Passed-in Data to Server
EFI_STATUS TestNetwork (EFI_HANDLE ImageHandle);//, CHAR8 *Buffer);

// Dump the PCR values into the Buffer with Specific Structure && Dump Data into file
EFI_STATUS ExtractPcrValue(CHAR16* Buffer);

// Convert CHAR8 Ascii to CHAR16 Unicode
VOID AsciiToUnicodeSize( CHAR8 *String, UINT32 length, CHAR16 *UniString);

// Convert UINT8 Ascii to CHAR8 Unicode
VOID UintToCharSize( UINT8 *UintStr, UINT32 length, CHAR8 *CharStr);

// Encrypt the input Data with SHA256 Alogorithm
EFI_STATUS Sha256CryptoData(IN CHAR8 *HashData, OUT CHAR16 *Buffer, OUT UINT8 *Record);

// Encrypt the input Data with AES-128 Alogorithm CBC Mode
EFI_STATUS AesCryptoData(IN UINT64 Material, IN CHAR8 *CryptData, OUT UINT8 *RsaBuf, IN UINTN Size);

// Decrypt the input Data with AES-128 Alogorithm CBC Mode
EFI_STATUS AesDecryptoData(IN UINT64 Nounce, IN CHAR8 *RecvBuffer, OUT UINT8 *DecrptData);

// Test FTP Client
EFI_STATUS TestMtftpConnection (IN EFI_HANDLE ImageHandle);
 
// Dump data into certain file
EFI_STATUS DumpData(IN VOID *TextBuffer, CONST CHAR16 *Filename, IN OUT UINTN *BufSize);

// Read the content of certain file into memory
EFI_STATUS ReadFileToMem(IN OUT CHAR16* Buffer, IN UINTN* BufferSize, IN CHAR16* Filename);

// Get a nouce from the TPM 1.2
EFI_STATUS GetRandom(IN UINT32* Nounce);

// Retrieve Event Log List and Dump to Buffer
EFI_STATUS GetEventLog(IN CHAR16 *TextBuffer);

// Get the File Size from the FTP server
EFI_STATUS GetFileSize (IN int sk, IN CONST CHAR8 *FilePath, OUT UINTN *FileSize);

// DownLoad FTP Server File to Buffer
EFI_STATUS DownloadFile (
  IN   int                  sk, 
  IN   CONST CHAR8          *AsciiFilePath, 
  IN   UINTN                FileSize,
  IN   UINT16               BlockSize,
  OUT  VOID                 **Data
);

#ifdef __cplusplus
}
#endif
#endif
