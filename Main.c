#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <sstd.h>
#include <Socket.h>
#include <Mtftp.h>
int MtftpClient();
EFI_STATUS MtftpConnect(int fd, UINT32 Ip32, UINT16 Port);
EFI_STATUS Write(int fd, UINT8* Path, CHAR8* Data, UINTN Lenth);
EFI_STATUS Read(int fd, UINT8* Path, CHAR8* Buffer, UINTN Lenth);
EFI_STATUS MtftpClose(int fd);

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
 
//Dump data into certain file
EFI_STATUS DumpData(IN VOID *TextBuffer, CONST CHAR16 *Filename, IN OUT UINTN *BufSize);
//Read the content of certain file into memory
EFI_STATUS ReadFileToMem(IN OUT CHAR16* Buffer, IN UINTN* BufferSize, IN CHAR16* Filename);
//Get a nouce from the TPM 1.2
EFI_STATUS GetRandom(IN UINT32* Nounce);
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

EFI_STATUS
EFIAPI
ShellAppMain (
          IN UINTN    Argc,
          IN CHAR16   **Argv
          )
{ 
   EFI_STATUS Status;
   // Test Char data extraction 
   CHAR16 Buffer[4096];
   //CHAR16 newBuffer[1024];
   Status = ExtractPcrValue(Buffer);
   if (EFI_ERROR(Status)) {
     Print(L"The Extraction Process Aborted\n");
   }
   else {
     Print(L"Extract Success\n");
     Print(L"Return Result:\n %s", Buffer);
   }
  
   // Test the Cryption
   CHAR8 newBuffer[2048];
   UnicodeStrToAsciiStrS(Buffer, newBuffer, 2048); 
   Status = CryptoData(newBuffer); 
   if (EFI_ERROR(Status)) {
     Print(L"The Encrytion Process Aborted\n");
   }

   CHAR16 Buf[20480];
   UINTN BufferSize = 20479;
   CHAR16* File = (CHAR16*)L"Event.log";
   
   // Read Data from File into Buf and Dump Buffer into data.log
   Status = ReadFileToMem(Buf, &BufferSize, File);



   
   // Config and Connect to the Server
   int WebSocket = Socket();
   UINT32 Nounce1;
   CHAR8 HelloMsg[128];
   CHAR16 PrintBuffer[1024]; 
   CHAR8 *RecvBuffer = (CHAR8*) malloc(1024);

   Status = Connect(WebSocket, IPV4(10,192,13,79), 8000);
   if(EFI_ERROR(Status)){
       Print(L" Connect Failure Code: %d\n", Status);
       return Status;
   }

   // Send Hello Msg and Nouce to Server
   Status = GetRandom(&Nounce1);
   AsciiSPrint(HelloMsg, sizeof(HelloMsg), "HelloMsg: %d", Nounce1); 
   Status = Send(WebSocket, HelloMsg, AsciiStrLen(HelloMsg)+3);

   Status = Recv(WebSocket, RecvBuffer, 1024);
   if(EFI_ERROR(Status)){
       Print(L" Recv Failure Code: %d\n", Status);
       return Status;
   }
   
   // Request Cerificate If Recved Auth Invitation 
   if (AsciiStrStr(RecvBuffer, "Invitation") != NULL){
       AsciiPrint("Recved Auth Invitation\n");

       UINT8* Path = (UINT8*)"cert.pem";
       CHAR16* CertPath = (CHAR16*)L"cert.pem";
       CHAR8* Cert = (CHAR8*)"cert.pem";
       int WebMtftpClient = MtftpClient();
       CHAR8* MtftpBuf = (CHAR8*) malloc(20480);
       VOID* RsaCtx;
       VOID* Data;
       UINTN CertSize = 0;
       UINTN BlockSize = 512;
       BOOLEAN Result = FALSE;

       Status = MtftpConnect(WebMtftpClient, IPV4(10,192,13,79), 0);
       if(EFI_ERROR(Status)){
           Print(L" MTFTP Connect Failure Code: %d\n", Status);
           return Status;
       }

       // Get File Info from server
       Status = GetFileSize(WebMtftpClient, Cert, &CertSize);
       if(EFI_ERROR(Status)) CertSize = 3115;
       
       // DownLoad File To Buffer
       Status = DownloadFile (WebMtftpClient, Cert, CertSize, BlockSize, &Data);
       DumpData(Data, CertPath, &CertSize);
       Result = RsaGetPublicKeyFromX509((UINT8*)CertPath, CertSize, &RsaCtx); 
       if (Result) {
           Print(L"RSA Private Key Retrieved Successfully\n");
       } else {
           Print(L"RSA PK Retrieved Failed\n");
       }
       
       // Print Data and Store the cert to file
       Status = Read(WebMtftpClient, Path, MtftpBuf, 20480);
       AsciiToUnicodeSize(MtftpBuf, 128, PrintBuffer);
       Print(L"The Recved MTFTP Msg: %s\n", PrintBuffer);
       UINTN MsgSize = StrLen(PrintBuffer) * 2;
       Status = DumpData(PrintBuffer, (CHAR16*)L"TheRecvedMsg.log", &MsgSize);

       Status = MtftpClose(WebMtftpClient);
       if(EFI_ERROR(Status)){
           Print(L" FTP Close Failure Code: %d\n", Status);
           return Status;
       }
   }


   AsciiToUnicodeSize(RecvBuffer, 128, PrintBuffer);
   Print(L"The Recved Msg: %s\n", PrintBuffer);

   return Status;
}

