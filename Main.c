#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseCryptLib.h>
#include <Library/UefiBootServicesTableLib.h>

#include <sstd.h>
#include <Socket.h>
#include <Mtftp.h>
#include <Main.h>

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
   CHAR8  newBuffer[2048];
   CHAR16 HexBuffer[2048];
   UINT8  Record[128];
   UnicodeStrToAsciiStrS(Buffer, newBuffer, 2048); 
   Status = Sha256CryptoData(newBuffer, HexBuffer, Record); 
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
   UINT32 Nounce1, Nounce3;
   CHAR8 HelloMsg[128];
   CHAR16 PrintBuffer[1024]; 
   CHAR8 *RecvBuffer = (CHAR8*) malloc(1024);

   Status = Connect(WebSocket, IPV4(10,192,13,77), 8000);
   if(EFI_ERROR(Status)){
       Print(L"[Fail] Connect Failure Code: %d\n", Status);
       return Status;
   }

   // Send Hello Msg and Nouce to Server
   Status = GetRandom(&Nounce1);
   AsciiSPrint(HelloMsg, sizeof(HelloMsg), "HelloMsg: %d", Nounce1); 
   Status = Send(WebSocket, HelloMsg, AsciiStrLen(HelloMsg)+3);

   // Staring the while loop 
   // while(1) {
   Status = Recv(WebSocket, RecvBuffer, 1024);
   if(EFI_ERROR(Status)){
       Print(L"[Fail] Recv Failure Code: %d\n", Status);
       return Status;
   }
   
   // Request Cerificate If Recved Auth Invitation 
   if (AsciiStrStr(RecvBuffer, "Invitation") != NULL){
       AsciiPrint("[Info] Recved Auth Invitation\n");

       // Extract the Nounce from Server
       CHAR8* Pointer = AsciiStrStr(RecvBuffer, ":") + 2;
       UINTN Nounce2 = AsciiStrDecimalToUintn(Pointer);
       Print(L"[Info] The Second Nounce from Server: %d\n", Nounce2);

       UINT8* Path = (UINT8*)"cert.pem";
       CHAR16* CertPath = (CHAR16*)L"cert.pem";
       CHAR8* Cert = (CHAR8*)"cert.pem";
       int WebMtftpClient = MtftpClient();
       CHAR8* MtftpBuf = (CHAR8*) malloc(4096);
       VOID* RsaCtx;
       VOID* Data;
       UINTN CertSize = 0;
       UINTN BlockSize = 512;
       BOOLEAN Result = FALSE;

       Status = MtftpConnect(WebMtftpClient, IPV4(10,192,13,77), 0);
       if(EFI_ERROR(Status)){
           Print(L"[Fail] MTFTP Connect Failure Code: %d\n", Status);
           return Status;
       }

       // Get File Info from server
       Status = GetFileSize(WebMtftpClient, Cert, &CertSize);
       if(EFI_ERROR(Status)) CertSize = 1245;
       
       // DownLoad Cert File To Buffer and Dump into File
       Status = DownloadFile (WebMtftpClient, Cert, CertSize, BlockSize, &Data);
       DumpData(Data, CertPath, &CertSize);
       Result = RsaGetPublicKeyFromX509((UINT8*)CertPath, CertSize, &RsaCtx); 
       if (Result) {
           Print(L"[Success] RSA Public Key Retrieved Successfully\n");
       } else {
           Print(L"[Fail] RSA PK Retrieved Failed\n");
       }
        
       // Send Pre Master Key after authticating server identification
       Status = GetRandom(&Nounce3);
       AsciiSPrint(HelloMsg, sizeof(HelloMsg), "Pre Master: %d", Nounce3); 
       Status = Send(WebSocket, HelloMsg, AsciiStrLen(HelloMsg)+3);

       // Generate Session Key using Nounce[0:3]
       UINTN Nounce = (UINTN)Nounce1 + Nounce2 + (UINTN)Nounce3;
       Print(L"[Debug] The Primal Key Material: %d\n", Nounce);

       // Aes-128 Encryption
       ZeroMem(Record, sizeof(Record)); 
       ZeroMem(HelloMsg, sizeof(HelloMsg)); 
       AesCryptoData(Nounce, HelloMsg, Record, sizeof(Record));
       UintToCharSize(Record, 256, HelloMsg);
       AsciiToUnicodeSize(HelloMsg, 1280, PrintBuffer);
       Print(L"\n\n[Debug] Uint Record Conversion: %s", PrintBuffer);
       Status = Send(WebSocket, HelloMsg, AsciiStrLen(HelloMsg)+3);

       // Print Data and Store the cert to file
       Status = Read(WebMtftpClient, Path, MtftpBuf, 4096);
       AsciiToUnicodeSize(MtftpBuf, 1280, PrintBuffer);
       Print(L"[Debug] The Recved MTFTP Msg: %s\n", PrintBuffer);
       UINTN MsgSize = StrLen(PrintBuffer) * 2;
       Status = DumpData(PrintBuffer, (CHAR16*)L"TheRecvedMsg.log", &MsgSize);

       //Status = MtftpClose(WebMtftpClient);
       //if(EFI_ERROR(Status)){
       //    Print(L" FTP Close Failure Code: %d\n", Status);
       //    return Status;
       //}
   }


   AsciiToUnicodeSize(RecvBuffer, 128, PrintBuffer);
   Print(L"The Recved Msg: %s\n", PrintBuffer);

   return Status;
}

