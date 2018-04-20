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

//
// FTP/MTFTP Server IPv4 Address
//
CONST UINT32 ServerAddr = IPV4(10,192,13,82);

//
// The nounce required for session key
//
UINT32 Nounce1, Nounce3;
UINTN  Nounce2, Nounce;

//
// Retrieve PubKey from Der-Coded X509 Cert
//
EFI_STATUS
EFIAPI
RetrieveCertPk(
  IN INT32 MtftpId 
)
{
  EFI_STATUS  Status;
  CHAR8       *Cert = (CHAR8*)"cert.pem";
  CHAR16      *CertPath = (CHAR16*)L"cert.pem";
  VOID        *RsaPubKey;
  VOID        *Data;
  UINTN       CertSize = 0;
  UINTN       BlockSize = 512;
  BOOLEAN     Result = FALSE;

  //
  // Get File Info from server
  //
  Status = GetFileSize(MtftpId, Cert, &CertSize);
  if(EFI_ERROR(Status)) CertSize = 1245;
  
  //
  // DownLoad Cert File To Buffer and Dump into File
  //
  Status = DownloadFile (MtftpId, Cert, CertSize, BlockSize, &Data);
  DumpData(Data, CertPath, &CertSize);
 
  //
  // Read Cert Content and Retrieve Pk
  //
  RsaPubKey = NULL;
  Result = RsaGetPublicKeyFromX509((UINT8*)Data, CertSize, &RsaPubKey); 
  if (Result) {
      Print(L"[Success] RSA Public Key Retrieved Successfully\n");
  } else {
      Print(L"[Fail] RSA PK Retrieved Failed\n");
  }

  return Status;
}

//
// Process Receiced Msg and response to server
//
EFI_STATUS
EFIAPI
RecvMsgProcessing(
  IN INT32 SocketId,
  IN INT32 MtftpId,
  IN CHAR8 *RecvBuffer
)
{
  EFI_STATUS    Status = EFI_SUCCESS;
  UINT8         DecryptData[1024];
  UINTN extern  Nounce;    
  //
  // Case 1: server response from client hello msg
  //
  if (AsciiStrStr(RecvBuffer, "Invitation") != NULL){
     AsciiPrint("[Info] Recved Auth Invitation\n");

     //
     // Extract the Nounce from Server
     //
     UINTN  extern  Nounce2; 
     UINT32 extern  Nounce1, Nounce3; 
     UINT8          Record[128];
     CHAR8          HelloMsg[128];
     CHAR16         PrintBuffer[1024]; 
     CHAR8          *MtftpBuf = (CHAR8*) malloc(4096);
     UINT8          *Path = (UINT8*)"cert.pem";
     CHAR8          *Pointer = AsciiStrStr(RecvBuffer, ":") + 2;

     Nounce2 = AsciiStrDecimalToUintn(Pointer);
     Print(L"[Info] The Second Nounce from Server: %d\n", Nounce2);

     //
     // Connect to the Mtftp Server
     //
     Status = MtftpConnect(MtftpId, ServerAddr, 0);
     if(EFI_ERROR(Status)){
         Print(L"[Fail] MTFTP Connect Failure Code: %d\n", Status);
         return Status;
     }

     Status = RetrieveCertPk(MtftpId); 
     if(EFI_ERROR(Status)){
         Print(L"[Fail] Retrieve Pem Cert Pk Failure Code: %d\n", Status);
         return Status;
     }

     //
     // Send Pre Master Key after authticating server identification
     //
     Status = GetRandom(&Nounce3);
     AsciiSPrint(HelloMsg, sizeof(HelloMsg), "Pre Master: %d", Nounce3); 
     Status = Send(SocketId, HelloMsg, sizeof(HelloMsg)+3);

     //
     // Generate Session Key using Nounce[0:3]
     //
     Nounce = (UINTN)Nounce1 + Nounce2 + (UINTN)Nounce3;
     Print(L"[Debug] The Nounces: %d, %d, %d\n", Nounce1, Nounce2, Nounce3);
     Print(L"[Debug] The Primal Key Material: %d\n", Nounce);

     //
     // Aes-128 Encryption Test: The Aes key is generated from nounce
     //
     ZeroMem(Record, sizeof(Record)); 
     ZeroMem(HelloMsg, sizeof(HelloMsg)); 
     AesCryptoData(Nounce, HelloMsg, Record, sizeof(Record));
     UintToCharSize(Record, 256, HelloMsg);
     Status = Send(SocketId, HelloMsg, sizeof(HelloMsg)+2);

     //
     // Read Data from Mtftp and Store to local file
     //
     Status = Read(MtftpId, Path, MtftpBuf, 4096);
     AsciiToUnicodeSize(MtftpBuf, 1280, PrintBuffer);
     Print(L"[Debug] The Recved MTFTP Msg: %s\n", PrintBuffer);
     UINTN MsgSize = StrLen(PrintBuffer) * 2;
     Status = DumpData(PrintBuffer, (CHAR16*)L"TheRecvedMsg.log", &MsgSize);
  }
  
  //
  // Case2: decrypt data using Aes-128 with session key
  //
  else if (!EFI_ERROR(Status = AesDecryptoData(Nounce, RecvBuffer, DecryptData))){

   Print(L"[INFO] Communicating in Encrypted Mode...\n"); 

  }

  return Status;

}  

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



   //
   // Config and Connect to the TCP/MTFTP Server
   //
   int     WebSocket = Socket();
   int     WebMtftpClient = MtftpClient();
   UINT32  extern Nounce1, Nounce3;
   CHAR8   HelloMsg[128];
   CHAR8   *RecvBuffer = (CHAR8*) malloc(1024);

   Status = Connect(WebSocket, ServerAddr, 8000);
   if(EFI_ERROR(Status)){
       Print(L"[Fail] TCP Connect Failure Code: %d\n", Status);
       return Status;
   }

   //
   // Send Hello Msg and Nouce to Server
   //
   Status = GetRandom(&Nounce1);
   AsciiSPrint(HelloMsg, sizeof(HelloMsg), "HelloMsg: %d", Nounce1); 
   Status = Send(WebSocket, HelloMsg, sizeof(HelloMsg)+3);

   //
   // Staring the while loop 
   //
   while(1) {
     Status = Recv(WebSocket, RecvBuffer, 1024);
     if(EFI_ERROR(Status)){
         Print(L"[Fail] Recv Failure Code: %d\n", Status);
         return Status;
     }
     
     //
     // Recved Msg Processing
     //
     Status = RecvMsgProcessing(WebSocket, WebMtftpClient, RecvBuffer);
     if(!(Status = EFI_SUCCESS)){
         Print(L"[Stop] Recving Loop Stopped : %d\n", Status);
         break;
     }
   }

       //Status = MtftpClose(WebMtftpClient);
       //if(EFI_ERROR(Status)){
       //    Print(L" FTP Close Failure Code: %d\n", Status);
       //    return Status;
       //}

   return Status;
}

