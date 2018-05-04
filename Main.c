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
// Define the Exchange Mode of Pre-Msater Key (RSA or DH)
//
#define RSA

//
// FTP/MTFTP Server IPv4 Address
//
CONST UINT32 ServerAddr = IPV4(192,168,3,99);

//
// The nounce required for session key
//
UINT32 Nounce1, Nounce3;
UINTN  Nounce2, Nounce;

//
// Rsa Ctx from the X509 Cert
//
VOID *RsaCtx;

//
// Retrieve PubKey from Der-Coded X509 Cert
//
EFI_STATUS
EFIAPI
RetrieveCertPk(
  IN INT32 MtftpId 
)
{
  EFI_STATUS   Status;
  CHAR8        *Cert = (CHAR8*)"crypt_cert.der";
  CHAR16       *CertPath = (CHAR16*)L"crypt_cert.der";
  VOID extern  *RsaCtx;
  VOID         *Data;
  UINTN        CertSize = 0;
  UINTN        BlockSize = 512;
  BOOLEAN      Result = FALSE;

  //
  // Get File Info of DER-coded X509 Cert from server
  //
  Status = GetFileSize(MtftpId, Cert, &CertSize);
  if(EFI_ERROR(Status)) CertSize = 588;
  
  //
  // DownLoad Cert File To Buffer and Dump into File specified by CertPath
  //
  Status = DownloadFile (MtftpId, Cert, CertSize, BlockSize, &Data);
  DumpData(Data, CertPath, &CertSize);
 
  //
  // Read Cert Content and Retrieve Pk
  //
  RsaCtx = NULL;
  Result = RsaGetPublicKeyFromX509((UINT8*)Data, CertSize, &RsaCtx); 
  if (Result) {
      Print(L"[Success] RSA Public Key Retrieved Successfully\n");
      //Status = X509VerifyCert ((UINT8*)Data, CertSize, TestCACert, sizeof (TestCACert));
      //if (EFI_ERROR(Status)) Print(L"[Warning] Cert issued from unrecognized CA\n");
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
  CHAR16        PrintBuffer[1024]; 

  RandomSeed (NULL, 0);

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
    CHAR8          *MtftpBuf = (CHAR8*) malloc(4096);
    UINT8          *Path = (UINT8*)"cert.pem";
    CHAR8          *Pointer = AsciiStrStr(RecvBuffer, ":") + 2;
    
    Nounce2 = AsciiStrDecimalToUintn(Pointer);
    Print(L"[Info] The Second Nounce from Server: %d\n", Nounce2);

    Status = RetrieveCertPk(MtftpId); 
    if(EFI_ERROR(Status)){
        Print(L"[Fail] Retrieve Pem Cert Pk Failure Code: %d\n", Status);
        return Status;
    }

    //
    // Get and Encrypt Pre Master Key after authticating server identification
    //
    Status = GetRandom(&Nounce3);
    AsciiSPrint(HelloMsg, sizeof(HelloMsg), "Pre Master: %d", Nounce3); 
    //Status = Send(SocketId, HelloMsg, sizeof(HelloMsg)+3);

    #ifdef RSA
        //
        // Test: Hash the data and encrypt the diegst with Rsa PubKey for ServerSide Auth
        //
        BOOLEAN      Result;
        VOID extern  *RsaCtx;
        UINT8        Encode[512];
        CHAR8        MasterKey[64];
        CHAR8        RsaMsg[512];
        CHAR16       PrintBuffer[128];

        ZeroMem(Encode, sizeof(Encode));
	ZeroMem(MasterKey, sizeof(MasterKey));
        ZeroMem(PrintBuffer, sizeof(PrintBuffer));
        ZeroMem(RsaMsg, sizeof(RsaMsg));

        AsciiSPrint(MasterKey, 128, "MasterKey: %d", Nounce3);
        Result = RsaEncrypt(RsaCtx, MasterKey, AsciiStrLen(MasterKey), Encode);
        if (!Result) {
          Print(L"[Fail] RSA Encryption Failed\n");
        } else {
          Print(L"\n[Debug] RSA Encryption Result:\n");
          for (int i = 0; i < sizeof(Encode); i++) {
            Print(L"%02x ", Encode[i]);
          }
          Print(L"\n");

          AsciiSPrint(RsaMsg, 512, "==rsa==");
          UintToCharSize(Encode, 512, RsaMsg);
          AsciiToUnicodeSize(RsaMsg, 128, PrintBuffer); 
          Print(L"[Denug] The RsaMsg: %s\n", PrintBuffer);
          Status = Send(SocketId, RsaMsg, sizeof(RsaMsg)+2);
        }
    #else
        //
        // Parameter for DH Pre-Matser Key Exchange
        //
        VOID           *DhCtx;
        UINT8          Prime[64];
        UINT8          PublicKey1[64];
        UINT8          PublicKey2[64];
        UINTN          PublicKey1Length;
        UINTN          PublicKey2Length;
        UINT8          Key1[64];
        UINTN          Key1Length; 
        CHAR8          DhMsg[64];
        BOOLEAN        Result;

        //
        // Diffile-Hellman Key Exchange Configuration with g = 7 and bit(p) = 64
        //
        PublicKey1Length = sizeof(PublicKey1);
        PublicKey2Length = sizeof(PublicKey2);
        Key1Length = sizeof(Key1);
        ZeroMem(DhMsg, sizeof(DhMsg));

        DhCtx = DhNew();
        if (DhCtx == NULL) {
            Print(L"[Fail] Dh Ctx Init Failed\n");
            return EFI_ABORTED;
        }

        Result = DhGenerateParameter (DhCtx, 7, 64, Prime);
        if (!Result) {
            Print(L"[Fail] Dh Set Parameter Failed\n");
            return EFI_ABORTED;
        }

        Result = DhGenerateKey (DhCtx, PublicKey1, &PublicKey1Length);
        if (!Result) {
            Print(L"[Fail] Dh Generate Key Failed\n");
            return EFI_ABORTED;
        }

        Print(L"[debug] The Public Key 1: %d\n", PublicKey1);

        //
        // One more loop to exchange Dh publickey and generate pre-master key
        //
        AsciiSPrint(DhMsg, 128, "Dh Pubkey1: %d", PublickKey1);
        Status = Send(SocketId, DhMsg, AsciiStrLen(DhMsg)+2);
        ZeroMem(RecvBuffer, sizeof(RecvBuffer));
        Status = Recv(WebSocket, RecvBuffer, 1024);

        CHAR8  Clean[64];
        CHAR8  *LenEnd = AsciiStrStr(RecvBuffer, (CHAR8*)"+");
        UINTN  Len = LenEnd - RecvBuffer;
        Print(L"[Debug] The Read-in Len is : %d\n", Len);
        AsciiStrnCpyS(Clean, 128, RecvBuffer, Len);

        //
        // Compute Dh Key (x)^Y mod p with the publickey2 received
        //
        Status = AsciiStrDecimalToUintnS(Clean, NULL, PublickKey2);  
        if (!Status) {
          Print(L"[Fail] Fail to Receive PublicKey2 from Server\n");
          return EFI_ABORTED;
        }
    
        Status = DhComputeKey (DhCtx, PublicKey2, PublicKey2Length, Key1, &Key1Length);
        if (!Status) {
          Print(L"[Fail] Fail to Compute Dh Key\n");
          return EFI_ABORTED;
        }
        Print(L"[Debug] The Dh Key generated: %d\n" Key1);

    #endif

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
  // Case2: decrypt data using Aes-128 with session key and take actions
  //
  else if (!EFI_ERROR(Status = AesDecryptoData(Nounce, RecvBuffer, DecryptData))){

    AsciiToUnicodeSize(RecvBuffer, 1024, PrintBuffer);
    Print(L"\n[INFO] Communicating in Encrypted Mode...\n"); 
    Print(L"[Debug] Encrypted Data from server: %s\n\n", PrintBuffer); 

    //
    // Prepare to send the Pcr Digests
    //
    UINT8   Record[4096];
    CHAR16  Buffer[4096];
    CHAR8   TcpMsg[128];
    UINT8   MsgRecord[128];
    CHAR8   EncryptoData[8192];
    CHAR8   ConvertData[8192];

    ZeroMem(Record, sizeof(Record));
    ZeroMem(Buffer, sizeof(Buffer));
    ZeroMem(TcpMsg, sizeof(TcpMsg));
    ZeroMem(MsgRecord, sizeof(MsgRecord));
    ZeroMem(EncryptoData, sizeof(EncryptoData));
    ZeroMem(ConvertData, sizeof(ConvertData));

    Status = ExtractPcrValue(Buffer);
    if (EFI_ERROR(Status)) {
      Print(L"[Debug] The Extraction Process Aborted\n");
    } else {
      Print(L"[Debug] Extract Success...\n");
      Print(L"[Debug] Return Result:\n %s", Buffer);
    }
    Status = Write(MtftpId, (UINT8*)"PcrValue.log", Buffer, 4096);

    //
    // Inform server with Encrypted Msg using TCP tunnel
    //
    AsciiSPrint(TcpMsg, 128, "[INFO] PCR Sent.");
    AesCryptoData(Nounce, TcpMsg, MsgRecord, sizeof(MsgRecord));
    ZeroMem(TcpMsg, sizeof(TcpMsg));
    AsciiSPrint(TcpMsg, 128, "=====");
    UintToCharSize(MsgRecord, 256, TcpMsg);
    Status = Send(SocketId, TcpMsg, sizeof(TcpMsg)+2);

    //
    // Encrypt the data using Aes-128 algorithm and transmit with TFTP
    //
    UnicodeStrToAsciiStrS(Buffer, EncryptoData, sizeof(EncryptoData));   
    AesCryptoData(Nounce, EncryptoData, Record, sizeof(Record));
    UintToCharSize(Record, 8192, ConvertData); 
    Status = Write(MtftpId, (UINT8*)"EncryptPcr.log", ConvertData, 8192);
    
    //
    // To send the Event Log
    //
    CHAR16  TextBuffer[40960]; 
    ZeroMem(TextBuffer, sizeof(TextBuffer));
    Status = GetEventLog(TextBuffer);
    Print(L"[Debug] The Event Log has been extracted...\n");
    Print(L"[Debug] %s", TextBuffer);
    Status = Write(MtftpId, (UINT8*)"Event.log", TextBuffer, 40960);

    //
    // Inform server with 
    //
    AsciiSPrint(TcpMsg, 128, "[INFO] Event Sent.");
    ZeroMem(MsgRecord, sizeof(MsgRecord));
    AesCryptoData(Nounce, TcpMsg, MsgRecord, sizeof(MsgRecord));
    ZeroMem(TcpMsg, sizeof(TcpMsg));
    AsciiSPrint(TcpMsg, 128, "=====");
    UintToCharSize(MsgRecord, 256, TcpMsg);
    Status = Send(SocketId, TcpMsg, sizeof(TcpMsg)+2);

    Status = EFI_ABORTED;
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
   EFI_STATUS  Status;

   //
   // Test: Read Data from File into Buf and Dump Buffer into data.log
   //
   CHAR16 Buf[20480];
   UINTN BufferSize = 20479;
   CHAR16* File = (CHAR16*)L"Event.log";
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
   // Connect to the Mtftp Server
   //
   Status = MtftpConnect(WebMtftpClient, ServerAddr, 0);
   if(EFI_ERROR(Status)){
       Print(L"[Fail] MTFTP Connect Failure Code: %d\n", Status);
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
     ZeroMem(RecvBuffer, sizeof(RecvBuffer));
     Status = Recv(WebSocket, RecvBuffer, 1024);
     if(EFI_ERROR(Status)){
         Print(L"[Fail] Recv Failure Code: %d\n", Status);
         return Status;
     }
     
     //
     // Recved Msg Processing
     //
     Status = RecvMsgProcessing(WebSocket, WebMtftpClient, RecvBuffer);
     if(!(Status == EFI_SUCCESS)){
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

