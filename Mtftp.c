#include <Uefi.h>
#include <Protocol/Mtftp4.h>
#include <Protocol/ServiceBinding.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <sstd.h>
#include "Mtftp.h"

//
// Frame for the progression slider
//
STATIC CONST CHAR16 mTftpProgressFrame[] = L"[                                        ]";

//
// Number of steps in the progression slider
//
#define TFTP_PROGRESS_SLIDER_STEPS  ((sizeof (mTftpProgressFrame) / sizeof (CHAR16)) - 3)

//
// Msg Size in progression slider
//
#define TFTP_PROGRESS_MESSAGE_SIZE  ((sizeof (mTftpProgressFrame) / sizeof (CHAR16)) + 12)

//
// Manual Configuration for Mtftp Client
//
CONST UINT32 ClientAddr  = IPV4(192,168,199,100);
CONST UINT32 SubMask     = IPV4(255,255,255,0);
CONST UINT32 GateWayAddr = IPV4(192,168,199,1);

typedef struct {
  UINTN  FileSize;
  UINTN  DownloadedNbOfBytes;
  UINTN  LastReportedNbOfBytes;
} DOWNLOAD_CONTEXT;

// Notify When Waiting for Response
extern VOID myEventNotify (IN EFI_EVENT Event, IN VOID *Content);
extern VOID NopNoify (IN EFI_EVENT  Event,  IN VOID *Context);
extern VOID AsciiToUnicodeSize(CHAR8 *String, UINT8 length, CHAR16 *UniString);


struct MtftpClient{
	EFI_HANDLE                       m_MtftpHandle;                   
	EFI_MTFTP4_PROTOCOL*             m_pMtftp4Protocol;
	EFI_MTFTP4_CONFIG_DATA*          m_pMtftp4ConfigData;
	EFI_MTFTP4_TOKEN                 WriteToken, ReadToken;
};

static struct MtftpClient* MtftpClientfd[32];

static EFI_STATUS Initialize(int sk)
{
    EFI_STATUS Status = EFI_SUCCESS;
    struct MtftpClient* this = MtftpClientfd[sk]; 
    // Configure Data
    this->m_pMtftp4ConfigData = (EFI_MTFTP4_CONFIG_DATA*) malloc(sizeof(EFI_MTFTP4_CONFIG_DATA));;

    // Token Data
    this->WriteToken.Status = EFI_ABORTED;
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->WriteToken, &this->WriteToken.Event);
    if(EFI_ERROR(Status)){
        Print(L"[Fail] Failed to Create the MTFTP WriteToken Event [%d]\n", Status); 
        return Status;    
    }
    
    // ReadToken Data
    this->ReadToken.Status = EFI_ABORTED;
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->ReadToken, &this->ReadToken.Event);
    if(EFI_ERROR(Status)){
        Print(L"[Fail] Failed to Create the MTFTP ReadToken Event [%d]\n", Status); 
        return Status;    
    }

    // Complete init
    Print(L"\n[Debug] MTFTP Initiliazation Success\n");
    return Status;
}


int MtftpClient()
{
    EFI_STATUS Status;
    EFI_SERVICE_BINDING_PROTOCOL*  pMtftpServiceBinding;
    struct MtftpClient* this = NULL;

    // Check the availability of positions
    int myfd = -1;
    {
      int i;
      for(i =0; i<32; i++){
        if(MtftpClientfd[i] == NULL){
          MtftpClientfd[i] = this = (struct MtftpClient*) malloc(sizeof(struct MtftpClient));
          myfd = i;
          break;
        }
      }
    }
    if(this == NULL){
        return myfd;
    }
    
    // Create Child and bind its handle with Ftp4Protocol 
    memset((void*)this, 0, sizeof(struct MtftpClient));        
    this->m_MtftpHandle = NULL;
    Status = gBS->LocateProtocol( &gEfiMtftp4ServiceBindingProtocolGuid,
                                  NULL,
                                  (VOID **)&pMtftpServiceBinding);
    if(EFI_ERROR(Status)){
        Print(L"[Fail] Unable to Locate Mtftp4ServiceBindingProtocol\n");
        return (int)Status;
    }

    Status = pMtftpServiceBinding->CreateChild ( pMtftpServiceBinding,
                                               &this->m_MtftpHandle );
    if(EFI_ERROR(Status)){
        Print(L"[Fail] Unable to create Child for Mtftp Handle\n");
        return (int)Status;
    }
          
    // Open the Mtftp4 Protocol on MtftpHandle
    Status = gBS->OpenProtocol ( this->m_MtftpHandle,
                                 &gEfiMtftp4ProtocolGuid,
                                 (VOID **)&this->m_pMtftp4Protocol,
                                 gImageHandle,
                                 this->m_MtftpHandle,
                                 EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL );
    if(EFI_ERROR(Status)){
        Print(L"[Fail] Unable to create Child for Mtftp Handle\n");
        return (int)Status;
    }

    // Initilize the the specific MtftpClient created
    Initialize(myfd);
    return myfd;
}


static EFI_STATUS MtftpConfig(int sk, UINT32 Ip32, UINT16 Port)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    struct MtftpClient* this = MtftpClientfd[sk]; 
    if(this->m_pMtftp4ConfigData == NULL) {
        Print(L"The Config Data is NULL");
        return Status;
    }

    // StationIp & SubnetMask & GatewayIp need to be set if FALSE
    this->m_pMtftp4ConfigData->UseDefaultSetting = FALSE;
    *(UINT32*)(this->m_pMtftp4ConfigData->StationIp.Addr)  = ClientAddr;
    *(UINT32*)(this->m_pMtftp4ConfigData->SubnetMask.Addr) = SubMask;
    *(UINT32*)(this->m_pMtftp4ConfigData->GatewayIp.Addr)  = GateWayAddr;

    this->m_pMtftp4ConfigData->LocalPort = (UINT16)0;

    *(UINT32*)(this->m_pMtftp4ConfigData->ServerIp.Addr) = Ip32;
    this->m_pMtftp4ConfigData->InitialServerPort = (UINT16)69;

    this->m_pMtftp4ConfigData->TryCount = (UINT16)5;
    this->m_pMtftp4ConfigData->TimeoutValue = (UINT16)10;

    Status = this->m_pMtftp4Protocol->Configure(this->m_pMtftp4Protocol, this->m_pMtftp4ConfigData);    
    return Status;
}

EFI_STATUS 
EFIAPI 
CheckCallback(IN EFI_MTFTP4_PROTOCOL *This,
                         IN EFI_MTFTP4_TOKEN *Token,
                         IN UINT16 PacketLen,
                         IN EFI_MTFTP4_PACKET *Packet)
{
    EFI_STATUS Status = EFI_SUCCESS;
    Print(L"[Debug] Parse the received TFTP Packet\n");

    Print(L"\n[Debug] Operation Code: %d\n", Packet->OpCode);
    AsciiPrint("Msg: %s\n", Packet->Wrq.Filename[0]);

    Print(L"\n[Debug] Error [%d] Msg: %s\n", Packet->Error.ErrorCode, Packet->Error.ErrorMessage[0]);
    AsciiPrint("[Debug] Msg: %s\n", Packet->Error.ErrorMessage[0]);
    return Status;
}

// Called when timeout event is triggered 
EFI_STATUS 
EFIAPI 
myTimeoutCallback(IN EFI_MTFTP4_PROTOCOL *This,
                             IN EFI_MTFTP4_TOKEN *Token)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    Print(L"[Error] The MTFTP Transmission is time out %d\n", Token->Status);
    return Status;
} 

EFI_STATUS
GetFileSize (
  IN   int                  sk,
  IN   CONST CHAR8          *FilePath,
  OUT  UINTN                *FileSize
  )
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  struct MtftpClient* this = MtftpClientfd[sk]; 
  if(this->m_pMtftp4Protocol == NULL) return Status; 

  EFI_MTFTP4_OPTION  ReqOpt[1];
  EFI_MTFTP4_PACKET  *Packet;
  UINT32             PktLen;
  EFI_MTFTP4_OPTION  *TableOfOptions;
  EFI_MTFTP4_OPTION  *Option;
  UINT32             OptCnt;
  UINT8              OptBuf[128];

  ReqOpt[0].OptionStr = (UINT8*)"tsize";
  OptBuf[0] = '0';
  OptBuf[1] = 0;
  ReqOpt[0].ValueStr = OptBuf;

  Status = this->m_pMtftp4Protocol->GetInfo (
             this->m_pMtftp4Protocol,
             NULL,
             (UINT8*)FilePath,
             NULL,
             1,
             ReqOpt,
             &PktLen,
             &Packet
             );

  if (EFI_ERROR (Status)) {
    Print(L"\n[Error] Cannot GetInfo from FTP Server: %d\n", Status);
    Print(L"[Debug] Operation Code: %d\n", Packet->OpCode);
    Print(L"[debug] Error [%d]  Msg: %d\n", Packet->Error.ErrorCode, Packet->Error.ErrorMessage[0]);
    goto Error;
  }

  Status = this->m_pMtftp4Protocol->ParseOptions (
             this->m_pMtftp4Protocol,
             PktLen,
             Packet,
             (UINT32 *) &OptCnt,
             &TableOfOptions
             );
  if (EFI_ERROR (Status)) {
    Print(L"[Error] Cannot Parse Option: %d\n", Status);
    goto Error;
  }

  Option = TableOfOptions;
  while (OptCnt != 0) {
    if (AsciiStrnCmp ((CHAR8 *)Option->OptionStr, "tsize", 5) == 0) {
      *FileSize = AsciiStrDecimalToUintn ((CHAR8 *)Option->ValueStr);
      break;
    }
    OptCnt--;
    Option++;
  }
  FreePool (TableOfOptions);

  if (OptCnt == 0) {
    Status = EFI_UNSUPPORTED;
  }

Error :

  return Status;
}


EFI_STATUS
EFIAPI
CheckPacket (
  IN EFI_MTFTP4_PROTOCOL  *This,
  IN EFI_MTFTP4_TOKEN     *Token,
  IN UINT16               PacketLen,
  IN EFI_MTFTP4_PACKET    *Packet
  )
{
  DOWNLOAD_CONTEXT  *Context;
  CHAR16            Progress[TFTP_PROGRESS_MESSAGE_SIZE];
  UINTN             NbOfKb;
  UINTN             Index;
  UINTN             LastStep;
  UINTN             Step;
  EFI_STATUS        Status;

  if ((SwapBytes16 (Packet->OpCode)) != EFI_MTFTP4_OPCODE_DATA) {
    return EFI_SUCCESS;
  }

  Context = (DOWNLOAD_CONTEXT*)Token->Context;
  if (Context->DownloadedNbOfBytes == 0) {
    Print (L"%s       0 Kb\n", mTftpProgressFrame);
  }

  //
  // The data in the packet are prepended with two UINT16 :
  // . OpCode = EFI_MTFTP4_OPCODE_DATA
  // . Block  = the number of this block of data
  //
  Context->DownloadedNbOfBytes += PacketLen - sizeof (Packet->OpCode)
                                            - sizeof (Packet->Data.Block);
  NbOfKb = Context->DownloadedNbOfBytes / 1024;

  Progress[0] = L'\0';
  LastStep  = (Context->LastReportedNbOfBytes * TFTP_PROGRESS_SLIDER_STEPS) / Context->FileSize;
  Step      = (Context->DownloadedNbOfBytes * TFTP_PROGRESS_SLIDER_STEPS) / Context->FileSize;

  if (Step <= LastStep) {
    return EFI_SUCCESS;
  }

  //Print(L"%s", mTftpProgressDelete);

  Status = StrCpyS (Progress, TFTP_PROGRESS_MESSAGE_SIZE, mTftpProgressFrame);
  if (EFI_ERROR(Status)) {
    return Status;
  }
  for (Index = 1; Index < Step; Index++) {
    Progress[Index] = L'=';
  }
  Progress[Step] = L'>';

  UnicodeSPrint (
    Progress + (sizeof (mTftpProgressFrame) / sizeof (CHAR16)) - 1,
    sizeof (Progress) - sizeof (mTftpProgressFrame),
    L" %7d Kb",
    NbOfKb
    );
  Context->LastReportedNbOfBytes = Context->DownloadedNbOfBytes;

  Print(L"%s\n", Progress);

  return EFI_SUCCESS;
}


EFI_STATUS
DownloadFile (
  IN   int                  sk,
  IN   CONST CHAR8          *AsciiFilePath,
  IN   UINTN                FileSize,
  IN   UINT16               BlockSize,
  OUT  VOID                 **Data
  )
{
  EFI_STATUS Status = EFI_NOT_FOUND;
  struct MtftpClient* this = MtftpClientfd[sk]; 
  if(this->m_pMtftp4Protocol == NULL) return Status; 

  EFI_PHYSICAL_ADDRESS  PagesAddress;
  VOID                  *Buffer;
  DOWNLOAD_CONTEXT      *TftpContext;
  EFI_MTFTP4_TOKEN      Mtftp4Token;
  EFI_MTFTP4_OPTION     ReqOpt;
  UINT8                 OptBuf[10];

  Status = gBS->AllocatePages (
                   AllocateAnyPages,
                   EfiBootServicesCode,
                   EFI_SIZE_TO_PAGES (FileSize),
                   &PagesAddress
                   );
  if (EFI_ERROR (Status)) {
    return Status;
  }

  Buffer = (VOID*)(UINTN)PagesAddress;
  TftpContext = AllocatePool (sizeof (DOWNLOAD_CONTEXT));
  if (TftpContext == NULL) {
    Status = EFI_OUT_OF_RESOURCES;
    goto Error;
  }
  TftpContext->FileSize = FileSize;
  TftpContext->DownloadedNbOfBytes   = 0;
  TftpContext->LastReportedNbOfBytes = 0;

  ZeroMem (&Mtftp4Token, sizeof (EFI_MTFTP4_TOKEN));
  Mtftp4Token.Filename    = (UINT8*)AsciiFilePath;
  Mtftp4Token.BufferSize  = FileSize;
  Mtftp4Token.Buffer      = Buffer;
  Mtftp4Token.CheckPacket = CheckPacket;
  Mtftp4Token.Context     = (VOID*)TftpContext;
  if (BlockSize != 512) {
    ReqOpt.OptionStr = (UINT8 *) "blksize";
    AsciiSPrint ((CHAR8 *)OptBuf, sizeof (OptBuf), "%d", BlockSize);
    ReqOpt.ValueStr  = OptBuf;

    Mtftp4Token.OptionCount = 1;
    Mtftp4Token.OptionList  = &ReqOpt;
  }

  Status = this->m_pMtftp4Protocol->ReadFile (this->m_pMtftp4Protocol, &Mtftp4Token);

Error :

  if (TftpContext == NULL) {
    FreePool (TftpContext);
  }

  if (EFI_ERROR (Status)) {
    gBS->FreePages (PagesAddress, EFI_SIZE_TO_PAGES (FileSize));
    return Status;
  }

  *Data = Buffer;
  Print(L"[Info] DownLoad Data Successfully\n");
  return EFI_SUCCESS;
}


EFI_STATUS Write(int sk, UINT8* Path, VOID* Data, UINTN Lenth)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    struct MtftpClient* this = MtftpClientfd[sk]; 
    if(this->m_pMtftp4Protocol == NULL) return Status; 

    this->WriteToken.OverrideData = NULL;
    this->WriteToken.Filename = Path;
    this->WriteToken.ModeStr = (UINT8*)"netascii";
    this->WriteToken.OptionCount = (UINT32)0;
    this->WriteToken.OptionList = NULL;
  
    this->WriteToken.Buffer = (VOID*)Data;
    this->WriteToken.BufferSize = (UINT64)Lenth;

    this->WriteToken.CheckPacket = &CheckCallback;
    this->WriteToken.TimeoutCallback = &myTimeoutCallback;
    this->WriteToken.PacketNeeded = NULL;
    
    Status = this->m_pMtftp4Protocol->WriteFile(this->m_pMtftp4Protocol, &this->WriteToken);
    if(!EFI_ERROR(Status)){
        Print(L"\n[Debug] Writing Data Now [%d]\n", Status);
    }
    
    UINTN index = 0;
    EFI_EVENT myEvent;
    
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 50*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"[Debug] Wait Status [%d]\n", Status);
    Status = this->WriteToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"[Debug] Writing Data Success [%d]\n", Status);
    }
    return Status;
}


EFI_STATUS Read(int sk, UINT8* Path,  VOID* Buffer, UINTN Lenth)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    struct MtftpClient* this = MtftpClientfd[sk]; 
    if(this->m_pMtftp4Protocol == NULL) return Status;

    this->ReadToken.OverrideData = NULL;
    this->ReadToken.Filename = Path;
    this->ReadToken.ModeStr = NULL;

    this->ReadToken.OptionCount = 0;
    this->ReadToken.OptionList = NULL;
    this->ReadToken.BufferSize = (UINT64)Lenth;
    this->ReadToken.Buffer = (VOID*)Buffer;

    Status = this->m_pMtftp4Protocol->ReadFile(this->m_pMtftp4Protocol, &this->ReadToken);
    if( !EFI_ERROR(Status)){
        Print(L"\n[Debug] Reading Data Now [%d]\n", Status);
    }
    
    UINTN index = 0;
    EFI_EVENT myEvent;
    
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, 
             (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 50*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"[Debug] Wait Status [%d]\n", Status);
    Status = this->ReadToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"[Debug] FTP Read Data Success [%d]\n", Status);
    }
    return Status;
}


static int Destroy(int sk)
{
    EFI_STATUS Status;
    struct MtftpClient* this = MtftpClientfd[sk]; 
    if(this->m_MtftpHandle){
        EFI_SERVICE_BINDING_PROTOCOL*  pMtftpServiceBinding;
        Status = gBS->LocateProtocol ( &gEfiMtftp4ServiceBindingProtocolGuid,
                                       NULL, (VOID **)&pMtftpServiceBinding );
        Status = pMtftpServiceBinding->DestroyChild ( pMtftpServiceBinding,
                                                    this->m_MtftpHandle );
    }

    //
    // Close the Event created
    //
    if(this->WriteToken.Event)
        gBS->CloseEvent(this->WriteToken.Event);    
    if(this->ReadToken.Event)
        gBS->CloseEvent(this->ReadToken.Event);
    
    //
    // Free the memory allocatino 
    //
    if(this->m_pMtftp4ConfigData){
	free(this->m_pMtftp4ConfigData);
    }
    return Status;
}


//
// Connect the FTP Server
//
EFI_STATUS MtftpConnect(int fd, UINT32 Ip32, UINT16 Port)
{
        EFI_STATUS Status;
        Status = MtftpConfig(fd, Ip32, Port);
        if(EFI_ERROR(Status)){
            Print(L"[Debug] MTFTP Config Error [%d]\n", Status);
        }
        else{
            Print(L"[Info] MTFTP Config Sucess [%d]\n", Status);
        }
	return Status;
}


EFI_STATUS MtftpClose(int sk)
{
	EFI_STATUS Status;
	struct MtftpClient* this = MtftpClientfd[sk]; 
	Status = this->WriteToken.Status;
	Print(L"[Debug] Close Status [%r]\n", Status);

	Destroy(sk);
	free(this);
	MtftpClientfd[sk] = NULL;

	return Status;

}

EFI_STATUS TestMtftpConnection (IN EFI_HANDLE ImageHandle)
{
	EFI_STATUS Status = 0;
	CHAR8 RequestData[]=  
    "POST / HTTP/1.1\n"
        "Host:10.192.13.89\nAccept:* / * \n"
        "Connection:Keep-Alive\n\n";
	
        UINT8* Path = (UINT8*)"data.log";
        CHAR16 Buffer[100];
        AsciiToUnicodeSize((CHAR8 *)&(RequestData), 100, Buffer);
	Print(L"\n\nFTP The Request Data: %s\n", Buffer);

	CHAR8 *RecvBuffer = (CHAR8*) malloc(1024);
	int WebMtftpClient = MtftpClient();
	{
		Status = MtftpConnect(WebMtftpClient, IPV4(10,192,13,89), 0);
                if(EFI_ERROR(Status)){
                    Print(L" FTP Connect Failure Code: %d\n", Status);
                    return Status;
                }
		Status = Write(WebMtftpClient, Path, RequestData, sizeof(RequestData));//! length +2
                if(EFI_ERROR(Status)){
                    Print(L" FTP Write Failure Code: %d\n", Status);
                    return Status;
                }
		Status = Read(WebMtftpClient, Path, RecvBuffer, 1024);
                if(EFI_ERROR(Status)){
                    Print(L" FTP Read Failure Code: %d\n", Status);
                    return Status;
                }
		Status = MtftpClose(WebMtftpClient);
                if(EFI_ERROR(Status)){
                    Print(L" FTP Close Failure Code: %d\n", Status);
                    return Status;
                }
	}
        CHAR16 newBuffer[100];
        AsciiToUnicodeSize((CHAR8 *)RecvBuffer, sizeof(newBuffer), newBuffer);
	Print(L"\nThe Recved Data: %s\n", newBuffer);
	Print(L"FTP Sent Data Size: %d\n Recved Data Size: %d\n", sizeof(Buffer), sizeof(RecvBuffer));
	free(RecvBuffer);
        Print(L"Free the Received Buffer\n");
	return Status;
}

