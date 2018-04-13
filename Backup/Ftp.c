#include <Uefi.h>
#include <Protocol/Mtftp4.h>
#include <Protocol/ServiceBinding.h>
#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <sstd.h>
#include "Mtftp.h"

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
        Print(L"Failed to Create the MTFTP WriteToken Event: %d\n", Status); 
        return Status;    
    }
    
    // ReadToken Data
    this->ReadToken.Status = EFI_ABORTED;
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->ReadToken, &this->ReadToken.Event);
    if(EFI_ERROR(Status)){
        Print(L"Failed to Create the MTFTP ReadToken Event: %d\n", Status); 
        return Status;    
    }

    // Complete init
    Print(L"\nMTFTP Initiliazation Success\n");
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
        Print(L"Unable to Locate Mtftp4ServiceBindingProtocol\n");
        return (int)Status;
    }

    Status = pMtftpServiceBinding->CreateChild ( pMtftpServiceBinding,
                                               &this->m_MtftpHandle );
    if(EFI_ERROR(Status)){
        Print(L"Unable to create Child for Mtftp Handle\n");
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
        Print(L"Unable to create Child for Mtftp Handle\n");
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

    Print(L"To Cinfig the Data...4\n");
    // StationIp & SubnetMask & GatewayIp need to be set if FALSE
    this->m_pMtftp4ConfigData->UseDefaultSetting = FALSE;
    *(UINT32*)(this->m_pMtftp4ConfigData->StationIp.Addr) = (10 | 192 << 8 | 13 << 16 | 89 << 24);
    *(UINT32*)(this->m_pMtftp4ConfigData->SubnetMask.Addr) = (255 | 255 << 8 | 255 << 16 | 128 << 24);
    *(UINT32*)(this->m_pMtftp4ConfigData->GatewayIp.Addr) = (10 | 192 << 8 | 13 << 16 | 1 << 24);

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
    EFI_STATUS Status = EFI_NOT_FOUND;
    Print(L"Parse the received Packet\n");
    Print(L"Error Code: %d\n", Packet->Error.ErrorCode);
    Print(L"Msg: %a\n", Packet->Error.ErrorMessage[1]);
    return Status;
}

// Called when timeout event is triggered 
EFI_STATUS 
EFIAPI 
myTimeoutCallback(IN EFI_MTFTP4_PROTOCOL *This,
                             IN EFI_MTFTP4_TOKEN *Token)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    Print(L"The MTFTP Transmission is time out %d\n", Token->Status);
    return Status;
} 

EFI_STATUS Write(int sk, UINT8* Path, CHAR8* Data, UINTN Lenth)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    struct MtftpClient* this = MtftpClientfd[sk]; 
    if(this->m_pMtftp4Protocol == NULL) return Status; 

    this->WriteToken.OverrideData = NULL;
    this->WriteToken.Filename = Path;
    this->WriteToken.ModeStr = NULL;
    this->WriteToken.OptionCount = (UINT32)0;
    this->WriteToken.OptionList = NULL;
  
    this->WriteToken.Buffer = (VOID*)Data;
    this->WriteToken.BufferSize = (UINT64)Lenth;

    this->WriteToken.CheckPacket = &CheckCallback;
    this->WriteToken.TimeoutCallback = &myTimeoutCallback;
    this->WriteToken.PacketNeeded = NULL;
    
    Status = this->m_pMtftp4Protocol->WriteFile(this->m_pMtftp4Protocol, &this->WriteToken);
    if(!EFI_ERROR(Status)){
        Print(L"\nWriting Data Now: %d\n", Status);
    }
    
    UINTN index = 0;
    EFI_EVENT myEvent;
    
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 50*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"Wait Status: %d\n", Status);
    Status = this->WriteToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"Writing Data Success: %d\n", Status);
    }
    return Status;
}


EFI_STATUS Read(int sk, UINT8* Path,  CHAR8* Buffer, UINTN Lenth)
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
        Print(L"\nReading Data Now: %d\n", Status);
    }
    
    UINTN index = 0;
    EFI_EVENT myEvent;
    
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, 
             (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 60*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"Wait Status: %d\n", Status);
    Status = this->ReadToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"FTP Read Data Success: %d\n", Status);
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

    // Close the Event created
    if(this->WriteToken.Event)
        gBS->CloseEvent(this->WriteToken.Event);    
    if(this->ReadToken.Event)
        gBS->CloseEvent(this->ReadToken.Event);
    
    // Free the memory allocatino 
    if(this->m_pMtftp4ConfigData){
	free(this->m_pMtftp4ConfigData);
    }
    return Status;
}


//EFI_STATUS MtftpConnect0(int sk)
//{
//    EFI_STATUS Status = EFI_NOT_FOUND;
//    struct MtftpClient* this = MtftpClientfd[sk]; 
//    if(this->m_pMtftp4Protocol == NULL) {
//        Print(L"The FtpClientfd is Null");
//        return Status; 
//    }
//    Status = this->m_pMtftp4Protocol->Connect(this->m_pMtftp4Protocol, &this->ConnectToken);
//    if(EFI_ERROR(Status)){
//        Print(L"FTP Connect0 Error Code: %d\n", Status);
//        return Status;
//    }
//
//    UINTN index = 0;
//    EFI_EVENT myEvent;
//    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
//             (EFI_EVENT_NOTIFY)NULL, (VOID*)NULL, &myEvent);
//    Status = gBS->SetTimer(myEvent, TimerPeriodic, 50*1000*1000);
//    Status = gBS->WaitForEvent(1, &myEvent, &index);
//    Print(L"Wait Status: %d\n", Status);
//    
//    Status = this->ConnectToken.Status;
//    if( !EFI_ERROR(Status)){
//        Print(L"FTP Connect Success: %d\n", Status);
//    }
//    return Status;
//}

// Connect the FTP Server
EFI_STATUS MtftpConnect(int fd, UINT32 Ip32, UINT16 Port)
{
        EFI_STATUS Status;
        Status = MtftpConfig(fd, Ip32, Port);
        if(EFI_ERROR(Status)){
            Print(L"Config Error Code: %d\n", Status);
        }
        else{
            Print(L"Config Sucess Code: %d\n", Status);
        }
	return Status;
}

EFI_STATUS MtftpClose(int sk)
{
	EFI_STATUS Status;
	struct MtftpClient* this = MtftpClientfd[sk]; 
	Status = this->WriteToken.Status;
	Print(L"Close Status %r\n", Status);

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
        "Host:192.168.199.229\nAccept:* / * \n"
        "Connection:Keep-Alive\n\n";
	
        UINT8* Path = (UINT8*)"Efi/Main.efi";
        CHAR16 Buffer[100];
        AsciiToUnicodeSize((CHAR8 *)&(RequestData), 100, Buffer);
	Print(L"\n\nFTP The Request Data: %s\n", Buffer);

	CHAR8 *RecvBuffer = (CHAR8*) malloc(1024);
	int WebMtftpClient = MtftpClient();
	{
		Status = MtftpConnect(WebMtftpClient, IPV4(192,168,199,229), 0);
                if(EFI_ERROR(Status)){
                    Print(L" FTP Connect Failure Code: %d\n", Status);
                    return Status;
                }
		Status = Write(WebMtftpClient, Path, RecvBuffer, sizeof(RecvBuffer));//! length +2
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

