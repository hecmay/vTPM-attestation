#ifdef __cplusplus
extern "C"{
#endif
#include <Uefi.h>
#include <Protocol/Tcp4.h>
#include <Protocol/ServiceBinding.h>
#include <Library/UefiLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/ShellLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <sstd.h>
#include <Socket.h>
#ifdef __cplusplus
}
#endif

#define SocketWait(e)     {\
	UINTN index = 0;\
	Status = gBS->WaitForEvent(1, &(e), &index); \
	Print(L"Wait Status Code: %d\n", Status); \
}

#ifdef __cplusplus
class Socket
{
	public:
		Socket();
		~Socket();   

		SOCKET_STATUS Connect(UINT32 Ip32, UINT16 Port){Config(Ip32, Port); reuturn Connect();};

		SOCKET_STATUS Send(CHAR8* Data, UINTN Lenth);
		SOCKET_STATUS Recv(CHAR8* Buffer, UINTN Lenth);
		SOCKET_STATUS Close();
	private:
		SOCKET Initialize();
		SOCKET_STATUS Config(UINT32 Ip32, UINT16 Port);
		SOCKET_STATUS Connect();
	private:
#else
		struct Socket{
#endif
		EFI_HANDLE                     m_SocketHandle;                   
		EFI_TCP4_PROTOCOL*             m_pTcp4Protocol;
		EFI_TCP4_CONFIG_DATA*          m_pTcp4ConfigData;
		EFI_TCP4_TRANSMIT_DATA*        m_TransData;
		EFI_TCP4_RECEIVE_DATA*         m_RecvData; 
		EFI_TCP4_CONNECTION_TOKEN      ConnectToken;
		EFI_TCP4_CLOSE_TOKEN           CloseToken;
		EFI_TCP4_IO_TOKEN              SendToken, RecvToken;
};

static struct Socket* Socketfd[32];

// Notify When Waiting for Response
VOID myEventNotify (IN EFI_EVENT Event, IN VOID *Content) {     
    static UINTN times = 0;
    Print(L"[INFO] myEventNotify signal: %d\n", times);
    EFI_STATUS Status = (EFI_STATUS)*((EFI_STATUS *)(Content));
    if (Status == EFI_SUCCESS || times > 200){
        Print(L"Sucess Event: %r\n", Status);
        gBS->SignalEvent(Event);
    } else {
        Print(L"The Status is: %r\n", Status);
    }
    times++;    
}

VOID NopNoify (  IN EFI_EVENT  Event,  IN VOID *Context  )
{
}

//SOCKET_STATUS Socket::Initialize()
static SOCKET_STATUS Initialize(int sk)
{
    EFI_STATUS                           Status = EFI_SUCCESS;
    struct Socket* this = Socketfd[sk]; 
    // Configure Data
    this->m_pTcp4ConfigData = (EFI_TCP4_CONFIG_DATA*) malloc(sizeof(EFI_TCP4_CONFIG_DATA));;
    // Connect Data
    this->ConnectToken.CompletionToken.Status = EFI_ABORTED;
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->ConnectToken, &this->ConnectToken.CompletionToken.Event );
    if(EFI_ERROR(Status)){
        Print(L"Failed to Create the Connection Event: %d\n", Status); 
        return Status;    
    }
    // Transmit Data
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->SendToken, &this->SendToken.CompletionToken.Event);
    if(EFI_ERROR(Status)) {
        Print(L"Failed to Create Send Event: %d\n", Status);
        return Status; 
    }
    this->SendToken.CompletionToken.Status  =EFI_ABORTED; 
    this->m_TransData = (EFI_TCP4_TRANSMIT_DATA*)malloc(sizeof(EFI_TCP4_TRANSMIT_DATA));;
    // Recv Data
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->RecvToken, &this->RecvToken.CompletionToken.Event);
    if(EFI_ERROR(Status)){
        Print(L"Failed to Create the Recv Event: %d\n", Status); 
        return Status;    
    }
    this->RecvToken.CompletionToken.Status  =EFI_ABORTED;
    this->m_RecvData = (EFI_TCP4_RECEIVE_DATA*) malloc(sizeof(EFI_TCP4_RECEIVE_DATA));;
// Close Data
    this->CloseToken.CompletionToken.Status = EFI_ABORTED;
    Status = gBS->CreateEvent(EVT_NOTIFY_SIGNAL, TPL_CALLBACK, (EFI_EVENT_NOTIFY)NopNoify , (VOID*)&this->CloseToken, &this->CloseToken.CompletionToken.Event );
    if(EFI_ERROR(Status)){
        Print(L"Failed to Create the Connection Event: %d\n", Status); 
        return Status;    
    }
    Print(L"\nInitiliazation Success\n");
    return Status;
}
//Socket::Socket()
int Socket()
{
    EFI_STATUS                           Status;
    EFI_SERVICE_BINDING_PROTOCOL*  pTcpServiceBinding;
    struct Socket* this = NULL;
    int myfd = -1;
    {
	    int i;
	    for(i =0;i<32; i++){
		    if(Socketfd[i] == NULL){
			    Socketfd[i] = this = ( struct Socket*) malloc(sizeof(struct Socket));
			    myfd = i;
			    break;
		    }
	    }
    }
    if(this == NULL){
        return myfd;
    }
    memset((void*)this, 0, sizeof(struct Socket));        
    this->m_SocketHandle              = NULL;
    Status = gBS->LocateProtocol ( &gEfiTcp4ServiceBindingProtocolGuid,
        NULL,
        (VOID **)&pTcpServiceBinding );
    if(EFI_ERROR(Status))
        return (int)Status;

    Status = pTcpServiceBinding->CreateChild ( pTcpServiceBinding,
        &this->m_SocketHandle );
    if(EFI_ERROR(Status))
        return (int)Status;

    Status = gBS->OpenProtocol ( this->m_SocketHandle,
        &gEfiTcp4ProtocolGuid,
        (VOID **)&this->m_pTcp4Protocol,
        gImageHandle,
        this->m_SocketHandle,
        EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL );
    if(EFI_ERROR(Status))
         return (int)Status;
    Initialize(myfd);
    return myfd;
}

//SOCKET_STATUS Socket::Config(UINT32 Ip32, UINT16 Port)
static SOCKET_STATUS Config(int sk, UINT32 Ip32, UINT16 Port)
{
    EFI_STATUS                           Status = EFI_NOT_FOUND;
    struct Socket* this = Socketfd[sk]; 
    if(this->m_pTcp4ConfigData == NULL) return Status;
    this->m_pTcp4ConfigData->TypeOfService = 0;
    this->m_pTcp4ConfigData->TimeToLive = 16;    
    *(UINTN*)(this->m_pTcp4ConfigData->AccessPoint.RemoteAddress.Addr) = Ip32;
    this->m_pTcp4ConfigData->AccessPoint.RemotePort = Port;
    *(UINT32*)(this->m_pTcp4ConfigData->AccessPoint.SubnetMask.Addr) = (255 | 255 << 8 | 255 << 16 | 0 << 24) ;

    this->m_pTcp4ConfigData->AccessPoint.UseDefaultAddress = TRUE;
    /// If UseDefaultAddress = FALSE, StationAddr is required
    //*(UINT32*)(this->m_pTcp4ConfigData->AccessPoint.StationAddress.Addr) = LocalIp;
    this->m_pTcp4ConfigData->AccessPoint.StationPort = 61558;
    this->m_pTcp4ConfigData->AccessPoint.ActiveFlag = TRUE;
    this->m_pTcp4ConfigData->ControlOption = NULL;
    Status = this->m_pTcp4Protocol ->Configure(this->m_pTcp4Protocol, this->m_pTcp4ConfigData);    
    return Status;
}

//SOCKET_STAUS Socket::Send(CHAR8* Data, UINTN Lenth)
SOCKET_STATUS Send(int sk, CHAR8* Data, UINTN Lenth)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    struct Socket* this = Socketfd[sk]; 
    if(this->m_pTcp4Protocol == NULL) return Status;  
    this->m_TransData->Push = TRUE;
    this->m_TransData->Urgent = TRUE;
    this->m_TransData->DataLength = (UINT32)Lenth;
    this->m_TransData->FragmentCount = 1;
    this->m_TransData->FragmentTable[0].FragmentLength =this->m_TransData->DataLength;
    this->m_TransData->FragmentTable[0].FragmentBuffer =Data;
    this->SendToken.Packet.TxData=  this->m_TransData;
    Status = this->m_pTcp4Protocol -> Transmit(this->m_pTcp4Protocol, &this->SendToken);
    if( !EFI_ERROR(Status)){
        Print(L"\nSending Data Now: %d\n", Status);
    }
    
    //SocketWait(this->SendToken.CompletionToken.Event);  
    UINTN index = 0;
    EFI_EVENT myEvent;
    
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 50*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"Wait Status: %d\n", Status);
    Status = this->SendToken.CompletionToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"Send Data Success: %d\n", Status);
    }
    return Status;
    //return this->SendToken.CompletionToken.Status;
}

//SOCKET Socket::Recv(CHAR8* Buffer, UINTN Lenth)
SOCKET_STATUS Recv(int sk, CHAR8* Buffer, UINTN Lenth)
{
    EFI_STATUS Status = EFI_NOT_FOUND;
    struct Socket* this = Socketfd[sk]; 
    if(this->m_pTcp4Protocol == NULL) return Status;

    this->m_RecvData->UrgentFlag = TRUE;
    this->m_RecvData->DataLength = (UINT32)Lenth;
    this->m_RecvData->FragmentCount = 1;
    this->m_RecvData->FragmentTable[0].FragmentLength = this->m_RecvData->DataLength ;
    this->m_RecvData->FragmentTable[0].FragmentBuffer = (void*)Buffer;
    this->RecvToken.Packet.RxData=  this->m_RecvData;
    Status = this->m_pTcp4Protocol -> Receive(this->m_pTcp4Protocol, &this->RecvToken);
    if( !EFI_ERROR(Status)){
        Print(L"\nRecving Data Now: %d\n", Status);
    }
    
    UINTN index = 0;
    EFI_EVENT myEvent;
    
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, 
             (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 60*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"Wait Status: %d\n", Status);
    Status = this->RecvToken.CompletionToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"Recv Data Success: %d\n", Status);
    }
    return Status;
    //return this->RecvToken.CompletionToken.Status;
}

#define SAFE_FREE(x) {if(x){free(x); x = NULL;}
//__inline Socket::~Socket()
static int Destroy(int sk)
{
    EFI_STATUS                           Status;
    struct Socket* this = Socketfd[sk]; 
    if(this->m_SocketHandle){
        EFI_SERVICE_BINDING_PROTOCOL*  pTcpServiceBinding;
        Status = gBS->LocateProtocol ( &gEfiTcp4ServiceBindingProtocolGuid,
                NULL, (VOID **)&pTcpServiceBinding );
        Status = pTcpServiceBinding->DestroyChild ( pTcpServiceBinding,
                this->m_SocketHandle );
    }
    if(this->ConnectToken.CompletionToken.Event)
        gBS->CloseEvent(this->ConnectToken.CompletionToken.Event);    
    if(this->SendToken.CompletionToken.Event)
        gBS->CloseEvent(this->SendToken.CompletionToken.Event);    
    if(this->RecvToken.CompletionToken.Event)
        gBS->CloseEvent(this->RecvToken.CompletionToken.Event);
    
    if(this->m_pTcp4ConfigData){
	    free(this->m_pTcp4ConfigData);
    }
    if(this->SendToken.Packet.TxData){
	    free(this->SendToken.Packet.TxData);
	    this->SendToken.Packet.TxData = NULL;
    }
    if(this->RecvToken.Packet.RxData){
	    free(this->RecvToken.Packet.RxData);
	    this->RecvToken.Packet.RxData = NULL;
    }
    return Status;
}


//EFI_STAUS Socket::Connect()
EFI_STATUS Connect0(int sk)
{
    EFI_STATUS                           Status = EFI_NOT_FOUND;
    struct Socket* this = Socketfd[sk]; 
    if(this->m_pTcp4Protocol == NULL) {
        Print(L"The Socketfd is Null");
        return Status; 
    }
    Status = this->m_pTcp4Protocol -> Connect(this->m_pTcp4Protocol, &this->ConnectToken);
    if(EFI_ERROR(Status)){
        Print(L"Connect0 Error Code: %d\n", Status);
        return Status;
    }

    UINTN index = 0;
    EFI_EVENT myEvent;
    Status = gBS->CreateEvent(EVT_TIMER, TPL_CALLBACK, 
             (EFI_EVENT_NOTIFY)NULL, (VOID*)NULL, &myEvent);
    Status = gBS->SetTimer(myEvent, TimerPeriodic, 50*1000*1000);
    Status = gBS->WaitForEvent(1, &myEvent, &index);
    Print(L"Wait Status: %d\n", Status);
    
    Status = this->ConnectToken.CompletionToken.Status;
    if( !EFI_ERROR(Status)){
        Print(L"Connect Success: %d\n", Status);
    }
    return Status;
}

SOCKET_STATUS Connect(int fd, UINT32 Ip32, UINT16 Port)
{
        EFI_STATUS Status;
        Status = Config(fd, Ip32, Port);
        if(EFI_ERROR(Status)){
            Print(L"Config Error Code: %d\n", Status);
        }
        else{
            Print(L"Config Sucess Code: %d\n", Status);
        }
	return Connect0(fd);
}

SOCKET_STATUS Close(int sk)
{
	EFI_STATUS                           Status;
	struct Socket* this = Socketfd[sk]; 
	Status = this -> m_pTcp4Protocol -> Close(this->m_pTcp4Protocol, &this->CloseToken);
	//CheckReturnStatus(L"Close");
	//Print(L"Close Status %r\n", CloseToken.CompletionToken.Status);

	Destroy(sk);
	free(this);
	Socketfd[sk] = NULL;

	return Status;

}

VOID
AsciiToUnicodeSize( CHAR8 *String, 
                    UINT8 length, 
                    CHAR16 *UniString)
{
    int len = length;
 
    while (*String != '\0' && len > 0) {
        *(UniString++) = (CHAR16) *(String++);
        len--;
    }
    *UniString = '\0';
}

EFI_STATUS TestNetwork (IN EFI_HANDLE ImageHandle)
{
	EFI_STATUS                           Status = 0;
	CHAR8 RequestData[]=  // "GET / HTTP/1.1\nHost:localhost\nAccept:* / * \nConnection:Keep-Alive\n\n";
    "GET / HTTP/1.1\n"
        "Host:10.192.13.84\nAccept:* / * \n"
        "Connection:Keep-Alive\n\n";
	
        CHAR16 Buffer[100];
        AsciiToUnicodeSize((CHAR8 *)&(RequestData), 100, Buffer);
	Print(L"The Request Data: %s\n", Buffer);

	CHAR8 *RecvBuffer = (CHAR8*) malloc(1024);
	int WebSocket = Socket();
	//if( WebSocket.Ready() == TRUE)
	{
		Status = Connect(WebSocket, IPV4(10,192,13,84), 8000);
                if(EFI_ERROR(Status)){
                    Print(L" Connect Failure Code: %d\n", Status);
                    return Status;
                }
		Status = Send(WebSocket, RequestData, AsciiStrLen(RequestData)+2 );//! length +2
                if(EFI_ERROR(Status)){
                    Print(L" Send Failure Code: %d\n", Status);
                    return Status;
                }
		Status = Recv(WebSocket, RecvBuffer, 1024);
                if(EFI_ERROR(Status)){
                    Print(L" Recv Failure Code: %d\n", Status);
                    return Status;
                }
		Status = Close(WebSocket);
                if(EFI_ERROR(Status)){
                    Print(L" Close Failure Code: %d\n", Status);
                    return Status;
                }
	}
        //Print(L"Sent: %s\n", RequestData);
        //Print(L"Recv size: %d\ndata: %s\n", sizeof(RecvBuffer), RecvBuffer);
        CHAR16 newBuffer[100];
        AsciiToUnicodeSize((CHAR8 *)RecvBuffer, sizeof(newBuffer), newBuffer);
	Print(L"\nThe Recved Data: %s\n", newBuffer);
	Print(L"Sent Data Size: %d\n Recved Data Size: %d\n", sizeof(Buffer), sizeof(RecvBuffer));
	free(RecvBuffer);
        Print(L"Free the Received Buffer\n");
	return Status;
}

