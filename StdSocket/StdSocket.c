#include <netinet/in.h>
#include <sys/EfiSysCall.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <stdio.h>
#include <Library/UefiLib.h>
#include <Uefi.h>
#include <string.h>


UINT32 Value1;
UINT32 Value2;
UINT32 Value3;
UINT32 Value4;

int TestTcpSocket(char *serverIP, int serverPort)
{
    int rc;
    int sock;
    struct sockaddr_in v4;

    char data[1024];
    size_t sentBytes;
    size_t sendStrLen;

    if ( !((4 == sscanf (serverIP,
                    "%d.%d.%d.%d",
                    &Value1,
                    &Value2,
                    &Value3,
                    &Value4))
          && (Value1 <= 255)
          && (Value2 <= 255)
          && (Value3 <= 255)
          && (Value4 <= 255))){
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == -1)
    {
        printf("init socket error\n");
        return -1;
    }

    memset(&v4, 0x00, sizeof(v4));

    v4.sin_len = sizeof(v4);
    v4.sin_family = AF_INET;
    v4.sin_addr.s_addr = Value1 
                       | (Value2 << 8)
                       | (Value3 << 16)
                       | (Value4 << 24);
    v4.sin_port = htons(serverPort);

    rc = connect(sock, (struct sockaddr*)&v4, sizeof(v4));
    if (rc == -1)
    {
        printf("connect() failed (%d)\n", rc);
        return -1;
    }

    printf("input string to send or 'q' to exit connection\n");

    while (1)
    {
        memset(data, 0x00, sizeof(data));

        fgets(data, sizeof(data) - 1, stdin);
        if (data[0] == 'q')
        {
            printf("ready to exit connection\n");
            break;
        }

        sendStrLen = strlen(data);

        if (sendStrLen > 0 && sendStrLen < 1023)
        {
            sentBytes = send(sock, data, sendStrLen, 0);
            printf("\t !!! Sent data: %s(%d) --- \n", data, sentBytes);
        }
    }

    close(sock);
    return 0;
}

int 
main (
  IN int Argc,
  IN char **Argv
  )
{
  
  if (Argc < 2) {
    Print(L"%s <remote Addr> <Port>", Argv[0]);
    return -1;
  }

  char *pRemoteHost;
  int pPort;

  pRemoteHost = Argv[1];
  pPort = 8000;

  puts("Begin to Test the socket\n");
  printf("Link Start;\n");
  TestTcpSocket(pRemoteHost, pPort);
  return 0;

}
