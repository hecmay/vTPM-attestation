#ifndef __MTFTP_HEADER__
#define __MTFTP_HEADER__
#include <Uefi.h>

#define IPV4(a,b,c,d) (a | b<<8 | c << 16 | d <<24)

int MtftpClient();
EFI_STATUS MtftpConnect(int fd, UINT32 Ip32, UINT16 Port);
EFI_STATUS Write(int fd, UINT8* Path, CHAR8* Data, UINTN Lenth);
EFI_STATUS Read(int fd, UINT8* Path, CHAR8* Buffer, UINTN Lenth);
EFI_STATUS MtftpClose(int fd);

#endif
