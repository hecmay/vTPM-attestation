#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <Library/BaseLib.h>
#include <Library/ShellCEntryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/BaseMemoryLib.h>
#include <stdlib.h>
#include <Protocol/RuntimeCrypt.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseCryptLib.h>

//
// Max Known Digest Size is SHA512 Output (64 bytes) by far
//
#define MAX_DIGEST_SIZE    64

//
// Convert CHAR8 Ascii to CHAR16 Unicode
//
extern VOID AsciiToUnicodeSize( CHAR8 *String, UINT32 length, CHAR16 *UniString);

//
// Message string for digest validation
//
extern EFI_GUID  gEfiRuntimeCryptProtocolGuid;

//
// The Initialization Vector for Aes-128 CBC Encryption
//
CONST UINT8 Aes128CbcIvec[] = {
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//
// Convert UINT8(unsigned char) to CHAR8(char)
//
VOID
UintToCharSize( UINT8  *UintStr, 
                UINT32 length, 
                CHAR8  *CharStr)
{
    CHAR8 Convert[16];
    int len = length;
    while (!(*UintStr == '\0' && *(UintStr+1) == '\0')  && len > 0) {
        AsciiSPrint(Convert, 1024, "%02x", 0xff & *(UintStr++));
        AsciiStrCatS(CharStr, 1024, Convert);
        len--;
    }
    *CharStr = '\0';
    AsciiPrint("\n\n[Debug] The Converted Str: %s", CharStr);
}

//
// Sha256 Encrytion: Hex in Unicode format will be returned to Buffer
//
EFI_STATUS
Sha256CryptoData(
  IN   CHAR8 *HashData,
  OUT  CHAR16 *Buffer, 
  OUT  UINT8  *Record 
  )
{
        EFI_RUNTIME_CRYPT_PROTOCOL  *mCryptProtocol = NULL;
        EFI_STATUS                  Status;
        UINT8                       Digest[MAX_DIGEST_SIZE];      
        UINTN    CtxSize;
        VOID     *HashCtx;
        UINTN    DataSize; 
        UINTN    Index;
        CHAR16   Convert[128];
        
        DataSize = AsciiStrLen (HashData);        
        Status = gBS->LocateProtocol(
                        &gEfiRuntimeCryptProtocolGuid, 
                        NULL, 
                        (VOID **) &mCryptProtocol);
        if (EFI_ERROR(Status)) {
           Print(L"Can't find the runtime cryptographic protocol\n");
           return Status;
        }
        
        ZeroMem (Digest, MAX_DIGEST_SIZE);
        CtxSize = mCryptProtocol->Sha256GetContextSize ();
        HashCtx = AllocatePool (CtxSize);

        CHAR16 PrintBuffer[2048];
        AsciiToUnicodeSize(HashData, 2048, PrintBuffer); 
        Print(L"[Debug] Data to be Hashed: %s\n", PrintBuffer);

        Status  = mCryptProtocol->Sha256Init (HashCtx);
        if (!Status) {
          Print (L"[Fail] Sha256 Init Falied [%d]\n", Status);
          return EFI_ABORTED;
        }

        Status  = mCryptProtocol->Sha256Update (HashCtx, HashData, DataSize);
        if (!Status) {
          Print (L"[Fail] Sha256 Update Falied [%d]\n", Status);
          return EFI_ABORTED;
        }

        Status  = mCryptProtocol->Sha256Final (HashCtx, Digest);
        if (!Status) {
          Print (L"[Fail] Sha256 Final Falied [%d]\n", Status);
          return EFI_ABORTED;
        }

        Print(L"[Debug] The Sha256 EncrptData:\n");
        for (Index = 0; Index < SHA256_DIGEST_SIZE; Index++) {
          Print (L"%2X  ",Digest[Index]);
          *(Record + Index) = Digest[Index];
          UnicodeSPrint(Convert, sizeof(Convert), L"%02x", 0xff & Digest[Index]);
          StrCatS(Buffer, 4096, Convert);
        }
        Print (L"\n");
        FreePool (HashCtx);

        return EFI_SUCCESS;
}


EFI_STATUS
GenerateRsaCbcKey (
  IN   UINT64  Material,
  OUT  UINT8   *AesCbcKey
  )
{
  
  EFI_STATUS  Status;
  CHAR16      Buffer[4096];
  CHAR8       HashBuf[2048];
  UINT8       Digest[64];

  ZeroMem (Buffer, sizeof (Buffer));
  ZeroMem (HashBuf, sizeof (HashBuf));

  AsciiSPrint(HashBuf, sizeof(Material)*4, "%d", Material);
  Status = Sha256CryptoData(HashBuf, Buffer, Digest);

  // retrieve the first 16 bytes of the sha256 as aes key
  for (int Index = 0; Index < 16; Index++){
    AesCbcKey[Index] = Digest[Index];
  }

  Print(L"The 16-bit key AES Encyption...\n");
  for (int Index = 0; Index < 16; Index++){
    Print(L"%02x ", AesCbcKey[Index]);
  }
 
  Print(L"\n\n[Debug] The Size of AesCbcKey: %d bytes\n", sizeof(AesCbcKey));
  Print(L"[Debug] The Last Byte in AesCbcKey: %02x \n", AesCbcKey[16]);
  // Print(L"Output Hex value: %s\n", Buffer);
  return Status;

}


EFI_STATUS
AesCryptoData (
  IN   UINT64 Material,
  IN   CHAR8  *CryptData,
  OUT  UINT8  *RsaBuf,
  IN   UINTN  Size
  )
{

    VOID        *AesCtx;
    BOOLEAN     Result;
    UINT8       Decrypt[256];
    UINT8       AesCbcKey[16];
    EFI_STATUS  Status;
    CHAR16      OutputBuffer[1024];

    ZeroMem(Decrypt, sizeof (Decrypt));
    ZeroMem(AesCbcKey, sizeof (AesCbcKey));
    AesCtx = AllocatePool (1024);

    Print(L"[Debug] Sizeof AesCbcKey: %d\n", sizeof(AesCbcKey));
    Status = GenerateRsaCbcKey ( Material, AesCbcKey ); 
    if (EFI_ERROR(Status)){
      Print(L"[Fail] Get AesCbcKey Failed: %d\n", Status);
      return Status;
    }

    Print(L"[Debug] After Sizeof AesCbcKey: %d\n[Debug] ", sizeof(AesCbcKey));
    for (int Index = 0; Index < 16; Index++){
      Print(L"%02x ", AesCbcKey[Index]);
    }
    Result = AesInit(AesCtx, AesCbcKey, 128);
    if (!Result) {
      Print (L"[Fail] AES Init\n");
      return EFI_ABORTED;
    }

    // Extend the lenth s.t. 16 | StrLen(HashBuf) 
    UINT8 Redudency = 16 - ((AsciiStrLen(CryptData) % 16));
    for (int index = 0 ; index < Redudency; index++){
      AsciiStrCatS(CryptData, 1024, "=");
    }

    // Examine the Correctness of Prerequisite
    if (AesCtx == NULL || RsaBuf == NULL || (AsciiStrLen(CryptData) % 16) != 0) {
      Print(L"AesCtx or Output or AsciiStrLen %d wrong\n", AsciiStrLen(CryptData));
    }
    if ( Aes128CbcIvec == NULL || RsaBuf == NULL) {
      Print(L"The Ivec or Output not right\n");
    }

    // [Debug] Dump the Data to be Encrypted
    AsciiToUnicodeSize(CryptData, 2048, OutputBuffer);
    Print(L"\n[Debug] Data encrypted by Aes: %s\n", OutputBuffer);  
    Print(L"\n[Debug] Data encrypted by Aes in Hex\n");  
    for (int Tag = 0; Tag < Size; Tag++) {
      Print(L"%02x ", CryptData[Tag]);
    }

    //    Status = StrnCpyS(DestKey, 1024, Buffer, 16);
    //    Print(L"AES Encryption Key: %s\n", Key);  
    //    CHAR16 PrintBuffer[2048];
    //    ZeroMem (PrintBuffer, 2048);

    Print(L"\n\n[Debug] AES Encryption CBC Mode...");  
    Result = AesCbcEncrypt( AesCtx, 
                            (UINT8*)CryptData, 
                            AsciiStrLen(CryptData), 
                            Aes128CbcIvec, 
                            RsaBuf ); 
    if (!Result) {
      Print (L"[Fail] AES Cbc Encrypt \n");
      return EFI_ABORTED;
    }

    Print(L"\n[Debug] The AES-128 CBC Encryption OutPut...\n");
    for (int Tag = 0; Tag < Size; Tag++) {
      Print(L"%02x ", RsaBuf[Tag]);
    }

    // Check the Aes Decryption
    Print(L"\n\n[Debug] AES Decryption Check...\n");  
    Result = AesCbcDecrypt (AesCtx, 
                            RsaBuf, 
                            AsciiStrLen(CryptData), 
                            Aes128CbcIvec, 
                            Decrypt);
    if (!Result) {
      Print (L"[Fail] Unable to performa Aes Decyption\n");
      return EFI_ABORTED;
    }

    Print(L"[Debug] Data decrypted by Aes in Hex\n");  
    for (int Tag = 0; Tag < Size; Tag++) {
      Print(L"%02x ", Decrypt[Tag]);
    }
    return Status;                                                        
                                                                          
}                                                                         


EFI_STATUS
AesDecryptoData (
  IN   UINT64  Nounce,
  IN   CHAR8   *RecvBuffer,
  OUT  UINT8   *DecryptData
  )
{
  VOID        *AesCtx;
  BOOLEAN     Result;
  UINT8       AesCbcKey[16];
  EFI_STATUS  Status = EFI_SUCCESS;

  AesCtx = AllocatePool (1024);
  Status = GenerateRsaCbcKey ( Nounce, AesCbcKey ); 
  if (EFI_ERROR(Status)){
    Print(L"[Fail] Get AesCbcKey for Decryption Failed: %d\n", Status);
    return Status;
  }

  Result = AesInit(AesCtx, AesCbcKey, 128);
  if (!Result) {
    Print (L"[Fail] AesCtx for Decryption Init\n");
    return EFI_ABORTED;
  }

  //
  // Clean the Received Data (The last character is +)
  //
  CHAR8  Clean[64];
  CHAR8  *LenEnd = AsciiStrStr(RecvBuffer, (CHAR8*)"+");
  UINTN  Len = LenEnd - RecvBuffer;
  Print(L"[Debug] The Read-in Len is : %d\n", Len);
  AsciiStrnCpyS(Clean, 1280, RecvBuffer, Len);

  Result = AesCbcDecrypt (AesCtx, 
                          (UINT8*)Clean, 
                          AsciiStrLen(Clean), 
                          Aes128CbcIvec, 
                          DecryptData);
  if (!Result) {
    CHAR16 PrintBuffer[64];
    AsciiToUnicodeSize(RecvBuffer, 128, PrintBuffer);
    Print (L"[Fail] Aes Decyption Failed for %s\n", PrintBuffer);
    return EFI_ABORTED;
  }

  Print(L"[Info] Data Decrypted by Aes in Hex\n");  
  for (int Tag = 0; Tag < 64; Tag++) {
    Print(L"%02x ", DecryptData[Tag]);
  }

  return Status;
}


//
// Rsa Encryption Implementation Wrapper with OpenSSL
//
EFI_STATUS
RsaEncryptoData (
  IN   VOID    *RsaCtx,
  IN   CHAR8   *DataBuffer,
  OUT  UINT8   *EncryptData
  )
{
  UINTN       KeySize;
  UINT8       *ExponentKey;
  UINT8       *ModulusKey;
  EFI_STATUS  Status;
  
  //
  // Assert RsaCtx != NULL 
  //
  if (RsaCtx == NULL) {
    Print(L"[Fail] Cannot Generate Rsa Ctx...\n");
  }

  //
  // Retrieve the Tag-designated Rsa key N/E from established RsaCtx
  //
  KeySize = 0;
  Status = RsaGetKey(RsaCtx, RsaKeyN, NULL, &KeySize);
  if (!Status || KeySize !=0) {
    Print(L"[Fail] Cannot Retrieve N Key from RSaCtx\n");
  }

  ExponentKey = AllocatePool (KeySize);
  Status = RsaGetKey(RsaCtx, RsaKeyN, ExponentKey, &KeySize);
  if (!Status || KeySize !=0) {
    Print(L"[Fail] Cannot Retrieve RsaKeyN Buffer from RSaCtx\n");
  }

  KeySize = 0;
  Status = RsaGetKey(RsaCtx, RsaKeyE, NULL, &KeySize);
  if (!Status || KeySize !=0) {
    Print(L"[Fail] Cannot Retrieve E Key from RSaCtx\n");
  }

  ModulusKey = AllocatePool(KeySize);
  Status = RsaGetKey(RsaCtx, RsaKeyE, ModulusKey, &KeySize);
  if (!Status || KeySize !=0) {
    Print(L"[Fail] Cannot Retrieve RsaKeyE Buffer from RSaCtx\n");
  }
  
  //
  // Check Invalid RsaKey Components
  //
  if (!RsaCheckKey (RsaCtx)) {
    Print(L"[Fail] RsaKey Components Invalid\n");
    return EFI_ABORTED;
  }
  return Status;

}
