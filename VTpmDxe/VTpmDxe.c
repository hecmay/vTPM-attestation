/** @file
  Virtual TPM Driver Implementation, which produce one crypto
  protocol.

Copyright (c) 2010 - 2012, Intel Corporation. All rights reserved.<BR>
This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

**/


//
// The handle onto which VTpm Protocol instance is installed
//
EFI_HANDLE  mVTpmHandle = NULL;

//
// The Virtual TPM Protocol instance produced by this driver
//
EFI_VIRTUAL_TPM_PROTOCOL  mVirtualTpmProtocol = {
  VTpmRandomNumber,
  VTpmSendCommand,
  VTpmRsaCalculate
};


UINTN
EFIAPI
VTpmRandomNumber (
  IN  EFI_VIRTUAL_TPM_PROTOCOL  *This,
  IN  UINTN                     RandomNumSize
  )
{
  return ;
}


EFI_STATUS
EFIAPI
VTpmSendCommand (
  IN   EFI_VIRTUAL_TPM_PROTOCOL  *This,
  IN   UINTN                     InBufferSize,
  IN   UINT8                     *InBuffer,
  IN   UINTN                     OutBufferSize,
  OUT  UINT8                     *OutBuffer 
  )
{
  EFI_STATUS Status;
  Status = TcgProtocol->PassThroughToTpm( TcgProtocol,
                                          InBufferSize,
                                          (UINT8 *)&InBuffer,
                                          OutBufferSize,
                                          (UINT8 *)&OutBuffer);
  if (EFI_ERROR (Status)) {
      Print(L"ERROR: PassThroughToTpm failed [%d]\n", Status);
  }
}


BOOLEAN
EFIAPI
VTpmRsaCalculate (
  IN   EFI_VIRTUAL_TPM_PROTOCOL  *This,
  IN   INT32                     *mContext,
  IN   INT32                     *e,
  IN   INT32                     *n,
  OUT  INT32                     *cContext
  )
{
  return RSA_public_encrypt();
}

