/** @file
  ML-DSA stub implementation for MbedTLS (unsupported).

  Copyright (c) 2026, Your Name. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include <Library/DebugLib.h>

VOID *
EFIAPI
MlDsaNew (
  IN UINTN  Nid
  )
{
  ASSERT (FALSE);
  return NULL;
}

VOID
EFIAPI
MlDsaFree (
  IN VOID  *MlDsaContext
  )
{
  ASSERT (FALSE);
}

BOOLEAN
EFIAPI
MlDsaSetPublicKey (
  IN OUT  VOID         *MlDsaContext,
  IN      CONST UINT8  *PublicKey,
  IN      UINTN        PublicKeySize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
EFIAPI
MlDsaSetPrivateKey (
  IN OUT  VOID         *MlDsaContext,
  IN      CONST UINT8  *PrivateKey,
  IN      UINTN        PrivateKeySize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
EFIAPI
MlDsaGetPublicKeySize (
  IN  CONST VOID  *MlDsaContext,
  OUT UINTN       *KeySize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
EFIAPI
MlDsaGetSignatureSize (
  IN  CONST VOID  *MlDsaContext,
  OUT UINTN       *SigSize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
EFIAPI
MlDsaSign (
  IN      VOID         *MlDsaContext,
  IN      CONST UINT8  *Message,
  IN      UINTN        MessageSize,
  OUT     UINT8        *Signature,
  IN OUT  UINTN        *SigSize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
EFIAPI
MlDsaVerify (
  IN  VOID         *MlDsaContext,
  IN  CONST UINT8  *Message,
  IN  UINTN        MessageSize,
  IN  CONST UINT8  *Signature,
  IN  UINTN        SigSize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
ExtractMlDsaPublicKeyFromPkcs8 (
  IN  CONST UINT8  *PrivKeyDer,
  IN  UINTN        PrivKeyDerSize,
  OUT UINT8        *PubKey,
  IN OUT UINTN     *PubKeySize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
ExtractMlDsaPublicKeyFromX509 (
  IN  CONST UINT8  *CertDer,
  IN  UINTN        CertDerSize,
  OUT UINT8        *PubKey,
  IN OUT UINTN     *PubKeySize
  )
{
  ASSERT (FALSE);
  return FALSE;
}

BOOLEAN
ExtractMlDsaPublicKeyFromDer (
  IN  CONST UINT8  *Data,
  IN  UINTN        DataSize,
  OUT UINT8        *PubKey
  )
{
  ASSERT (FALSE);
  return FALSE;
}