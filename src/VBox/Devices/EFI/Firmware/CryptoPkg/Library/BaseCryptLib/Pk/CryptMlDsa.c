/** @file
  ML-DSA (Module-Lattice-Based Digital Signature Standard) Wrapper Implementation
  over OpenSSL 3.6.

  Copyright (c) 2026, Your Name. All rights reserved.<BR>
  SPDX-License-Identifier: BSD-2-Clause-Patent
**/

#include "InternalCryptLib.h"
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/core_names.h>
#include <openssl/param_build.h>

// Key and signature sizes (example values, adjust as needed)
#define ML_DSA_65_PUBLIC_KEY_SIZE   1952
#define ML_DSA_65_SIGNATURE_SIZE    3309
// Internal context structure
typedef struct {
  UINTN        Nid;            // Parameter set NID (CRYPTO_NID_ML_DSA_*)
  EVP_PKEY     *Pkey;          // OpenSSL EVP_PKEY object (holds key material)
  BOOLEAN      HasPrivate;     // Whether private key is loaded
} ML_DSA_CTX;

//
// Map EDK2 NID to OpenSSL algorithm name string
//
STATIC
const char *
MlDsaGetAlgName (
  IN UINTN  CryptoNid
  )
{
  switch (CryptoNid) {
    case CRYPTO_NID_ML_DSA_44:
      return "ML-DSA-44";
    case CRYPTO_NID_ML_DSA_65:
      return "ML-DSA-65";
    case CRYPTO_NID_ML_DSA_87:
      return "ML-DSA-87";
    default:
      return NULL;
  }
}

//
// Public API
//

VOID *
EFIAPI
MlDsaNew (
  IN UINTN  Nid
  )
{
  ML_DSA_CTX  *Ctx;
  const char  *AlgName;

  AlgName = MlDsaGetAlgName (Nid);
  if (AlgName == NULL) {
    return NULL;
  }

  Ctx = AllocateZeroPool (sizeof (ML_DSA_CTX));
  if (Ctx == NULL) {
    return NULL;
  }

  Ctx->Nid        = Nid;
  Ctx->Pkey       = NULL;
  Ctx->HasPrivate = FALSE;

  return Ctx;
}

VOID
EFIAPI
MlDsaFree (
  IN VOID  *MlDsaContext
  )
{
  ML_DSA_CTX  *Ctx;

  if (MlDsaContext == NULL) {
    return;
  }

  Ctx = (ML_DSA_CTX *)MlDsaContext;
  if (Ctx->Pkey != NULL) {
    EVP_PKEY_free (Ctx->Pkey);
  }
  FreePool (Ctx);
}

BOOLEAN
EFIAPI
MlDsaSetPublicKey (
  IN OUT  VOID         *MlDsaContext,
  IN      CONST UINT8  *PublicKey,
  IN      UINTN        PublicKeySize
  )
{
  ML_DSA_CTX  *Ctx;
  EVP_PKEY    *Pkey;
  const char  *AlgName;

  if ((MlDsaContext == NULL) || (PublicKey == NULL) || (PublicKeySize == 0)) {
    return FALSE;
  }

  Ctx = (ML_DSA_CTX *)MlDsaContext;
  AlgName = MlDsaGetAlgName (Ctx->Nid);
  if (AlgName == NULL) {
    return FALSE;
  }

  // Create EVP_PKEY from raw public key
  Pkey = EVP_PKEY_new_raw_public_key (EVP_PKEY_ML_DSA_65, NULL, PublicKey, (size_t)PublicKeySize);
  if (Pkey == NULL) {
    DEBUG((DEBUG_ERROR, "EVP_PKEY_new_raw_public_key failed\n"));
    return FALSE;
  }

  // Replace existing key if any
  if (Ctx->Pkey != NULL) {
    EVP_PKEY_free (Ctx->Pkey);
  }
  Ctx->Pkey       = Pkey;
  Ctx->HasPrivate = FALSE;

  return TRUE;
}

BOOLEAN
EFIAPI
MlDsaSetPrivateKey (
  IN OUT  VOID         *MlDsaContext,
  IN      CONST UINT8  *PrivateKey,
  IN      UINTN        PrivateKeySize
  )
{
  ML_DSA_CTX  *Ctx;
  EVP_PKEY    *Pkey;
  const char  *AlgName;

  if ((MlDsaContext == NULL) || (PrivateKey == NULL) || (PrivateKeySize == 0)) {
    return FALSE;
  }

  Ctx = (ML_DSA_CTX *)MlDsaContext;
  AlgName = MlDsaGetAlgName (Ctx->Nid);
  if (AlgName == NULL) {
    return FALSE;
  }

  // Create EVP_PKEY from raw private key
  Pkey = EVP_PKEY_new_raw_private_key (EVP_PKEY_ML_DSA_65, NULL, PrivateKey, (size_t)PrivateKeySize);
  if (Pkey == NULL) {
    return FALSE;
  }

  if (Ctx->Pkey != NULL) {
    EVP_PKEY_free (Ctx->Pkey);
  }
  Ctx->Pkey       = Pkey;
  Ctx->HasPrivate = TRUE;

  return TRUE;
}

BOOLEAN
EFIAPI
MlDsaGetPublicKeySize (
  IN  CONST VOID  *MlDsaContext,
  OUT UINTN       *KeySize
  )
{
  ML_DSA_CTX  *Ctx;
  int         Size;

  if ((MlDsaContext == NULL) || (KeySize == NULL)) {
    return FALSE;
  }

  Ctx = (ML_DSA_CTX *)MlDsaContext;
  if (Ctx->Pkey == NULL) {
    return FALSE;
  }

  Size = EVP_PKEY_get_size (Ctx->Pkey);
  if (Size <= 0) {
    return FALSE;
  }

  *KeySize = (UINTN)Size;
  return TRUE;
}

BOOLEAN
EFIAPI
MlDsaGetSignatureSize (
  IN  CONST VOID  *MlDsaContext,
  OUT UINTN       *SigSize
  )
{
  // For ML-DSA, the signature size is fixed per parameter set and is
  // independent of the key. We can obtain it from EVP_PKEY if available,
  // or return pre-defined values.
  ML_DSA_CTX  *Ctx;

  if ((MlDsaContext == NULL) || (SigSize == NULL)) {
    return FALSE;
  }

  Ctx = (ML_DSA_CTX *)MlDsaContext;
  if (Ctx->Pkey == NULL) {
    // Fallback: return sizes based on Nid
    switch (Ctx->Nid) {
      case CRYPTO_NID_ML_DSA_44: *SigSize = 2420; break;  // ML-DSA-44 signature size
      case CRYPTO_NID_ML_DSA_65: *SigSize = 3309; break;  // ML-DSA-65 signature size
      case CRYPTO_NID_ML_DSA_87: *SigSize = 4627; break;  // ML-DSA-87 signature size
      default: return FALSE;
    }
    return TRUE;
  }

  // If key exists, query the actual signature length
  *SigSize = (UINTN)EVP_PKEY_get_size (Ctx->Pkey);
  return (*SigSize > 0);
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
  ML_DSA_CTX  *Ctx;
  EVP_MD_CTX  *MdCtx;
  size_t      RequiredSize;
  BOOLEAN     Result;

  if ((MlDsaContext == NULL) || (Message == NULL) || (Signature == NULL) || (SigSize == NULL)) {
    return FALSE;
  }

  Ctx = (ML_DSA_CTX *)MlDsaContext;
  if ((Ctx->Pkey == NULL) || (!Ctx->HasPrivate)) {
    return FALSE;
  }

  // Determine required signature buffer size
  RequiredSize = (size_t)EVP_PKEY_get_size (Ctx->Pkey);
  if (*SigSize < RequiredSize) {
    *SigSize = RequiredSize;
    return FALSE;
  }

  MdCtx = EVP_MD_CTX_new ();
  if (MdCtx == NULL) {
    return FALSE;
  }

  // Initialize signing operation (no hash, sign the raw message)
  Result = (BOOLEAN)EVP_DigestSignInit (MdCtx, NULL, NULL, NULL, Ctx->Pkey);
  if (Result) {
    Result = (BOOLEAN)EVP_DigestSign (MdCtx, Signature, &RequiredSize, Message, (size_t)MessageSize);
  }

  if (Result) {
    *SigSize = RequiredSize;
  }

  EVP_MD_CTX_free (MdCtx);
  return Result;
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
  ML_DSA_CTX  *Ctx;
  EVP_MD_CTX  *MdCtx;
  BOOLEAN     Result;

  if ((MlDsaContext == NULL) || (Message == NULL) || (Signature == NULL)) {
    return FALSE;
  }
  DEBUG ((DEBUG_INFO, "MlDsaVerify: MessageSize = %d bytes\n", MessageSize));
  for (UINTN i = 0; i < MessageSize; i++) {
    if (i % 16 == 0) {
      DEBUG ((DEBUG_INFO, "\n  %04x: ", i));
    }
    DEBUG ((DEBUG_INFO, "%02x ", Message[i]));
  }
  DEBUG ((DEBUG_INFO, "\n"));
  
  Ctx = (ML_DSA_CTX *)MlDsaContext;
  if (Ctx->Pkey == NULL) {
    return FALSE;
  }

  MdCtx = EVP_MD_CTX_new ();
  if (MdCtx == NULL) {
    return FALSE;
  }

  Result = (BOOLEAN)EVP_DigestVerifyInit (MdCtx, NULL, NULL, NULL, Ctx->Pkey);
  if (Result) {
    Result = (BOOLEAN)EVP_DigestVerify (MdCtx, Signature, (size_t)SigSize, Message, (size_t)MessageSize);
  }

  EVP_MD_CTX_free (MdCtx);
  return Result;
}

/**
  Extract ML-DSA public key from a PKCS#8 DER-encoded private key.

  @param[in]   PrivKeyDer      Pointer to PKCS#8 DER data.
  @param[in]   PrivKeyDerSize  Size of DER data.
  @param[out]  PubKey          Pointer to buffer to receive raw public key.
  @param[out]  PubKeySize      On input, size of PubKey buffer; on output, actual size.

  @retval TRUE   Public key extracted successfully.
  @retval FALSE  Failed to extract.
**/
BOOLEAN
EFIAPI
ExtractMlDsaPublicKeyFromPkcs8 (
  IN  CONST UINT8  *PrivKeyDer,
  IN  UINTN        PrivKeyDerSize,
  OUT UINT8        *PubKey,
  IN OUT UINTN     *PubKeySize
  )
{
  BOOLEAN     Result;
  const UINT8 *TempPtr;
  EVP_PKEY    *Pkey;
  size_t      RequiredSize;

  Result = FALSE;
  Pkey   = NULL;

  if ((PrivKeyDer == NULL) || (PubKeySize == NULL)) {
    return FALSE;
  }

  // Parse PKCS#8 private key
  TempPtr = PrivKeyDer;
  Pkey = d2i_AutoPrivateKey (NULL, &TempPtr, (long)PrivKeyDerSize);
  if (Pkey == NULL) {
    goto Done;
  }

  // Get raw public key size
  RequiredSize = (size_t)EVP_PKEY_get_size (Pkey);
  if (RequiredSize == 0) {
    goto Done;
  }

  if (*PubKeySize < RequiredSize) {
    *PubKeySize = RequiredSize;
    goto Done;
  }

  // Extract raw public key
  if (EVP_PKEY_get_raw_public_key (Pkey, PubKey, &RequiredSize) != 1) {
    goto Done;
  }

  *PubKeySize = RequiredSize;
  Result = TRUE;

Done:
  if (Pkey != NULL) {
    EVP_PKEY_free (Pkey);
  }
  return Result;
}

/**
  Extract ML-DSA public key from an X.509 DER certificate.

  @param[in]   CertDer         Pointer to X.509 DER certificate.
  @param[in]   CertDerSize     Size of certificate.
  @param[out]  PubKey          Pointer to buffer to receive raw public key.
  @param[out]  PubKeySize      On input, size of PubKey buffer; on output, actual size.

  @retval TRUE   Public key extracted successfully.
  @retval FALSE  Failed to extract.
**/
BOOLEAN
EFIAPI
ExtractMlDsaPublicKeyFromX509 (
  IN  CONST UINT8  *CertDer,
  IN  UINTN        CertDerSize,
  OUT UINT8        *PubKey,
  IN OUT UINTN     *PubKeySize
  )
{
  BOOLEAN      Result;
  const UINT8  *TempPtr;
  X509         *Cert;
  EVP_PKEY     *Pkey;
  size_t       RequiredSize;

  Result = FALSE;
  Cert   = NULL;
  Pkey   = NULL;

  if ((CertDer == NULL) || (PubKeySize == NULL)) {
    return FALSE;
  }

  TempPtr = CertDer;
  Cert = d2i_X509 (NULL, &TempPtr, (long)CertDerSize);
  if (Cert == NULL) {
    goto Done;
  }

  Pkey = X509_get_pubkey (Cert);
  if (Pkey == NULL) {
    goto Done;
  }

  // Check if it's an ML-DSA key
  if (EVP_PKEY_get_id (Pkey) != EVP_PKEY_ML_DSA_65) {
    goto Done;
  }

  RequiredSize = (size_t)EVP_PKEY_get_size (Pkey);
  if (RequiredSize == 0) {
    goto Done;
  }

  if (*PubKeySize < RequiredSize) {
    *PubKeySize = RequiredSize;
    goto Done;
  }

  if (EVP_PKEY_get_raw_public_key (Pkey, PubKey, &RequiredSize) != 1) {
    goto Done;
  }

  *PubKeySize = RequiredSize;
  Result = TRUE;

Done:
  if (Pkey != NULL) {
    EVP_PKEY_free (Pkey);
  }
  if (Cert != NULL) {
    X509_free (Cert);
  }
  return Result;
}

/**
  Extract raw ML-DSA public key from a PKCS#8 or X.509 DER blob.

  @param[in]   Data        DER data.
  @param[in]   DataSize    Size of data.
  @param[out]  PubKey      Buffer to receive raw public key (must be at least ML_DSA_65_PUBLIC_KEY_SIZE).
  @return TRUE on success, FALSE otherwise.
**/
BOOLEAN
EFIAPI
ExtractMlDsaPublicKeyFromDer (
  IN  CONST UINT8  *Data,
  IN  UINTN        DataSize,
  OUT UINT8        *PubKey
  )
{
  BOOLEAN      Result;
  const UINT8  *Ptr;
  EVP_PKEY     *Pkey;
  size_t       RequiredSize;
  int          KeyId;

  Result = FALSE;
  Pkey   = NULL;

  if (Data == NULL || PubKey == NULL) {
    return FALSE;
  }

  Ptr = Data;
  Pkey = d2i_AutoPrivateKey (NULL, &Ptr, (long)DataSize);
  if (Pkey == NULL) {
    Ptr = Data;
    Pkey = d2i_PUBKEY (NULL, &Ptr, (long)DataSize);
  }
  if (Pkey == NULL) {
    DEBUG ((DEBUG_ERROR, "ExtractMlDsaPublicKeyFromDer: Failed to parse DER (not PKCS#8 nor SubjectPublicKeyInfo)\n"));
    goto Done;
  }

  KeyId = EVP_PKEY_get_id (Pkey);
  DEBUG ((DEBUG_INFO, "ExtractMlDsaPublicKeyFromDer: EVP_PKEY_get_id = %d\n", KeyId));

  if (KeyId != EVP_PKEY_ML_DSA_65 && KeyId != -1) {
    goto Done;
  }
  RequiredSize = ML_DSA_65_PUBLIC_KEY_SIZE;
  if (EVP_PKEY_get_raw_public_key (Pkey, PubKey, &RequiredSize) != 1) {
    DEBUG ((DEBUG_ERROR, "ExtractMlDsaPublicKeyFromDer: EVP_PKEY_get_raw_public_key failed, RequiredSize=%zu\n", RequiredSize));
    goto Done;
  }

  DEBUG ((DEBUG_INFO, "ExtractMlDsaPublicKeyFromDer: Got raw public key of size %x\n", RequiredSize));
  Result = (RequiredSize == ML_DSA_65_PUBLIC_KEY_SIZE);

Done:
  if (Pkey != NULL) {
    EVP_PKEY_free (Pkey);
  }
  return Result;
}