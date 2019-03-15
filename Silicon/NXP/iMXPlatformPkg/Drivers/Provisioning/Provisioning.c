//
// Copyright (C) Microsoft. All rights reserved
//

#include <Uefi.h>

#include <IndustryStandard/Tpm20.h>

#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Protocol/TcgService.h>
#include <Protocol/Tcg2Protocol.h>

// This depends on the fTPM implementation. The full response should be sent out
//  and the host side should be responsible for parsing and truncating it.
#define EKCERT_SZ 326

EFI_STATUS
EFIAPI
ProvisioningInitialize (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;
  EFI_TCG2_PROTOCOL *Tcg2Protocol;
  UINT8 tpm_in[0xe] = { 0x80, 0x01, // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x0e, // Command size is 0xe
                        0x00, 0x00, 0x01, 0x73, // TPM_CC_ReadPublic 0x173
                        0x81, 0x01, 0x00, 0x01}; // 0x81010001 is EK Cert
  UINT8 tpm_out[1000] = {0};
  TPM2_RESPONSE_HEADER *resp_header = (TPM2_RESPONSE_HEADER*)tpm_out;

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **) &Tcg2Protocol);
  if (EFI_ERROR(Status)){
    DEBUG((DEBUG_ERROR, "%a: failed to locate protocol. Status: 0x%x\n", __FUNCTION__, Status));
    return Status;
  }
  Status = Tcg2Protocol->SubmitCommand (
                          Tcg2Protocol,
                          0xe,
                          tpm_in,
                          1000,
                          tpm_out
                          );

  if(SwapBytes32(resp_header->responseCode) != TPM_RC_SUCCESS) {
    DEBUG((DEBUG_ERROR, "%a: Failed to retrieve EK Certificate from TPM!\n", __FUNCTION__));
    return EFI_NOT_FOUND;
  }

  DEBUG((DEBUG_ERROR, "%a: EK Certificate retrieved from TPM\n", __FUNCTION__));
  DEBUG((DEBUG_ERROR, "MFG:ekcertstart\n"));
  for(int x = sizeof(TPM2_RESPONSE_HEADER); x < SwapBytes32(resp_header->paramSize) && x < EKCERT_SZ; x++) {
    DEBUG((DEBUG_ERROR, "%02x\n", tpm_out[x]));
  }
  DEBUG((DEBUG_ERROR, "MFG:ekcertend\n"));
  DEBUG((DEBUG_ERROR, "%a exit\n", __FUNCTION__));
  return Status;
}
