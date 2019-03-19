//
// Copyright (C) Microsoft. All rights reserved
//

#include <Uefi.h>

#include <IndustryStandard/Tpm20.h>

#include <Library/DebugLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>

#include <Library/SerialPortLib.h>

#include <Protocol/TcgService.h>
#include <Protocol/Tcg2Protocol.h>

// This depends on the fTPM implementation. The full response should be sent out
//  and the host side should be responsible for parsing and truncating it.
#define EKCERT_SZ 326

STATIC CONST CHAR16           mDeviceCertVariableName[] = L"ManufacturerDeviceCert0";

EFI_STATUS
EFIAPI
ProvisioningInitialize (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status = EFI_SUCCESS;
  EFI_TCG2_PROTOCOL *Tcg2Protocol;
  UINT8 tpm_in[0xe] = { 0x80, 0x01, // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x0e, // Command size is 0xe
                        0x00, 0x00, 0x01, 0x73, // TPM_CC_ReadPublic 0x173
                        0x81, 0x01, 0x00, 0x01}; // 0x81010001 is EK Cert
  UINT8 tpm_out[1000] = {0};
  TPM2_RESPONSE_HEADER *resp_header = (TPM2_RESPONSE_HEADER*)tpm_out;

  UINT32 certlen;
  UINT8* cert;
  UINTN bytesread = 0;

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

  DEBUG((DEBUG_ERROR, "MFG:devicecert\n"));
  while(SerialPortPoll() == FALSE) {}
  int i = 4;
  UINT8* bufptr = (UINT8*) &certlen;
  while(i > 0) {
    bytesread = SerialPortRead(bufptr, i);
    i -= bytesread;
    bufptr += bytesread;
  }

  DEBUG((DEBUG_ERROR, "bytesread: %d\n", bytesread));
  DEBUG((DEBUG_ERROR, "certlen: 0x%x\n", certlen));

  cert = AllocateZeroPool (certlen);
  if (cert == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }


  i = certlen;
  bufptr = cert;
  while(i > 0) {
    bytesread = SerialPortRead(bufptr, i);
    i -= bytesread;
    bufptr += bytesread;
  }

  i = certlen;
  int sum = 0;
  for(i = 0; i < certlen; i++) {
    sum += cert[i];
  }
  DEBUG((DEBUG_ERROR, "device side checksum: %d\n", sum));

  DEBUG((DEBUG_ERROR, "cert[0]: 0x%02x\n", cert[0]));
  DEBUG((DEBUG_ERROR, "cert[1]: 0x%02x\n", cert[1]));
  DEBUG((DEBUG_ERROR, "cert[2]: 0x%02x\n", cert[2]));
  DEBUG((DEBUG_ERROR, "cert[3]: 0x%02x\n", cert[3]));
  DEBUG((DEBUG_ERROR, "cert[4]: 0x%02x\n", cert[4]));
  DEBUG((DEBUG_ERROR, "cert[5]: 0x%02x\n", cert[5]));
  DEBUG((DEBUG_ERROR, "cert[6]: 0x%02x\n", cert[6]));
  DEBUG((DEBUG_ERROR, "cert[7]: 0x%02x\n", cert[7]));
  DEBUG((DEBUG_ERROR, "cert[8]: 0x%02x\n", cert[8]));
  DEBUG((DEBUG_ERROR, "cert[9]: 0x%02x\n", cert[9]));
  DEBUG((DEBUG_ERROR, "cert[10]: 0x%02x\n", cert[10]));
  DEBUG((DEBUG_ERROR, "cert[11]: 0x%02x\n", cert[11]));
  DEBUG((DEBUG_ERROR, "cert[12]: 0x%02x\n", cert[12]));
  DEBUG((DEBUG_ERROR, "cert[13]: 0x%02x\n", cert[13]));
  DEBUG((DEBUG_ERROR, "cert[14]: 0x%02x\n", cert[14]));

    Status = gRT->SetVariable (
                    (CHAR16 *)mDeviceCertVariableName,
                    &gEfiCallerIdGuid,
                    EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                    certlen,
                    (VOID *)cert
                    );
    if (EFI_ERROR (Status)) {
      DEBUG ((
        EFI_D_ERROR,
        "Provisioning: Failed to save %s variable to non-volatile storage, Status = %r\n",
        mDeviceCertVariableName,
        Status
        ));
    }

  DEBUG((DEBUG_ERROR, "%a exit\n", __FUNCTION__));
  return Status;
}
