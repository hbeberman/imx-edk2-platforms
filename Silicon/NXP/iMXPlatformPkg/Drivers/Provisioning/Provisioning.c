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
#define TPMIN_SZ 14
#define TPMOUT_SZ 1000

STATIC CONST CHAR16 mDeviceCertVariableName[] = L"ManufacturerDeviceCert";

EFI_STATUS
EFIAPI
RecieveBuffer(
  CHAR8 *requeststring,
  UINT8 **buffer,
  UINT32 *length
)
{
  EFI_STATUS Status;
  UINT32 i;
//  UINT32 sum;
//  UINT32 buflen;
  UINT8* tempptr;
  UINTN bytesread;

  Status = EFI_SUCCESS;

  DEBUG((DEBUG_ERROR, requeststring));

  while(SerialPortPoll() == FALSE) {}

  tempptr = (UINT8*) length;
  for(i = 4, bytesread = 0; i > 0;) {
    bytesread = SerialPortRead(tempptr, i);
    i -= bytesread;
    tempptr += bytesread;
  }

  DEBUG((DEBUG_WARN, "bytesread: %d\n", bytesread));
  DEBUG((DEBUG_WARN, "length: 0x%x\n", *length));

  *buffer = AllocateZeroPool (*length);
  if (*buffer == NULL) {
    *buffer = NULL;
    return EFI_OUT_OF_RESOURCES;
  }

  for(i = *length, tempptr = *buffer; i > 0;) {
    bytesread = SerialPortRead(tempptr, i);
    i -= bytesread;
    tempptr += bytesread;
  }

  return Status;
}

EFI_STATUS
EFIAPI
TransmitEKCertificate()
{
  EFI_STATUS Status;
  EFI_TCG2_PROTOCOL *Tcg2Protocol;

  UINT8 tpm_in[TPMIN_SZ] = { 0x80, 0x01, // TPM_ST_NO_SESSIONS
                        0x00, 0x00, 0x00, 0x0e, // Command size is 0xe
                        0x00, 0x00, 0x01, 0x73, // TPM_CC_ReadPublic 0x173
                        0x81, 0x01, 0x00, 0x01}; // 0x81010001 is EK Cert
  UINT8 tpm_out[TPMOUT_SZ] = {0};
  TPM2_RESPONSE_HEADER *resp_header = (TPM2_RESPONSE_HEADER*)tpm_out;

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL, (VOID **) &Tcg2Protocol);
  if (EFI_ERROR(Status)){
    DEBUG((DEBUG_ERROR, "%a: failed to locate protocol. Status: 0x%x\n", __FUNCTION__, Status));
    return Status;
  }

  Status = Tcg2Protocol->SubmitCommand (
                          Tcg2Protocol,
                          TPMIN_SZ,
                          tpm_in,
                          TPMOUT_SZ,
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
  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RecieveCrossSignedCert()
{
  EFI_STATUS Status;
  UINT32 i;
  UINT32 sum;
  UINT32 certlen;
  UINT8* certptr;
  UINTN bytesread;

  DEBUG((DEBUG_ERROR, "MFG:devicecert\n"));

  while(SerialPortPoll() == FALSE) {}

  UINT8* bufptr = (UINT8*) &certlen;
  for(i = 4, bytesread = 0; i > 0;) {
    bytesread = SerialPortRead(bufptr, i);
    i -= bytesread;
    bufptr += bytesread;
  }

  DEBUG((DEBUG_WARN, "bytesread: %d\n", bytesread));
  DEBUG((DEBUG_WARN, "certlen: 0x%x\n", certlen));

  certptr = AllocateZeroPool (certlen);
  if (certptr == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  for(i = certlen, bufptr = certptr; i > 0;) {
    bytesread = SerialPortRead(bufptr, i);
    i -= bytesread;
    bufptr += bytesread;
  }


  for(i = 0, sum = 0; i < certlen; i++) {
    sum += certptr[i];
  }

  DEBUG((DEBUG_WARN, "Device side checksum: %d\n", sum));

/*
  DEBUG((DEBUG_WARN, "cert[0]: 0x%02x\n", cert[0]));
  DEBUG((DEBUG_WARN, "cert[1]: 0x%02x\n", cert[1]));
  DEBUG((DEBUG_WARN, "cert[2]: 0x%02x\n", cert[2]));
  DEBUG((DEBUG_WARN, "cert[3]: 0x%02x\n", cert[3]));
  DEBUG((DEBUG_WARN, "cert[4]: 0x%02x\n", cert[4]));
  DEBUG((DEBUG_WARN, "cert[5]: 0x%02x\n", cert[5]));
  DEBUG((DEBUG_WARN, "cert[6]: 0x%02x\n", cert[6]));
  DEBUG((DEBUG_WARN, "cert[7]: 0x%02x\n", cert[7]));
  DEBUG((DEBUG_WARN, "cert[8]: 0x%02x\n", cert[8]));
  DEBUG((DEBUG_WARN, "cert[9]: 0x%02x\n", cert[9]));
  DEBUG((DEBUG_WARN, "cert[10]: 0x%02x\n", cert[10]));
  DEBUG((DEBUG_WARN, "cert[11]: 0x%02x\n", cert[11]));
  DEBUG((DEBUG_WARN, "cert[12]: 0x%02x\n", cert[12]));
  DEBUG((DEBUG_WARN, "cert[13]: 0x%02x\n", cert[13]));
  DEBUG((DEBUG_WARN, "cert[14]: 0x%02x\n", cert[14]));
*/

  Status = gRT->SetVariable (
                  (CHAR16 *)mDeviceCertVariableName,
                  &gEfiCallerIdGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                  certlen,
                  (VOID *)certptr
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Provisioning: Failed to save %s variable to non-volatile storage, Status = %r\n",
      mDeviceCertVariableName,
      Status
      ));
  }

  if(certptr != NULL)
    FreePool(certptr);

  return Status;
}

EFI_STATUS
EFIAPI
RecieveSmbiosValues()
{
  EFI_STATUS Status;
  UINT8* smbiosptr;
  UINT32 smbioslen;
  UINT32 sum;
  UINT32 i;

  Status = EFI_SUCCESS;

  RecieveBuffer("MFG:smbiosreq\n", &smbiosptr, &smbioslen);

  for(i = 0, sum = 0; i < smbioslen; i++) {
    sum += smbiosptr[i];
  }

  DEBUG((DEBUG_ERROR, "Smbios device side checksum: %d\n", sum));

  return Status;
}

EFI_STATUS
EFIAPI
ProvisioningInitialize (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS Status;

  Status = TransmitEKCertificate();
  if (EFI_ERROR(Status)) {
    // Tell the host device that EK certificate retrieval and transmit failed.
    DEBUG((DEBUG_ERROR, "MFG:ekcertfailure\n", Status));
    DEBUG((DEBUG_ERROR, "TransmitEKCertificate returned 0x%x\n", Status));
    return Status;
  }

  Status = RecieveCrossSignedCert();
  if (EFI_ERROR(Status)) {
    // Tell the host device that cross signed cert retrieval failed.
    DEBUG((DEBUG_ERROR, "MFG:devicecertfailure\n", Status));
    DEBUG((DEBUG_ERROR, "RecieveCrossSignedCert returned 0x%x\n", Status));
    return Status;
  }

  Status = RecieveSmbiosValues();
  if (EFI_ERROR(Status)) {
    // Tell the host device that cross signed cert retrieval failed.
    DEBUG((DEBUG_ERROR, "MFG:smbiosfailure\n", Status));
    DEBUG((DEBUG_ERROR, "RecieveSmbiosValues returned 0x%x\n", Status));
    return Status;
  }

  DEBUG((DEBUG_WARN, "%a exit\n", __FUNCTION__));
  return Status;
}
