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
#define EKCERT_SZ 316
#define TPMIN_SZ 14
#define TPMOUT_SZ 1000

STATIC CONST CHAR16 mDeviceCertVariableName[] = L"ManufacturerDeviceCert";
STATIC CONST CHAR16 mSmbiosSerialNumberName[] = L"SystemSerialNumber1";

#define SEND_REQUEST_TO_HOST(msg) SerialPortWrite((UINT8*)msg, AsciiStrLen(msg))

EFI_STATUS
EFIAPI
RecieveBuffer(
  CHAR8 *requeststring,
  UINT8 **buffer,
  UINT32 *length
)
{
  UINT32 i;
  UINT32 hostsum;
  UINT32 checksum;
  UINT8* tempptr;
  UINTN bytesread;

  SEND_REQUEST_TO_HOST(requeststring);

  while(SerialPortPoll() == FALSE) {}

  // Recieve the 4-byte length of the buffer
  tempptr = (UINT8*) length;
  for(i = 4, bytesread = 0; i > 0;) {
    bytesread = SerialPortRead(tempptr, i);
    i -= bytesread;
    tempptr += bytesread;
  }

  // Allocate space to recieve the buffer.
  *buffer = AllocateZeroPool (*length);
  if (*buffer == NULL) {
    *buffer = NULL;
    return EFI_OUT_OF_RESOURCES;
  }

  // Recieve the buffer
  for(i = *length, tempptr = *buffer; i > 0;) {
    bytesread = SerialPortRead(tempptr, i);
    i -= bytesread;
    tempptr += bytesread;
  }

  //Recieve the 4-byte checksum from the host.
  tempptr = (UINT8*) &hostsum;
  for(i = 4, bytesread = 0; i > 0;) {
    bytesread = SerialPortRead(tempptr, i);
    i -= bytesread;
    tempptr += bytesread;
  }

  // Compute the checksum for the information we recieved.
  for(i = 0, checksum = 0; i < *length; i++) {
    checksum += (*buffer)[i];
  }

  if(hostsum != checksum) {
    DEBUG((DEBUG_ERROR, "Checksum mismatch!\n Expected 0x%x\n Recieved 0x%x\n",
           hostsum, checksum));
    return EFI_CRC_ERROR;
  }

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
TransmitEKCertificate()
{
  EFI_STATUS Status;
  EFI_TCG2_PROTOCOL *Tcg2Protocol;
  UINT32 senduint;
  UINT32 i;

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

  SEND_REQUEST_TO_HOST("MFG:ekcert\r\n");
  senduint = EKCERT_SZ;
  SerialPortWrite((UINT8*)&senduint, 4);
  SerialPortWrite((tpm_out+sizeof(TPM2_RESPONSE_HEADER)), EKCERT_SZ);

  for(i = 0, senduint = 0; i < EKCERT_SZ; i++) {
    senduint += (tpm_out+sizeof(TPM2_RESPONSE_HEADER))[i];
  }
  SerialPortWrite((UINT8*)&senduint, 4);

  return EFI_SUCCESS;
}

EFI_STATUS
EFIAPI
RecieveCrossSignedCert()
{
  EFI_STATUS Status;
  UINT32 certlen;
  UINT8* certptr;

  Status = RecieveBuffer("MFG:devicecert\r\n", &certptr, &certlen);
  if (EFI_ERROR(Status)) {
    goto cleanup;
  }

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

cleanup:
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

  Status = RecieveBuffer("MFG:smbiosserialreq\r\n", &smbiosptr, &smbioslen);

  if (EFI_ERROR(Status)) {
    goto cleanup;
  }

  Status = gRT->SetVariable (
                  (CHAR16 *)mSmbiosSerialNumberName,
                  &gEfiCallerIdGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                  smbioslen,
                  (VOID *)smbiosptr
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Provisioning: Failed to save %s variable to non-volatile storage, Status = %r\n",
      mSmbiosSerialNumberName,
      Status
      ));
  }

cleanup:
  if(smbiosptr != NULL)
    FreePool(smbiosptr);

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
    SEND_REQUEST_TO_HOST("MFG:ekcertfail\r\n");
    DEBUG((DEBUG_ERROR, "TransmitEKCertificate failed. 0x%x\n", Status));
    return Status;
  }

  Status = RecieveCrossSignedCert();
  if (EFI_ERROR(Status)) {
    SEND_REQUEST_TO_HOST("MFG:devicecertfail\r\n");
    DEBUG((DEBUG_ERROR, "RecieveCrossSignedCert failed. 0x%x\n", Status));
    return Status;
  }

  Status = RecieveSmbiosValues();
  if (EFI_ERROR(Status)) {
    SEND_REQUEST_TO_HOST("MFG:smbiosfail\r\n");
    DEBUG((DEBUG_ERROR, "RecieveSmbiosValues failed. 0x%x\n", Status));
    return Status;
  }

  DEBUG((DEBUG_WARN, "%a exit\n", __FUNCTION__));
  return Status;
}
