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
#include <Library/TimeBaseLib.h>

#include <Library/SerialPortLib.h>

#include <Protocol/TcgService.h>
#include <Protocol/Tcg2Protocol.h>

// This depends on the fTPM implementation. The full response should be sent out
//  and the host side should be responsible for parsing and truncating it.
#define EKCERT_SZ 316
#define TPMIN_SZ 14
#define TPMOUT_SZ 1000


// {72096f5b-2ac7-4e6d-a7bb-bf947d673415}
EFI_GUID ProvisioningGuid =
{ 0x72096f5b, 0x2ac7, 0x4e6d, { 0xa7, 0xbb, 0xbf, 0x94, 0x7d, 0x67, 0x34, 0x15 } };

STATIC CONST CHAR16 mDeviceProvisioned[] = L"DeviceProvisioned";
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
ProvisionedCheck()
{
  EFI_STATUS Status;
  UINTN DataSize;

  DataSize = 0;
  Status = gRT->GetVariable (
                  (CHAR16*) mDeviceProvisioned,
                  &ProvisioningGuid,
                  NULL,
                  &DataSize,
                  NULL
                  );

  DEBUG((DEBUG_ERROR, "%a: Status: 0x%x\n", __FUNCTION__, Status));

  if (Status == EFI_BUFFER_TOO_SMALL) {
      return EFI_SUCCESS;
  }
  return EFI_NOT_READY;
}

EFI_STATUS
EFIAPI
ProvisionedSet()
{
  EFI_STATUS Status;
  UINT8 Data;

  Data = 1;
  Status = gRT->SetVariable (
                  (CHAR16 *) mDeviceProvisioned,
                  &ProvisioningGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                  1,
                  (VOID *)&Data
                  );

  return Status;
}

EFI_STATUS
EFIAPI
RemoteHostExists()
{
  UINT32 hostresponse;
  UINT8* tempptr;
  UINTN bytesread;
  UINT32 i;
  EFI_TIME time1;
  UINTN time1epoch;
  EFI_TIME time2;
  UINTN time2epoch;
  EFI_STATUS Status;

  SEND_REQUEST_TO_HOST("MFG:hostcheck\r\n");

  Status = gRT->GetTime (&time1, NULL);

  time1epoch = EfiTimeToEpoch(&time1);
  while(SerialPortPoll() == FALSE) {
    gRT->GetTime (&time2, NULL);
    time2epoch = EfiTimeToEpoch(&time2);
    if(time2epoch - time1epoch > 5)
      return EFI_NO_RESPONSE;
  }

  //Recieve the 4-byte flag from the host.
  tempptr = (UINT8*) &hostresponse;
  for(i = 4, bytesread = 0; i > 0;) {
    bytesread = SerialPortRead(tempptr, i);
    i -= bytesread;
    tempptr += bytesread;
  }

  if (hostresponse != 0x4D464748) {
    return EFI_NO_RESPONSE;
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
                  &ProvisioningGuid,
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
                  &ProvisioningGuid,
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

  Status = ProvisionedCheck();
  if (Status == EFI_SUCCESS) {
    DEBUG((DEBUG_ERROR, "Device already provisioned!\n"));
    return Status;
  }

  DEBUG((DEBUG_ERROR, "Device unprovisioned, checking for host!\n"));
  Status = RemoteHostExists();
  if (EFI_ERROR(Status)) {
    SEND_REQUEST_TO_HOST("MFG:remotehostfail\r\n");
    DEBUG((DEBUG_ERROR, "RemoteHostExists failed. 0x%x\n", Status));
    return Status;
  }

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

  Status = ProvisionedSet();
  if (EFI_ERROR(Status)) {
    SEND_REQUEST_TO_HOST("MFG:provisionedfail\r\n");
    DEBUG((DEBUG_ERROR, "ProvisionedSet failed. 0x%x\n", Status));
    return Status;
  }

  SEND_REQUEST_TO_HOST("MFG:success\r\n");

  DEBUG((DEBUG_WARN, "%a exit\n", __FUNCTION__));
  return Status;
}
