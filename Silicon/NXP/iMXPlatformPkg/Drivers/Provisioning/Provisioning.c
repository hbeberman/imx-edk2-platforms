/** @file
*  This file contains routines used to provision a device during manufacturing.
*
*  Copyright (c) 2019 Microsoft Corporation. All rights reserved.
*
*  This program and the accompanying materials
*  are licensed and made available under the terms and conditions of the BSD License
*  which accompanies this distribution.  The full text of the license may be found at
*  http://opensource.org/licenses/bsd-license.php
*
*  THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
*  WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.
*
**/

#include <Uefi.h>

#include <IndustryStandard/Tpm20.h>

#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/SerialPortLib.h>
#include <Library/TimeBaseLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>

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

#define SEND_REQUEST_TO_HOST(msg) SerialPortWrite ((UINT8*)msg, AsciiStrLen (msg))


/**
  Send a request string to the manufacturing host and recieve a response buffer.

  Send an Ascii string to a remote host, then await 4 bytes for a buffer length,
  length bytes of a buffer, then 4 bytes of a buffer checksum.

  @param[in] RequestString    Pointer to the Ascii string to send to the host.

  @param[out] Buffer          Double pointer to return the allocated buffer of
                              data recieved from the host.
  @param[out] Length          Pointer to the length of the recieved buffer.

  @retval  EFI_SUCCESS            The host sent a buffer successfully.
  @retval  EFI_OUT_OF_RESOURCES   Unable to allocate space for the buffer.
  @retval  EFI_CRC_ERROR          Checksum mismatch between device and host.

**/
EFI_STATUS
EFIAPI
RecieveBuffer (
  CHAR8   *RequestString,
  UINT8   **Buffer,
  UINT32  *Length
  )
{
  UINTN   BytesRead;
  UINT32  Checksum;
  UINTN   i;
  UINT32  RecievedChecksum;
  UINT8   *TempPtr;

  SEND_REQUEST_TO_HOST (RequestString);

  while (SerialPortPoll () == FALSE);

  // Recieve the 4-byte length of the buffer
  TempPtr = (UINT8*) Length;
  for (i = 4, BytesRead = 0; i > 0;) {
    BytesRead = SerialPortRead (TempPtr, i);
    i -= BytesRead;
    TempPtr += BytesRead;
  }

  // Allocate space for the buffer.
  *Buffer = AllocateZeroPool (*Length);
  if (*Buffer == NULL) {
    return EFI_OUT_OF_RESOURCES;
  }

  // Recieve the buffer from the host.
  for (i = *Length, TempPtr = *Buffer; i > 0;) {
    BytesRead = SerialPortRead (TempPtr, i);
    i -= BytesRead;
    TempPtr += BytesRead;
  }

  // Recieve the 4-byte checksum from the host.
  TempPtr = (UINT8*) &RecievedChecksum;
  for (i = 4, BytesRead = 0; i > 0;) {
    BytesRead = SerialPortRead (TempPtr, i);
    i -= BytesRead;
    TempPtr += BytesRead;
  }

  // Compute the checksum for the information we recieved.
  for (i = 0, Checksum = 0; i < *Length; i++) {
    Checksum += (*Buffer)[i];
  }

  if (RecievedChecksum != Checksum) {
    DEBUG ((DEBUG_ERROR, "Checksum mismatch!\n Expected 0x%x\n Computed 0x%x\n",
           RecievedChecksum, Checksum));
    return EFI_CRC_ERROR;
  }

  return EFI_SUCCESS;
}

/**
  Check UEFI variables for the DeviceProvisioned variable

  @retval  EFI_SUCCESS           DeviceProvisioned variable is present.
  @retval  EFI_NOT_READY         DeviceProvisioned variable is not present.

**/
EFI_STATUS
EFIAPI
ProvisionedCheck ()
{
  UINTN       DataSize;
  EFI_STATUS  Status;

  DataSize = 0;
  Status = gRT->GetVariable (
                  (CHAR16*) mDeviceProvisioned,
                  &ProvisioningGuid,
                  NULL,
                  &DataSize,
                  NULL
                  );

  if (Status == EFI_BUFFER_TOO_SMALL) {
      return EFI_SUCCESS;
  }

  return EFI_NOT_READY;
}

/**
  Set the DeviceProvisioned variable in UEFI variables

  @retval  EFI_SUCCESS           DeviceProvisioned variable was set.
  @retval  EFI_STATUS            Return the status of gRT->SetVariable ().

**/
EFI_STATUS
EFIAPI
ProvisionedSet ()
{

  UINT8       Data;
  EFI_STATUS  Status;

  Data = 1;
  Status = gRT->SetVariable (
                  (CHAR16 *) mDeviceProvisioned,
                  &ProvisioningGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  1,
                  (VOID *)&Data
                  );

  return Status;
}

/**
  Check over serial that a manufacturing host is present.

  Challenge the remote host with MFG:hostcheck and await a response of "MFGH".
  Fail if the host does not respond within 5 secs or the response is incorrect.

  @retval  EFI_SUCCESS           The remote host is present and responsive.
  @retval  EFI_NO_RESPONSE       No response from the remote host.
  @retval  EFI_UNSUPPORTED       Incorrect response from the remote host.

**/
EFI_STATUS
EFIAPI
RemoteHostExists ()
{
  UINTN       BytesRead;
  UINTN       CurrentEpoch;
  UINT32      HostResponse;
  UINTN       i;
  UINTN       StartEpoch;
  EFI_STATUS  Status;
  UINT8       *TempPtr;
  EFI_TIME    Time;


  SEND_REQUEST_TO_HOST ("MFG:hostcheck\r\n");

  Status = gRT->GetTime (&Time, NULL);
  if (EFI_ERROR (Status)) {
    return Status;
  }
  StartEpoch = EfiTimeToEpoch (&Time);

  // Timeout the poll in 5 seconds to allow a device in the field to continue.
  while (SerialPortPoll () == FALSE) {
    Status = gRT->GetTime (&Time, NULL);
    if (EFI_ERROR (Status)) {
      return Status;
    }
    CurrentEpoch = EfiTimeToEpoch (&Time);
    if (CurrentEpoch - StartEpoch > 5) {
      return EFI_NO_RESPONSE;
    }
  }

  // Recieve the 4-byte flag from the host.
  TempPtr = (UINT8*) &HostResponse;
  for (i = 4, BytesRead = 0; i > 0;) {
    BytesRead = SerialPortRead (TempPtr, i);
    i -= BytesRead;
    TempPtr += BytesRead;
  }

  if (HostResponse != 0x4D464748) {
    return EFI_UNSUPPORTED;
  }

  return EFI_SUCCESS;
}

/**
  Retrieve the Endorsement Key Certificate from the TPM and send it to the
  manufacturing host.

  Use the Tcg2Protocol to submit the EK Cert read command to the TPM.
  Notify the remote host to recieve the ekcert by sending MFG:ekcert.

  @retval  EFI_SUCCESS           Successfully sent the EK Certificate.
  @retval  EFI_NOT_FOUND         Unable to retrieve the EK Certificate from TPM
  @retval  EFI_STATUS            Return the status of gBS->LocateProtocol ().

**/
EFI_STATUS
EFIAPI
TransmitEKCertificate ()
{
  UINT32             i;
  UINT32             SendUint32;
  EFI_STATUS         Status;
  EFI_TCG2_PROTOCOL  *Tcg2Protocol;
  UINT8              TpmIn[TPMIN_SZ] = { 0x80, 0x01,  // TPM_ST_NO_SESSIONS
                            0x00, 0x00, 0x00, 0x0e,   // Command size is 0xe
                            0x00, 0x00, 0x01, 0x73,   // TPM_CC_ReadPublic 0x173
                            0x81, 0x01, 0x00, 0x01 }; // 0x81010001 is EK Cert
  UINT8              TpmOut[TPMOUT_SZ];

  Status = gBS->LocateProtocol (&gEfiTcg2ProtocolGuid, NULL,
                                (VOID **) &Tcg2Protocol);
  if (EFI_ERROR (Status)){
    DEBUG ((DEBUG_ERROR, "%a: failed to locate protocol. Status: 0x%x\n",
           __FUNCTION__, Status));
    return Status;
  }

  Status = Tcg2Protocol->SubmitCommand (
                          Tcg2Protocol,
                          TPMIN_SZ,
                          TpmIn,
                          TPMOUT_SZ,
                          TpmOut
                          );

  if (SwapBytes32 (((TPM2_RESPONSE_HEADER*)TpmOut)->responseCode) != TPM_RC_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "%a: Failed to retrieve EK Cert from TPM!\n", __FUNCTION__));
    return EFI_NOT_FOUND;
  }

  SEND_REQUEST_TO_HOST ("MFG:ekcert\r\n");

  SendUint32 = EKCERT_SZ;
  SerialPortWrite ((UINT8*)&SendUint32, 4);
  SerialPortWrite ((TpmOut+sizeof(TPM2_RESPONSE_HEADER)), EKCERT_SZ);
  for (i = 0, SendUint32 = 0; i < EKCERT_SZ; i++) {
    SendUint32 += (TpmOut+sizeof(TPM2_RESPONSE_HEADER))[i];
  }
  SerialPortWrite ((UINT8*)&SendUint32, 4);

  return EFI_SUCCESS;
}

/**
  Recieve a cross-signed device certificate from the manufacturing host.

  Store the cross-signed device certificate in UEFI variables.

  @retval  EFI_SUCCESS           Successfully stored the device certificate.
  @retval  EFI_STATUS            Return the status of RecieveBuffer ().
  @retval  EFI_STATUS            Return the status of gRT->SetVariable ().

**/
EFI_STATUS
EFIAPI
RecieveCrossSignedCert ()
{
  UINT32      CertLen;
  UINT8*      CertPtr;
  EFI_STATUS  Status;

  Status = RecieveBuffer ("MFG:devicecert\r\n", &CertPtr, &CertLen);
  if (EFI_ERROR (Status)) {
    goto cleanup;
  }

  Status = gRT->SetVariable (
                  (CHAR16 *)mDeviceCertVariableName,
                  &ProvisioningGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  CertLen,
                  (VOID *)CertPtr
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Provisioning: Failed to save %s variable, Status = %r\n",
      mDeviceCertVariableName,
      Status
      ));
  }

cleanup:
  if (CertPtr != NULL)
    FreePool (CertPtr);

  return Status;
}

/**
  Recieve a SMBIOS values from the manufacturing host.

  Store the device-specific SMBIOS values in UEFI variables.

  @retval  EFI_SUCCESS           Successfully stored the smbios values.
  @retval  EFI_STATUS            Return the status of RecieveBuffer ().
  @retval  EFI_STATUS            Return the status of gRT->SetVariable ().

**/
EFI_STATUS
EFIAPI
RecieveSmbiosValues ()
{
  UINT32      SmbiosLen;
  UINT8*      SmbiosPtr;
  EFI_STATUS  Status;

  Status = RecieveBuffer ("MFG:smbiosserialreq\r\n", &SmbiosPtr, &SmbiosLen);
  if (EFI_ERROR (Status)) {
    goto cleanup;
  }

  Status = gRT->SetVariable (
                  (CHAR16 *)mSmbiosSerialNumberName,
                  &ProvisioningGuid,
                  EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS |
                  EFI_VARIABLE_RUNTIME_ACCESS,
                  SmbiosLen,
                  (VOID *)SmbiosPtr
                  );

  if (EFI_ERROR (Status)) {
    DEBUG ((
      DEBUG_ERROR,
      "Provisioning: Failed to save %s variable, Status = %r\n",
      mSmbiosSerialNumberName,
      Status
      ));
  }

cleanup:
  if (SmbiosPtr != NULL)
    FreePool (SmbiosPtr);

  return Status;
}

/**
  Run through the device provisioning flow if necessary.

  1) Exit immediately if UEFI variables says the device is already provisioned.
  2) Stall for 5 seconds then exit if theres no manufacturing host.
  3) Send the EK Certificate to a manufacturing host.
  4) Recieve a device certificate from the manufacturing host.
  5) Recieve a SMBIOS values from the manufacturing host.
  6) Store a UEFI variable indicating the device is provisioned.

  @retval  EFI_SUCCESS           Successfully provisioned the device.
  @retval  EFI_STATUS            Return the status of the failing sub-function.

**/
EFI_STATUS
EFIAPI
ProvisioningInitialize (
  IN EFI_HANDLE       ImageHandle,
  IN EFI_SYSTEM_TABLE *SystemTable
  )
{
  EFI_STATUS  Status;

  Status = ProvisionedCheck ();
  if (Status == EFI_SUCCESS) {
    DEBUG ((DEBUG_ERROR, "Device already provisioned!\n"));
    return Status;
  }

  DEBUG ((DEBUG_ERROR, "Device unprovisioned, checking for host!\n"));
  Status = RemoteHostExists ();
  if (EFI_ERROR (Status)) {
    SEND_REQUEST_TO_HOST ("MFG:remotehostfail\r\n");
    DEBUG ((DEBUG_ERROR, "RemoteHostExists failed. 0x%x\n", Status));
    return Status;
  }

  Status = TransmitEKCertificate ();
  if (EFI_ERROR (Status)) {
    SEND_REQUEST_TO_HOST ("MFG:ekcertfail\r\n");
    DEBUG ((DEBUG_ERROR, "TransmitEKCertificate failed. 0x%x\n", Status));
    return Status;
  }

  Status = RecieveCrossSignedCert ();
  if (EFI_ERROR (Status)) {
    SEND_REQUEST_TO_HOST ("MFG:devicecertfail\r\n");
    DEBUG ((DEBUG_ERROR, "RecieveCrossSignedCert failed. 0x%x\n", Status));
    return Status;
  }

  Status = RecieveSmbiosValues ();
  if (EFI_ERROR (Status)) {
    SEND_REQUEST_TO_HOST ("MFG:smbiosfail\r\n");
    DEBUG ((DEBUG_ERROR, "RecieveSmbiosValues failed. 0x%x\n", Status));
    return Status;
  }

  Status = ProvisionedSet ();
  if (EFI_ERROR (Status)) {
    SEND_REQUEST_TO_HOST ("MFG:provisionedfail\r\n");
    DEBUG ((DEBUG_ERROR, "ProvisionedSet failed. 0x%x\n", Status));
    return Status;
  }

  SEND_REQUEST_TO_HOST ("MFG:success\r\n");

  DEBUG ((DEBUG_WARN, "%a exit\n", __FUNCTION__));
  return Status;
}
