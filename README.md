# Confidential DataHub

This is a draft repo, including the following things:
- `kms`: KMS/Vault drivers
- `secret`: Sealed secret for Kubernetes definitions and implementations

## Supported KMS
- `alibaba KMS` (in test): there should be an env `KMS_BINARY_PATH` pointing to the kms client binary.