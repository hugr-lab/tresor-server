---
title: The KEK
---

# The KEK

**When**: the KEK's rotation is due (a policy of yours, or the vault's), the KEK moves (a local key to a KMS, one
key to another), or an old version is retired.

**Who**: the platform operator, with the rights on the KEK in its vault, and the right to run the service's
commands. A secrets administrator has no part in it.

The KEK wraps the data keys; the data keys seal the material. A rotation or a move changes the data keys'
wrapping only: no sealed value is touched, and the service serves throughout. The reference is in
[Encryption](../encryption.md).

## Rotating it

### Azure Key Vault, Managed HSM (`azurekeyvault`)

1. **Rotate the key in the vault** (by hand, or its rotation policy). The new version needs the operations
   wrapKey, unwrapKey and **sign** (sign makes the root). The service reads the current version at most once a
   minute, and makes a new data key for new values. Old values still open: their data keys name the old version.
2. **`rewrap`**, once every replica has seen the new version (a minute):

   ```sh
   kubectl -n tresor create job --from=cronjob/<fullname>-rewrap rewrap-$(date +%Y%m%d%H%M)   # Kubernetes
   az containerapp job start -g <rg> -n <prefix>-rewrap                                    # Container Apps
   tresor-server rewrap -config server.yaml                                                 # a VM
   ```

   Every data key is unwrapped under its old version and wrapped under the current one, compare-and-set. It goes
   on past a data key it cannot rewrap, names each, and exits `1`: run it again once that is fixed.
3. **Retire the old versions** in the vault once `rewrap` has passed.

### OpenBao, Vault Transit (`vault`)

1. `bao write -f transit/keys/tresor-kek/rotate` (`vault write`, the same).
2. `rewrap`, as above.
3. Raise the key's `min_decryption_version` to retire the old versions. Never set `min_encryption_version`: it
   refuses the HMAC at older versions, and the service refuses such a key.

### AWS KMS (`awskms`)

KMS rotates the encryption key's material inside the same key; old material still decrypts. The KEK's id does
not change: no `rewrap`. The HMAC key (`mac_key`) does not rotate. Another key is a [move](#moving-to-another-kek).
See [AWS](../aws.md#the-kek-two-keys).

### GCP Cloud KMS (`gcpkms`)

1. A new primary version of `key`: a new KEK id, and new data keys under it.
2. `rewrap` moves the old ones.
3. Disable the old versions: they decrypt until then.

The MAC version (`mac_key`) does not change by itself; a new one is a [move](#moving-to-another-kek). See
[GCP](../gcp.md#the-kek-a-key-and-a-mac-version).

### A local key (`local`)

A local key has no versions: a new key is a [move](#moving-to-another-kek), from the old local key to the new
one (or to a KMS).

## Moving to another KEK

From a local key to Key Vault, Vault or a KMS; from one local key to another; from one Key Vault key to another;
from one Transit key (or mount) to another on the same Vault server (spec 011). Moving between two Vault servers
is not supported: one `vault:` client serves every Vault KEK.

1. **Both KEKs configured.** The new one is `keys`; the old one is listed under `keys.previous`, read only: data
   keys under it still unwrap, nothing new is wrapped with it. Give the service its rights on the new KEK, then
   deploy ([Changing the configuration](configuration.md)).

   ```yaml
   keys:
     kind: azurekeyvault
     key: https://corp-kv.vault.azure.net/keys/tresor-kek
     previous:
       - {kind: local, key_file: /var/run/tresor/kek-old/kek}
   ```

   On the chart, `localKEK.previousSecretName` mounts the old local KEK and lists it in `keys.previous`; a new
   local KEK is `localKEK.secretName`. Readiness checks each previous KEK (`keys.previous[0]`, …).
2. **Move the data keys**, once the rollout has finished (a replica still on the old configuration makes new data
   keys under the old KEK): `rewrap`, as above. Every data key under a previous KEK is wrapped under the new one,
   its tag made under the new KEK's root. Run it until it moves none.
3. **Remove `keys.previous`**, deploy, then retire the old KEK: delete the local key's file and its Secret, or
   disable the old key in its vault.

- Until step 3 the old KEK is trusted as the current one is: `rewrap` carries over every data key authentic under
  it.
- A move keeps the data keys, so it keeps every MAC (the SQL stores' and the Kubernetes store's).

## Check

- `rewrap` exits `0`, and its log counts the data keys rewrapped.
- Readiness: `keys` (and each `keys.previous[i]`) is `ok`.
- The console's Service screen: the KEK's kind and current version, and any previous KEK.
- A read of a secret written before the rotation, and one written after.
- Before step 3 of a move: a second `rewrap` moves none.

## Back

- **A rotation**: the old versions stay usable until you retire them. Retire nothing until `rewrap` has passed.
- **A move, before step 3**: swap `keys` and `keys.previous` back and deploy, then `rewrap`: the data keys move
  back to the old KEK.
- **After a version or a KEK is retired**: a data key still under it is refused (`500`), never read as empty.
  Re-enable the version, or put the KEK back in `keys.previous`, and `rewrap`.
- **Backups**: a backup taken before a `rewrap` holds data keys under the old versions or the old KEK. Keep them
  while such a backup may be restored ([Backup and restore](backup-restore.md)).

## A KEK that leaked

Not written as a runbook. A move to another KEK keeps the same data keys: whoever holds the old KEK and a copy of
the store still opens that copy.
