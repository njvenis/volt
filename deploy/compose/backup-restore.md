# Compose cold backup and restore

This is a cold, single-image evaluation procedure. It has no RPO/RTO promise and does not demonstrate a live backup controller or production recovery. It captures all three Compose volumes together with OIDC/client and recovery keys, application secrets, the exact image ID, bundle version and configuration digest.

## Capture

1. Stop admission at the configured TLS proxy and prevent new external provider commands.
2. Confirm through the external provider/host integration controls that no outbound command, webhook, polling run or other effect is in flight or unresolved. The Compose installer does not own this independent effect journal; if that confirmation is unavailable, do not take or claim a coordinated backup.
3. Stop VOLT using `python3 setup.py stop INSTANCE`. The command allows ten minutes for the supervisor's sequential cleanup, then requires exit 0, no OOM, and successful writer, worker and PostgreSQL cleanup evidence from the current container run. Forced termination or cleanup failure blocks backup. Do not capture until this succeeds. This stops UVM, CE, workers and the in-container databases before volume reads.
4. Run `python3 setup.py backup-record INSTANCE` while it remains stopped. This records each store’s file-content, ownership and permission inventory, including explicitly empty media or state stores. Copy the complete private instance directory, including `.env`, `instance.json`, `oidc.json` and `secrets/`, into the protected backup set. Capture exact image ID and bundle version from `instance.json` and `VERSION`. Preserve the original absolute instance and extracted-bundle paths; this restore procedure intentionally does not relocate or rename an instance.
5. With the container stopped, archive each exact project volume using the admitted image as an offline tar helper. Set `IMAGE_ID` to the `image` value in `instance.json`, `PROJECT` to its `project` value, and `BACKUP_DIR` to a private existing directory. The image contains GNU tar; the helper has no network and no Docker socket:

   ```sh
   for store in postgres media state; do
     docker run --rm --network none --read-only --user 0:0 \
       --mount "type=volume,src=${PROJECT}_${store},dst=/source,readonly" \
       --mount "type=bind,src=${BACKUP_DIR},dst=/backup" \
       --entrypoint /bin/tar "$IMAGE_ID" \
       --numeric-owner -C /source -cpf "/backup/${PROJECT}_${store}.tar" .
   done
   sha256sum "$BACKUP_DIR"/"$PROJECT"_*.tar
   ```

   Also record checksums for the copied instance files. Restrict the backup set to the same private handling boundary as the source.
6. Retain the verified backup outside the Docker host. Re-enable the proxy only after the instance is restarted and health/readback checks pass.

Do not copy a running PostgreSQL volume or only one of the three volumes. Do not treat a UVM API success, Compose health, or image pull as proof that an archive is consistent.

## Restore

Restore all three archives and the exact private instance directory to a fresh Docker host at the same absolute paths, with the same project name and exact bundle version. Verify every recorded digest before extraction, and load the exact recorded image ID from the host's protected image archive. Confirm the project resources do not already exist. From the extracted bundle directory, run `python3 setup.py restore-provision INSTANCE`. This creates only the three correctly owner-labelled empty volumes and private network; it does not create or start the runtime. Import each archive into its matching volume using the offline helper below, then run `python3 setup.py restore-admit INSTANCE`. That checks all three imports exactly match the captured inventories (including valid empty stores) and verifies PostgreSQL's `PG_VERSION`. It refuses runtime startup before all checks pass:

```sh
for store in postgres media state; do
  docker run --rm --network none --read-only --user 0:0 \
    --mount "type=volume,src=${PROJECT}_${store},dst=/restore" \
    --mount "type=bind,src=${BACKUP_DIR},dst=/backup,readonly" \
    --entrypoint /bin/tar "$IMAGE_ID" \
    --numeric-owner -C /restore -xpf "/backup/${PROJECT}_${store}.tar"
done
```

Only after `restore-admit` succeeds, run `python3 setup.py start INSTANCE`. Keep the TLS proxy closed and external provider commands fenced while checking image admission, all three volume identities, OIDC config digest, secret/key presence, database health, application health, the trusted identity-sync freshness contract and a permission-scoped readback. Reconcile external effect state with the independent provider/controller before reopening ingress. Relocation, project renaming, image changes, and schema migration are not supported by this procedure. These checks are operator gates; `restore-admit` is not a substitute for application-level fenced verification.

This procedure does not authorize startup on a different image, schema migration, database downgrade, volume adoption, key regeneration, or external writer cutover. If the exact image or effect-fence readback is unavailable, keep ingress closed and use the separately reviewed G7 recovery-control contract. Image rollback alone is not schema rollback.
