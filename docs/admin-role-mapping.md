# Map a new access permission to an identity provider

Native access requires both a current native grant and a current provider mapping to permit the role and exact source scope. A provider mapping alone creates no permission, membership or principal.

For the RC3 evaluation install and optional Okta setup, see [the installation guide](installation.md#rc3-compose-installation) and [source-free bundle instructions](../deploy/compose/README.md#optional-okta-oidc-evaluation).

The protected bootstrap administrator remains separate from action permissions. Complete the supported bootstrap and explicit native-authority activation first; this form does not activate native authority or grant bootstrap capability.

1. Prepare an unused role UUID in the deployment's identity-provider mapping. For Okta, use that UUID in the configured role IDs for the intended provider group, together with the exact authorised source tuples and source-scope ceilings. Do not reuse a role already owned by a legacy or native permission.
2. In Administration → Access groups, create or edit a group. Select an action from the server catalogue, enter its **Mapped role UUID (optional)**, then choose **Add permission**. Leaving the field blank generates a new UUID; its displayed Role ID can instead be copied into the provider configuration before access is expected.
3. Review and narrow the permission scope, limits and separation of duties, select the group's exact source scopes, provide a reason and evidence reference, and save. Adding a draft permission does not save or grant it.
4. Check the committed group readback and its stable Role ID. Configure the intended principal's native group membership separately. Effective access requires the native membership and current provider mapping to permit the same role and exact source scope.

Role IDs on added or existing permissions are read-only. Invalid UUIDs and duplicate role IDs in the current draft block addition and form submission. The server independently rejects cross-group/legacy collisions, changed revisions and permissions outside the administrator's ceiling; the browser cannot determine those from this draft.

After a rejected save, the draft remains available for correction. After an uncertain response, use the existing exact-request retry; do not change its role or create another permission to guess the outcome. Removing either native authority or the current provider mapping withdraws the affected access; ownership-team membership does not grant actions.

Browser fixtures demonstrate only local UI behaviour, not real Okta, database or deployment integration.
