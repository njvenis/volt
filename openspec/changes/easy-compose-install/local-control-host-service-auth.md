# Local recovery-control host-service authentication composition

Root records this narrow compatibility decision for the admitted independent recovery-control listener. It does not alter ordinary local-user authentication or grant native roles to host principals.

The existing configured host-service registry and exactly one current observer deployment binding are the host permission model. Preserve the current service-token, actor_kind=service, enabled-policy and explicit-deny checks under the existing policy lock. Do not invent role_ids, service_grants, backup permissions, human identities or synthetic AuthorityContext values when the configured host model supplies none.

Only the factory-validated conjunction of recovery-control-only and verification-only mode, on the actual configured ASGI listener port, may select the shared existing service-token primitive for registered `/recovery-control/v1/` routes. Pin the exact configuration source/port in the backend implementation checkpoint. Missing or contradictory control configuration fails closed. Never select this path from a request Host/Origin/forwarded-TLS header or a cookie. The normal local/main listener's authentication remains unchanged; arbitrary bearer tokens do not become local-user sessions.

The independent listener remains mTLS-only and control-route-only. Actual TLS/no-client-certificate denial and ordinary API route absence are delivery-owned executable checks. Backend tests cover configured service tokens, real current registry binding, actor kind, policy enablement/denial, registry removal and rejection of cookies alone or spoofed listener headers. No OIDC constructor or persisted authentication-mode switch is used to create a local control context.

The existing operations authenticate closure may snapshot the admitted construction-time role and trusted port, then rederive token/actor/current policy authority for each request through the shared existing primitive. Extracting that primitive must preserve OIDC/demo behavior. Control operations keep their existing audit attribution and permissions. No browser obtains host-service authority or private recovery proof.

Implementation, same-reviewer acceptance and actual mTLS/runtime proof remain distinct. This decision closes the model ambiguity only.
