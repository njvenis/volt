# Independently built pre-runtime verifier. This image is pinned from the
# trusted release page; it is never selected by the downloaded bundle.
FROM gcr.io/projectsigstore/cosign@sha256:0f06154836d2de34f887a5c273506d52ca43edaa1d9e53e6510fa78a48f69c2d AS cosign
FROM python:3.13.11-slim-bookworm@sha256:20080e807bfc404f8450b185cf0fc95d553462673598549613735f70a5b4d5d0 AS verifier-base
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=cosign --chown=65532:65532 /ko-app/cosign /usr/local/bin/cosign
WORKDIR /opt/verifier
COPY --chown=65532:65532 uvm/installer ./uvm/installer
USER 65532:65532
ENTRYPOINT ["python", "-m", "uvm.installer.verifier"]

# Fixture policy and trust roots enter only through a separately provisioned
# local build context. The normal production target has no fixture key, root,
# Rekor URL, environment switch, or package-selectable trust mode.
FROM verifier-base AS verifier-fixture
# These three PUBLIC policy files must be readable by the admitted host UID.
# Private build staging stays 0600; never depend on its mode inside the image.
COPY --from=fixture-policy --chown=65532:65532 --chmod=0444 /fixture-trust.json /usr/local/share/volt-verifier/fixture-trust.json
COPY --from=fixture-policy --chown=65532:65532 --chmod=0444 /fixture.pub /usr/local/share/volt-verifier/fixture.pub
COPY --from=fixture-policy --chown=65532:65532 --chmod=0444 /trusted-root.json /usr/local/share/volt-verifier/trusted-root.json

# Keep the default build target production so an omitted --target can never
# accidentally include the local verification key/root policy.
FROM verifier-base AS verifier-production
