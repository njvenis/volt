"""Immutable release identity and standard image-provisioned Sigstore roots.

No customer policy, expiry override, clock, environment or candidate root selector.
The production image acquires this target with pinned Cosign's ordinary TUF client.
"""
from pathlib import Path
import stat
SIGNER='https://github.com/njvenis/volt/.github/workflows/release-rc4.yml@refs/heads/main'
ISSUER='https://token.actions.githubusercontent.com'
TRUSTED_ROOT=Path('/usr/local/share/volt-verifier/public-trusted-root.json')

def identity(signer,issuer):
    if signer!=SIGNER or issuer!=ISSUER:
        raise ValueError('production verification requires the exact RC4 publisher and issuer')

def keyless_arguments(signer,issuer):
    identity(signer,issuer)
    info=TRUSTED_ROOT.lstat()
    if (not stat.S_ISREG(info.st_mode)or info.st_uid!=0 or info.st_nlink!=1
            or stat.S_IMODE(info.st_mode)!=0o444 or not 0<info.st_size<=65536):
        raise ValueError('standard Sigstore trusted root is not provisioned in the independent production image')
    return ['--certificate-identity',SIGNER,'--certificate-oidc-issuer',ISSUER,
            '--trusted-root',str(TRUSTED_ROOT)]
