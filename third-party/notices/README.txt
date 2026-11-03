This directory contains license and notice text assets shipped with the VOLT image.

DISTLIB-LAUNCHER-BSD-2.txt is the exact two-condition launcher notice from distlib 0.4.2 PC/launcher.c. The pinned pip 26.2.1 vendor manifest selects distlib 0.4.2.

SETUPTOOLS-84.0.0-MIT-LICENSE.txt is copied from the LICENSE member in the setuptools 84.0.0 wheel. SETUPTOOLS-LAUNCHERS.json records the PyPI-published wheel checksum and each launcher member's SHA-256. The collector downloads that exact wheel, verifies its checksum and license text, then requires all eight image launcher files to match their wheel members byte-for-byte. PyPI reports that this wheel has no provenance metadata.

OPENSSL-APACHE-2.0.txt is the Apache License 2.0 text applicable to OpenSSL 3.5.x; upstream OpenSSL specifies that 3.0-and-later releases use Apache-2.0.

MUSL-1.2.6-COPYRIGHT is the full copyright and license file from the version-tagged musl 1.2.6 source mirror. MUSL-LICENSE-EVIDENCE.json records its source URLs, digest and the limitation that the official release archive could not be downloaded in this environment. The collector checks the tagged source text, Alpine package metadata and copied musl binary hashes together.

REACT-UI-MIT-LICENSE.txt is the verbatim LICENSE file from integrity-verified npm
packages React 19.3.0, React DOM 19.3.0, and Scheduler 0.28.0. Their package
archive SHA-512 values and file paths are recorded in
ui-production-license-assets.json. The three packages contain byte-identical
license files.

The image-specific release inventory is generated from the immutable final image.
This directory alone does not complete image license review.

DISTLIB-PIP-WHEEL-LICENSE.txt is the verbatim distlib LICENSE.txt member in the
pinned pip 26.2.1 wheel. The collector verifies the wheel digest, installed
vendor.txt, exact distlib 0.4.2 PC/launcher.c source header and each of the six
image PE members, then retains the source wheel and launcher source in its
image-specific inventory.
