# Third-party notices

## Published RC1 inventory

The [RC1 release](https://github.com/njvenis/volt/releases/tag/v0.1.0-rc.1) includes image-specific notices and retained source evidence in its signed offline bundle. Its [notice manifest](https://github.com/njvenis/volt/releases/download/v0.1.0-rc.1/notice-manifest.json) binds the inventory to the released image; the [release workflow](https://github.com/njvenis/volt/actions/runs/41804175229) passed collection and verification. Use the release verification instructions before relying on downloaded evidence.

The notices below describe source dependencies. Every new or modified image needs a fresh image-specific inventory and verification under [the notice collection procedure](docs/third-party-notices.md); RC1 evidence does not cover arbitrary rebuilds.

## DefectDojo CE global OAuthlib 4.0.1

The pinned DefectDojo CE runtime image provides OAuthlib globally for CE's `requests-oauthlib` dependency. The G7 runtime pins this CE-global distribution to OAuthlib 4.0.1, separately from the UVM virtual environment, using the exact PyPI wheel digest recorded in [`docker/g7/versions.lock`](docker/g7/versions.lock). The wheel's PyPI publish provenance is recorded at the corresponding PyPI Integrity API URL in that lock. The release's exact BSD 3-Clause license text is included in [`third-party/notices/OAUTHLIB-4.0.1-BSD-3-Clause.txt`](third-party/notices/OAUTHLIB-4.0.1-BSD-3-Clause.txt); the text is byte-identical in the hash-verified 4.0.1 wheel and source archive.

## Valkey

The optional single-container packaging build uses Valkey 9.1.2 from the pinned `valkey/valkey:9.1.2-alpine` container image. The upstream release is identified by [Valkey's release page](https://valkey.io/download/). The build copies the Valkey server, command-line client and required musl/OpenSSL runtime libraries into the final image. Valkey's upstream license is BSD 3-Clause; its source tree identifies copyright as 2024-present Valkey contributors and 2006-2020 Redis Ltd ([Valkey 9.1.2 COPYING](https://github.com/valkey-io/valkey/blob/9.1.2/COPYING)).

The repository contains only small launcher scripts for these binaries; the binaries themselves are obtained from the pinned image at build time. This source tree does not redistribute the CE or Valkey binaries. A built image does redistribute DefectDojo CE 3.3.100, Valkey, musl/OpenSSL and other base-image content. RC1's package-level inventory is supplied with that release as described above. For another build, collect and include the exact package-level notices and copyright metadata before redistribution. DefectDojo CE is licensed under BSD 3-Clause ([DefectDojo license](https://github.com/DefectDojo/django-DefectDojo/blob/3.3.100/LICENSE.md); [upstream dependency notices](https://github.com/DefectDojo/django-DefectDojo/blob/3.3.100/NOTICE)).

### Valkey 9.1.2 COPYING

#### License 1 — Valkey contributors

BSD 3-Clause License

Copyright (c) 2024-present, Valkey contributors

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#### License 2 — Redis Ltd.

BSD 3-Clause License

Copyright (c) 2006-2020, Redis Ltd.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.

* Neither the name of Redis nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Other runtime and UI dependencies are declared in `uv.lock` and `ui/package-lock.json` and are installed by their package managers rather than copied into this source tree.

## DefectDojo CE 3.3.100

DefectDojo CE is an external runtime base, not source code included in this repository. Its upstream license is BSD 3-Clause. The pinned build recipe copies the resulting CE layer into the optional built image, so this notice alone does not satisfy image redistribution obligations; see the image-specific inventory requirements above.

Copyright (c) 2015-2023 DefectDojo, Inc.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
