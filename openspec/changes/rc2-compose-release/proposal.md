# RC2 Compose compatible release preparation

Prepare a separately versioned VOLT 0.1.0-rc.2 image and source-free Compose bundle. The candidate pipeline builds once from an exact clean main revision, binds the source archive digest and Compose capability labels to the image, qualifies that same image through a synthetic Compose lifecycle and cold restore, then retains the gated candidate for an explicitly approved later publication dispatch. It does not create a Git tag or GitHub Release.

## Requirements

CR-01, CR-08, CR-09, CR-10, CR-11, NFR-04, NFR-05, NFR-06 and the approved Compose primary installation contract.

## Boundaries

Publication remains a separate reviewer-gated action and consumes only the retained candidate run matching repository, workflow, main branch, exact source SHA and successful completion. RC1 assets and historical verification support remain intact. The local demo and restore exercise are synthetic, loopback-only evidence and establish no named OIDC provider, production hosting, or independent-host recovery claim.
