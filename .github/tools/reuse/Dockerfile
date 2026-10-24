# Copyright the cfgaudit contributors
# SPDX-License-Identifier: Apache-2.0

# reuse for the REUSE job in ci.yml (#789), pinned by digest. A file of its
# own so Dependabot updates the pin. The PyPI wheel of reuse needs a newer
# glibc than the runner has, and building the sdist would pull its build
# backend unpinned.
FROM fsfe/reuse:6.2.0@sha256:85462a75c0f8efda09ddd190b92816b70e7662577c8427429e11e1b9f25a992e
