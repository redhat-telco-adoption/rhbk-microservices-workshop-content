# Workshop attendee guide

This is the Antora component for the workshop attendee guide and the
repository's only documentation site. Edit the AsciiDoc under `content/`
directly. Antora is pinned in `package.json`; build it in the project's
development container:

```bash
bash .devcontainer/run.sh --engine podman -- bash -c 'cd workshop/showroom && node_modules/.bin/antora --log-failure-level=warn site.yml'
```

The site is written to `build/www/`.

The Antora playbook uses the RHDP Showroom theme release bundle so it can build
from a published repository checkout without relying on ignored local build
artifacts. Pin the content repository to an immutable Git ref when deploying it
through the Showroom workload. The published content-only repository provides a
root-level Antora playbook for the deployed checkout.

The deployed Showroom reads `site.yml` and `ui-config.yml` from the content
repository root, not from `workshop/showroom/`. When publishing, copy both files
to the root as well.
