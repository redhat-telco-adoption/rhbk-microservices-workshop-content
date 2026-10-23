# Workshop attendee guide

This is a standalone Antora component for the RHDP lab candidate. It does not
participate in the repository's existing Showroom source allowlist or generated
site. Build it with Antora in the project's development container after the
workshop is integrated into the target RHDP Showroom build.

The Antora playbook uses the RHDP Showroom theme release bundle so it can build
from a published repository checkout without relying on ignored local build
artifacts. Pin the content repository to an immutable Git commit when deploying
it through the Showroom workload.
