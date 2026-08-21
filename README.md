# ArtMotife Downloads

Public, immutable release artifacts for the ArtMotife Connector and Chrome Collector. Source code remains in the private ArtMotife repository.

The native release workflow checks out one exact reviewed private commit through a repository-scoped, read-only deploy key. Windows, macOS, and Linux packages are built on their native GitHub runners. A release is published only after the complete platform matrix succeeds.

Studio uses stable `releases/latest/download/...` aliases. Each published release also retains versioned artifacts, SHA-256 evidence, updater metadata, and a combined manifest bound to the private source commit. A scheduled check publishes a new release only when the Connector or Collector version has changed.
