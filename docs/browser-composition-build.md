# Dagon browser SDK ownership

Host applications consume `@dagon/zkapi-browser-sdk` as an immutable
dependency and own their UI, payment-mode runtime, routing, and deployments.

This repository builds the SDK and local client independently of host applications.
See
[SDK integration](../sdk/README.md) for the host API and asset packaging,
and [the local client guide](../zkapi-clientd/README.md) for the independent
local daemon.
