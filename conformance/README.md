# Conformance cases

Each JSON entry supplies a YAML policy, one policy call, and either an expected
decision or a stable policy-error code. Python and Rust test runners load the
same files; adding a v1 semantic requires adding a case here first.

`cases/simulator_v1.json` is the equivalent fixture for the offline simulator:
it supplies policy texts, JSON Lines trace events, expected reports, and stable
trace errors. Both runtimes must serialize its reports identically.

`cases/inline_adapter_v1.json` defines the host-local adapter boundary:
normalized requests, allow-only effects, deadline failures, and invalid request
values. Both runtimes must produce equivalent responses from this fixture.
