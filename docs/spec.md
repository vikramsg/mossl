# Lightbug HTTP Integration Spec

This specification outlines the steps to integrate `lightbug_http` into the project and verify its functionality with a Mojo script.

## TODOs
- [x] Install `lightbug_http` as a dependency (using Mojo 0.25.6.1 and lightbug_http 0.25.6 for compatibility)
- [x] Research/Find a suitable HTTP endpoint for testing (used httpbin.org/get)
- [x] Write a Mojo script using `lightbug_http` to make an API call
- [x] Verify the script succeeds and prints the response
- [x] Final review of the implementation against the spec

## Acceptance Criteria
- A working Mojo script that successfully performs an HTTP request using `lightbug_http`. (Verified with `scripts/test_lightbug.mojo`)
- The script is tested and its output verified. (Verified output status 200 and JSON response)
