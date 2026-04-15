#!/usr/bin/env bash
# Shared test helpers for install-xen-orchestra BATS unit tests.
# Load with: load '../helpers/mock_helpers'

# Stub out privileged commands so unit tests never touch the real system.
sudo() { true; }
export -f sudo

systemctl() { true; }
export -f systemctl

useradd() { true; }
export -f useradd

# Source the main script without executing main().
# The _XO_SOURCE_ONLY guard at the bottom of the script prevents main() from running.
load_script() {
    _XO_SOURCE_ONLY=1 source "${BATS_TEST_DIRNAME}/../../install-xen-orchestra.sh"
}
