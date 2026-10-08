#!/bin/sh
# TEST FIXTURE: never executed by the tests.
# curl in a comment must not count
curl -fsSL https://installer.example.invalid/setup | sh
