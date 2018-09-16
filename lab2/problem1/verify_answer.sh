#!/usr/bin/env bash
#
# DO NOT MODIFY THIS FILE.
#
# Run this file with `./verify_answer.sh`
#
# This is a test, so that you can verify that you're returning your answers in
# the right format.  Once the "solution" file returns the correct solution,
# running this function will return "good!"
#
# Remember, EXPECTED is the *hash* of the answer, not the answer itself.
EXPECTED="cf270b02bfc8dd05df220db9ea459a2c3ea50b9a8eedc06a3b6c952ee39f7aa7"
ACTUAL=$(echo -n "$(./solution)" | shasum -a 256 | tr -d " -")

if [ "${EXPECTED}" == "${ACTUAL}" ] ; then
    echo "good!"
else
    echo "incorrect"
fi
