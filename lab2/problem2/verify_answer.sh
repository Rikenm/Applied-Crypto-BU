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
EXPECTED="f0783f558e348978cf298fbb271a9227ac644a542d7d6d173f24f54bf4f709d3"
ACTUAL=$(echo -n "$(./solution)" | shasum -a 256 | tr -d " -")

if [ "${EXPECTED}" == "${ACTUAL}" ] ; then
    echo "good!"
else
    echo "incorrect"
fi
