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
EXPECTED="bd4cb8f49fbb6eb82cb749284e8aaf8dc0c12ff56b620f11f739514764394480"
ACTUAL=$(echo -n "$(./solution)" | shasum -a 256 | tr -d " -")

if [ "${EXPECTED}" == "${ACTUAL}" ] ; then
    echo "good!"
else
    echo "incorrect"

fi
