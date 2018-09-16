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
EXPECTED="547b4b369c22ef6d6a772b1a5e1f534fbe91fd0423a7e7fe866970357f369ffb"
ACTUAL=$(echo -n "$(./solution)" | shasum -a 256 | tr -d " -")

if [ "${EXPECTED}" == "${ACTUAL}" ] ; then
    echo "good!"
else
    echo "incorrect"
fi
