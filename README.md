LibCryptParse
=============
Soon to be a library for parsing linux' `/proc/crypto` file

Now collecting `/proc/crypto` files from the wild to analyze them and search for
common patterns.

Contributing
------------
For now, you can help by running `./collect.sh` on your Linux machine. It should
be run from the project root directory and it will save a copy of your
`/proc/crypto` file into the `samples/` subdirectory.
