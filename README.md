Prototype code for a wrapper from decaf library by Mike Hanburg to wickr-crypto codebase.

INSTRUCTIONS:
    pull mike's lib as a submodule:
        git submodule update --remote
	edit files:
		src/crypto/ed448_suite.c
		src/crypto/ed448_suite.h
		src/ed448_test/test_main.c
	build:
		LINUX:
			make -f makefile.linux ed448_test
		OSX:
			make -f makefile.osx ed448_test (untested for now)
