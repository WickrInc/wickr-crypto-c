#!/bin/sh
# Protobuf requires gtest to be installed in the source directory even
# before autogen.sh runs!  When it was hosted on google, they used a
# svn external reference, but in moving to github choose NOT to do a
# git submodule.  Worse, the autogen script they have in protobuf attempts
# to retrieve the gtest code in a tar format from a site that no longer 
# exists.  This pre-script simply retrieves the gtest code and runs autogen.sh.
# Because curl cannot follow the github redirects even with the -l option we
# have to use the actual target uri, which may change in the future.  The
# version of protobuf we are using, for compatibility with protobuf-c, is
# 2.6.1, and this is matched with gtest-1.5.0.

if test ! -f ./configure ; then

echo IN PROTOBUF-AUTOGEN.SH and .configure not found!
	# in case a prior run...
	rm -rf gtest	

	# fetch and install gtest from new location...
	curl https://codeload.github.com/google/googletest/tar.gz/release-1.5.0 |\
		 tar xz
	mv googletest-release-1.5.0 gtest
	./autogen.sh
else
echo IN PROTOBUF-AUTOGEN.SH and .configure IS found!
fi
