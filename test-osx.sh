cd build-osx
xcodebuild -target crypto_test -configuration Release -enableAddressSanitizer YES
bin/Release/crypto_test
