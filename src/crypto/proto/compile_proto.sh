rm -rf ../*.pb.*
../../../build-osx/third-party/bin/protoc-c --c_out=../ *.proto
