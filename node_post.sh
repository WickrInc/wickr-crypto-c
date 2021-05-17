if [[ ! -f "package-lock.json" ]]; then
    rm -rf *.podspec *.cmake Doxyfile CMakeLists.txt appveyor.yml build*.sh deploy_cocoapods.sh test src third-party docs docker CMakeModules
fi
