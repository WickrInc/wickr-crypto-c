
# usage ./deploy_cocoapods podreponame

rm -rf pod_deploy
mkdir pod_deploy
cp WickrCryptoC.podspec pod_deploy/
cd pod_deploy

# Push std library version
pod repo push $1 WickrCryptoC.podspec --allow-warnings --private --verbose 

sed -i '' -e '19s/\([0-9]\{1,2\}\.[0-9]\{1,2\}\.[0-9]\{1,2\}\)/\1.fips/' WickrCryptoC.podspec
sed -i '' -e 's/\.\/build/FIPS=true\ \.\/build/' WickrCryptoC.podspec
sed -i '' -e 's/NO_FIPS/FIPS/' WickrCryptoC.podspec

# Push FIPS library version
pod repo push $1 WickrCryptoC.podspec --allow-warnings --private --verbose 

