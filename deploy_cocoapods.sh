# usage ./deploy_cocoapods podreponame

# Push std library version
pod repo push $1 WickrCryptoC.podspec --allow-warnings --private --verbose 

# Push FIPS library version
pod repo push $1 WickrCryptoCFips.podspec --allow-warnings --private --verbose 
