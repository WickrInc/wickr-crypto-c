#
#  Be sure to run `pod spec lint wickr-crypto-c.podspec' to ensure this is a
#  valid spec and to remove all comments including this before submitting the spec.
#
#  To learn more about Podspec attributes see http://docs.cocoapods.org/specification.html
#  To see working Podspecs in the CocoaPods repo see https://github.com/CocoaPods/Specs/
#

Pod::Spec.new do |s|

  # ―――  Spec Metadata  ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  These will help people to find your library, and whilst it
  #  can feel like a chore to fill in it's definitely to your advantage. The
  #  summary should be tweet-length, and the description more in depth.
  #

  s.name         = "WickrCryptoC"
  s.version      = "1.13.9"
  s.summary      = "An implementation of the wickr protocol, written in C"

  # This description is used to generate tags and improve search results.
  #   * Think: What does it do? Why did you write it? What is the focus?
  #   * Try to keep it short, snappy and to the point.
  #   * Write the description between the DESC delimiters below.
  #   * Finally, don't worry about the indent, CocoaPods strips it!
  s.description  = <<-DESC
			Contains C code that encrypts / decrypts wickr secure packets.
			Also contains cryptographic helper functions for the wickr client
			including password / key management functions
                   DESC

  s.homepage     = "https://github.com/WickrInc/wickr-crypto-c.git"
  # s.screenshots  = "www.example.com/screenshots_1.gif", "www.example.com/screenshots_2.gif"


  # ―――  Spec License  ――――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  Licensing your code is important. See http://choosealicense.com for more info.
  #  CocoaPods will detect a license file if there is a named LICENSE*
  #  Popular ones are 'MIT', 'BSD' and 'Apache License, Version 2.0'.
  #

  s.license      = { :type => "WICKR", :file => "LICENSE" }

  # ――― Author Metadata  ――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  Specify the authors of the library, with email addresses. Email addresses
  #  of the authors are extracted from the SCM log. E.g. $ git log. CocoaPods also
  #  accepts just a name if you'd rather not provide an email address.
  #
  #  Specify a social_media_url where others can refer to, for example a twitter
  #  profile URL.
  #

  #s.author             = { "Tom Leavy" => "tom@wickr.com" }
  # Or just: s.author    = "Tom Leavy"
    s.authors            = { "Tom Leavy" => "tom@wickr.com", "Paul Cushman" => "pcushman@wickr.com" }
  # s.social_media_url   = "http://twitter.com/Tom Leavy"

  # ――― Platform Specifics ――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  If this Pod runs only on iOS or OS X, then specify the platform and
  #  the deployment target. You can optionally include the target after the platform.
  #

  # s.platform     = :ios
  s.platform     = :ios, "10.0"

  #  When using multiple platforms
  # s.ios.deployment_target = "8.0"
  # s.osx.deployment_target = "10.9"
  # s.watchos.deployment_target = "2.0"
  # s.tvos.deployment_target = "9.0"


  # ――― Source Location ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  Specify the location from where the source should be retrieved.
  #  Supports git, hg, bzr, svn and HTTP.
  #

  s.source       = { :git => "https://github.com/WickrInc/wickr-crypto-c.git", :tag => "#{s.version}".gsub(/.fips/, '') }

  # ――― Source Code ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  CocoaPods is smart about how it includes source code. For source files
  #  giving a folder will include any swift, h, m, mm, c & cpp files.
  #  For header files it will include any header in the folder.
  #  Not including the public_header_files will make all headers public.
  #

  s.source_files  = "src/**/*.{h,c}", "output_fat/include/**/*.h", "output_fat/lib/libbcrypt.a", "output_fat/lib/libscrypt.a", "output_fat/lib/libprotobuf-c.a", "build_device/third-party/openssl/1.0.2-fips/fips_output/lib/fips_premain.c"
  s.preserve_paths = "src/**/*.{h,c}", "output_fat/**/*", "build_device/**/*"
  s.private_header_files = "src/protobuf/gen/*.h", "src/wickrcrypto/include/wickrcrypto/private/*.h", "src/wickrcrypto/include/wickrcrypto/openssl_*suite.h", "output_fat/include/**/*.h"
  
  # ――― Resources ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  A list of resources included with the Pod. These are copied into the
  #  target bundle with a build phase script. Anything else will be cleaned.
  #  You can preserve files from being cleaned, please don't preserve
  #  non-essential files like tests, examples and documentation.
  #

  # s.resource  = "icon.png"
  # s.resources = "Resources/*.png"

  # s.preserve_paths = "FilesToSave", "MoreFilesToSave"


  # ――― Project Linking ―――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  Link your library with frameworks, or libraries. Libraries do not include
  #  the lib prefix of their name.
  #

  #  s.framework  = "Foundation"
  # s.frameworks = "SomeFramework", "AnotherFramework"

  # s.library   = "iconv"
  s.module_map = "src/wickrcrypto/wickr_crypto_c.modulemap"
  s.script_phase = { :name => 'Openssl Fips Incore', :script => 'if [ ! -f ${PODS_ROOT}/WickrCryptoC/output_fat/bin/incore_macho ]; then exit 0; fi; ${PODS_ROOT}/WickrCryptoC/output_fat/bin/incore_macho --debug -dylib "$CONFIGURATION_BUILD_DIR/$EXECUTABLE_PATH"' } 

  s.prepare_command = <<-CMD
        ./build-ios-fat.sh
  CMD
  # ――― Project Settings ――――――――――――――――――――――――――――――――――――――――――――――――――――――――― #
  #
  #  If your library depends on compiler flags you can set them in the xcconfig hash
  #  where they will only apply to your library. If you depend on other Podspecs
  #  you can include multiple dependencies to ensure it works.

  # s.requires_arc = true

  s.pod_target_xcconfig = { 'OTHER_CFLAGS' => '-DNO_FIPS', 'OTHER_LDFLAGS' => '$(inherited) -L${PODS_ROOT}/WickrCryptoC/output_fat/lib -lcrypto -lbcrypt -lscrypt -lprotobuf-c', 'HEADER_SEARCH_PATHS' => '$(inherited) ${PODS_ROOT}/WickrCryptoC/src/wickrcrypto/include/wickrcrypto ${PODS_ROOT}/WickrCryptoC/output_fat/include' }
    
end
