PKI_Playhouse
=============

My very own "PKI" Playhouse. Just a testing-ground for encipher-stuff, encoding, keys etc.

# Included testcases

* Generate HMACs
* Generate GMACs
* Generate AES-symmetric keys
    * Convert to / from Base64 to SecretKey
* Keys in Keystores
* Different types of Keystores (JKS, JKCES, p12 etc..)
* Radix-stuff
* Import certificates based on a hostname to an existing or new keystore.

# Import certificates from hostname

You can download and store x509 certificates in a keystore based on a hostname, quite simple.

    com.vegaasen.playhouse.run.ImportCertificate <hostname> <password> <outputKeyStore> <existingKeyStore(will append to existing keystore)>
    #example
    com.vegaasen.playhouse.run.ImportCertificate www.telenor.no telenor /tmp/keystore.out

Then use the keytool to look into a keystore. Example:

    keytool -list -v -keystore keystore.out

# Generate / Usage of the provided Keystore

## Generate a keystore with the program

    com.vegaasen.playhouse.run.KeyStoreWithSymmetric ea2d841105bbcafa80070ea76446425A3 /tmp/something.jceks some-key password

## Generate an AES-Key

This is how you would typically generate a AESKey with the default Keytool-command-line thingie provided by Sun/Oracle..

* keytool -genseckey -alias my-secret -keyalg AES -keysize 192 -storetype JCEKS -keystore fun.jceks
* keytool -list -keystore fun.jceks -storetype JCEKS

When listing the contents of the keystore, it would result in similar to this:

    vegaasen@vegaasen-ppc1:~/_develop/java/PKI_Playhouse/src/main/resources$ keytool -list -storetype jceks -keystore fun.jceks
    Enter keystore password:

    Keystore type: JCEKS
    Keystore provider: SunJCE

    Your keystore contains 2 entries

    my-second-secret, Apr 1, 2013, SecretKeyEntry,
    my-secret, Mar 30, 2013, SecretKeyEntry,

Password for both the AES-generated key and the keystore: vegard

# Performance testing for AES versus Certificates (Symmetric vs Asymmetric) signing

    Run with: java -cp PKI-1.0-jar-with-dependencies.jar com.vegaasen.playhouse.run.StartPerformance <numOfIteration> "<documentToSign>" "#<elementId>"

# Acknowledgements

- Vegard Aasen || vegaasen at gmail dot com || www.vegaasen.com