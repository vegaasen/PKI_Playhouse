PKI_Playhouse
=============

My very own PKI Playhouse. Just a testing-ground for encipherments, encoding, keys etc.

# Included testcases

-HMAC
-GMAC
-Generate HMACs
-Generate GMACs
-Encode/Decode AES formatted symmetric keys
-Certificates with HMAC..?
-Keys in Keystores
-Different types of Keystores (JKS, JKCES, p12 etc..)

# Generate / Usage of Keystore

keytool -genseckey -alias my-secret -keyalg AES -keysize 192 -storetype JCEKS -keystore fun.jceks
keytool -list -keystore fun.jceks -storetype JCEKS

Password for both the AES-generated key and the keystore: vegard