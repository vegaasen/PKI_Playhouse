package com.vegaasen.playhouse.run;

import com.vegaasen.playhouse.utils.CertificateImportUtils;

/**
 * Simple tools that imports an existing certificate into an existing keyStore or a new keyStore :-)
 * This will fetch the certificate by itself..
 *
 * @author <a href="mailto:vegard.aasen@telenor.com">Vegard Aasen</a>
 * @since 1:10 PM
 */
public final class ImportCertificate {

    public static void main(String... args) {
        if (args == null || args.length == 0) {
            showUsageAndDie();
        }
        final String hostName = args[0];
        String password = null, outputKeyStore = null, existingKeyStore = null;
        if (args.length > 1) {
            password = args[1];
            if (args.length > 2) {
                outputKeyStore = args[2];
                if (args.length > 3) {
                    existingKeyStore = args[3];
                }
            }
        }
        try {
            final String location =
                    CertificateImportUtils.downloadAndImportCertificates(hostName, existingKeyStore, outputKeyStore, password);
            if (location != null && !location.isEmpty()) {
                System.out.println(String.format("Saved file to: {%s}", location));
                System.exit(1);
            }
            System.out.println("Unable to save file for some reason.");
        } catch (final Throwable t) {
            throw new RuntimeException(String.format("Unable to download and import certificate for %s", hostName), t);
        }
        showUsageAndDie();
    }

    private static void showUsageAndDie() {
        System.err.println("Wrong usage.\nUsage: <hostname> <password> <outputKeyStore> <existingKeyStore(will append to existing keystore)>");
        System.exit(-1);
    }

}
