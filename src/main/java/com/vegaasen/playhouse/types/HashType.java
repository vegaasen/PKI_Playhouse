package com.vegaasen.playhouse.types;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public enum HashType {

    SHA_256("SHA-256", "", 256),
    SHA_384("SHA-384", "", 384),
    SHA_512("SHA-512", "", 512),
    HMAC_SHA_1("HmacSHA1", "http://www.w3.org/2000/09/xmldsig#hmac-sha1", 160),
    HMAC_SHA_256("HmacSHA256", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", 256),
    HMAC_SHA_384("HmacSHA384", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", 384),
    HMAC_SHA_512("HmacSHA512", "http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", 512),
    HMAC_MD_5("HmacMD5", "http://www.w3.org/2001/04/xmldsig-more#hmac-MD5", 128),
    AES("AES", "", 0),
    TRIPLE_DES("DES", "", 0);

    private String type;
    private String xmlAlgorithm;
    private int bitLength;

    private HashType(String type, String xmlAlgorithm, int bitLength) {
        this.type = type;
        this.xmlAlgorithm = xmlAlgorithm;
        this.bitLength = bitLength;
    }

    public String getType() {
        return this.type;
    }

    public String getXmlAlgorithm() {
        return xmlAlgorithm;
    }

    public int getBitLength() {
        return bitLength;
    }
}
