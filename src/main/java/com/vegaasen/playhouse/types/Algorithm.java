package com.vegaasen.playhouse.types;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public enum Algorithm {

    HMAC_SHA_1("HmacSHA1"), HMAC_SHA_256("HmacSHA256"), HMAC_SHA_512("HmacSHA512"),
    HMAC_MD5("HmacMD5");

    private String type;

    private Algorithm(String type) {
        this.type = type;
    }

    public String getType() {
        return this.type;
    }

}
