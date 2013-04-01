package com.vegaasen.playhouse.utils;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class PropertiesUtils {

    private static PropertiesUtils propertiesUtils;
    private static String propertiesFileName = File.separator + "application.properties";
    private static Properties properties;

    private PropertiesUtils() {
    }

    public static PropertiesUtils getInstance() {
        if (propertiesUtils == null) {
            propertiesUtils = new PropertiesUtils();
        }
        if (properties == null) {
            propertiesUtils.loadProperties();
        }
        return propertiesUtils;
    }

    private void loadProperties() {
        if (properties == null) {
            final InputStream is =
                    PropertiesUtils.class.getResourceAsStream(
                            propertiesFileName
                    );
            if (is != null) {
                properties = new Properties();
                try {
                    properties.load(is);
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }

    public String getProperty(final String property) {
        if (property != null && !property.isEmpty()) {
            return (String) properties.get(property);
        }
        return null;
    }

    public static void setPropertiesFileName(final String fileName) {
        propertiesFileName = File.separator + fileName;
    }

}
