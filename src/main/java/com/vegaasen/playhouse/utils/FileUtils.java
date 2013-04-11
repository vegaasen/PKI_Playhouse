package com.vegaasen.playhouse.utils;

import com.google.common.base.Strings;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.URL;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class FileUtils {

    private static final String SEPARATOR = "/";

    private static FileUtils fileUtils;

    private FileUtils() {
    }

    public static FileUtils getInstance() {
        if (fileUtils == null) {
            fileUtils = new FileUtils();
        }
        return fileUtils;
    }

    public InputStream getFileAsInputStreamFromClassPath(String fileName) {
        if(!Strings.isNullOrEmpty(fileName)) {
            final InputStream is = this.getClass().getResourceAsStream(SEPARATOR + fileName);
            if(is!=null) {
                return is;
            }
        }
        return null;
    }

    public File getFileFromClassPath(String fileName) {
        if (!Strings.isNullOrEmpty(fileName)) {
            final URL resource = this.getClass().getResource(SEPARATOR + fileName);
            if (resource != null) {
                return new File(resource.getFile());
            }
        }
        return null;
    }

    public File getFileFromFileSystem(String pathAndFileName) {
        if (!Strings.isNullOrEmpty(pathAndFileName)) {
            return new File(pathAndFileName);
        }
        return null;
    }

}
