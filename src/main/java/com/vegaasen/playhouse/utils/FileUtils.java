package com.vegaasen.playhouse.utils;

import java.io.File;
import java.net.URL;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public final class FileUtils {

    private static FileUtils fileUtils;

    private FileUtils() {
    }

    public static FileUtils getInstance() {
        if (fileUtils == null) {
            fileUtils = new FileUtils();
        }
        return fileUtils;
    }

    public File getFileFromClassPath(String fileName) {
        if (fileName != null && !fileName.isEmpty()) {
            final URL resource = this.getClass().getResource(File.separator + fileName);
            if (resource != null) {
                return new File(resource.getFile());
            }
        }
        return null;
    }

    public File getFileFromFileSystem(String pathAndFileName) {
        if (pathAndFileName != null && !pathAndFileName.isEmpty()) {
            return new File(pathAndFileName);
        }
        return null;
    }

}
