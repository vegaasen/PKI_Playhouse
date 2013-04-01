package com.vegaasen.playhouse.utils;

import org.junit.Test;

import java.io.File;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * @author <a href="mailto:vegaasen@gmail.com">Vegard Aasen</a>
 */
public class FileUtilsTest {

    @Test
    public void shouldFindHostFile() {
        final File hostFile = FileUtils.getInstance().getFileFromFileSystem("/etc/hosts");
        assertNotNull(hostFile);
        assertTrue(hostFile.exists());
    }

    @Test
    public void shouldReturnNoFile() {
        final File noSuchFile = FileUtils.getInstance().getFileFromFileSystem("/dev/null/no-such.file");
        assertNotNull(noSuchFile);
        assertTrue(!noSuchFile.exists());
    }

    @Test
    public void shouldReturnNullNoFileName() {
        final File result = FileUtils.getInstance().getFileFromFileSystem("");
        assertNull(result);
    }

    @Test
    public void shouldFindLocalResource() {
        final File localResource = FileUtils.getInstance().getFileFromClassPath("application.properties");
        assertNotNull(localResource);
        assertTrue(localResource.canRead());
    }

    @Test
    public void shouldReturnNullIfNoResourceFound() {
        final File noSuchResource = FileUtils.getInstance().getFileFromClassPath("no-such.file");
        assertNull(noSuchResource);
    }

    @Test
    public void shouldReturnNullIfMissingFileName() {
        final File result = FileUtils.getInstance().getFileFromClassPath("");
        assertNull(result);
    }

}
