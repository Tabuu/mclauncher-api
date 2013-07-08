package sk.tomsik68.mclauncher.util.net;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.net.URL;
import java.net.URLConnection;

import sk.tomsik68.mclauncher.api.ui.IProgressMonitor;

public class FileDownload {

    public static void downloadFileWithProgress(String url, File dest, IProgressMonitor progress) throws Exception {
        System.out.println("Downloading "+url);
        if (!dest.exists())
            dest.createNewFile();

        URL u = new URL(url);
        URLConnection connection = u.openConnection();
        connection.connect();

        BufferedInputStream in = new BufferedInputStream(connection.getInputStream());
        BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(dest));

        final int len = connection.getContentLength();
        progress.setMax(len);

        int readBytes = 0;
        byte[] block;

        while (readBytes < len) {
            block = new byte[8192];
            int readNow = in.read(block);
            if (readNow > 0)
                out.write(block, 0, readNow);

            progress.setProgress(readBytes);
            readBytes += readNow;
        }
        out.flush();
        out.close();
        in.close();
        progress.finish();
        System.out.println("Download finished.");
    }

}