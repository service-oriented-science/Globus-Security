/*
 * Copyright 1999-2006 University of Chicago
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.globus.util;

import org.slf4j.Logger;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.io.RandomAccessFile;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;

public class Tail implements Runnable {

    private static final int CHUNK_SIZE = 2048;

    private byte[] buffer;
    private boolean _stop = false;
    private List<FileWatcher> list = null;
    private Thread _thread;

    private Logger _logger;

    public Tail() {
        buffer = new byte[CHUNK_SIZE];
        list = Collections.synchronizedList(new LinkedList<FileWatcher>());
    }

    public void setLogger(Logger logger) {
        _logger = logger;
    }

    public void start() {
        _thread = new Thread(this);
        _thread.start();
    }

    class FileWatcher {
        private RandomAccessFile _ras;
        private OutputStream _out;
        private long _pos;

        public FileWatcher(File file, OutputStream out, int pos) throws IOException {
            _ras = new RandomAccessFile(file, "r");
            _out = out;
            _pos = pos;
        }

        public void init()
                throws IOException {
            _ras.seek(_pos);
        }

        public long getDiff()
                throws IOException {
            return _ras.length() - _pos;
        }

        public void moveBuffer(byte[] buffer, int size)
                throws IOException {
            _ras.readFully(buffer, 0, size);
            _pos += size;

            if (_logger.isDebugEnabled()) {
                _logger.debug("[tail] output size: " + size);
            }

            _out.write(buffer, 0, size);
        }

        public void close() {
            try {
                _ras.close();
            } catch (Exception e) {
                //Nothing we can do in this situation
            }
            try {
                _out.close();
            } catch (Exception e) {
                //This should not happen
            }
        }
    }

    public void join()
            throws InterruptedException {
        _thread.join();
    }

    public void addFile(File file, OutputStream out, int pos)
            throws IOException {
        list.add(new FileWatcher(file, out, pos));
    }

    public void run() {

        _logger.debug("[tail] running...");


        try {
            initFileWatchers();

            while (!isDone()) {
                pollWatchers();
            }
        } catch (IOException e) {
            _logger.debug("Unexpected error.", e);
        } finally {
            close();
        }

        _logger.debug("[tail] done.");
    }

    private void pollWatchers() throws IOException {
        try {
            Thread.sleep(2000);
        } catch (Exception e) {
            //Should not happen
        }

        for (FileWatcher watcher : list) {
            watch(watcher);
        }
    }

    private void initFileWatchers() throws IOException {
        for (FileWatcher watcher : list) {
            watcher.init();
        }
    }

    private boolean watch(FileWatcher watcher) throws IOException {
        long len;
        int size;
        len = watcher.getDiff();
        if (len <= 0) return true;

        while (len > 0) {
            size = (len > CHUNK_SIZE) ? CHUNK_SIZE : (int) len;
            watcher.moveBuffer(buffer, size);
            len -= size;
        }
        return false;
    }

    private boolean isDone()
            throws IOException {
        if (!_stop) return false;
        for (FileWatcher watcher : list) {

            if (watcher.getDiff() > 0) return false;
        }

        return true;
    }

    private void close() {
        for (FileWatcher watcher : list) {
            watcher.close();
        }
    }

    public void stop() {
        _logger.debug("[tail] stop called");
        _stop = true;
    }

}
