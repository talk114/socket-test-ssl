package com.vnpay.nio;

import android.content.Context;
import android.os.StrictMode;
import android.support.annotation.RawRes;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Log;

import com.vnpay.nio.client.NettySocketClient;
import com.vnpay.nio.client.SecureMessage;
import com.vnpay.nio.client.SecureSocketNettyClient;
import com.vnpay.nio.nio.NioSSLExample;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.Charset;
import java.nio.charset.CharsetDecoder;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Set;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

public class MainActivity extends AppCompatActivity {
    public static final String SEPERATOR_DIFF_MESSAGE = new String(
            new byte[]{(byte) (6)});
    public static final String SEPERATOR_NEW_SIGNATURE = new String(
            new byte[]{(byte) (8)});
    public static final String SEPERATOR_NEW_4 = new String(
            new byte[]{(byte) (4)});
    public static final String SEPERATOR_NEW_5 = new String(
            new byte[]{(byte) (5)});
    public static final String SEPERATOR_NEW_ARRAY = new String(
            new byte[]{(byte) (2)});
    public static final String SEPERATOR_NEW_DIFF_ARRAY = new String(
            new byte[]{(byte) (3)});
    public static final String SEPERATOR_NEW_ELEMENT = new String(
            new byte[]{(byte) (1)});
    SocketChannel client;
    Selector selector;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        SecureMessage.provideSSL(this);
        new Thread(new Runnable() {
            @Override
            public void run() {
//                try {
//                    new SecureSocketNettyClient("ott.vnpay.vn", 20136).run(Ping());
//                } catch (Exception e) {
//                    e.printStackTrace();
//                }
                try {
                    NettySocketClient.main("demo.vnpayment.vn", 20154, GCM());
                } catch (Exception e) {
                    e.printStackTrace();
                }
            }
        }).start();


    }

//     try {
//        selector = Selector.open();
//
//        StrictMode.ThreadPolicy policy = new StrictMode.ThreadPolicy.Builder()
//                .permitAll().build();
//        StrictMode.setThreadPolicy(policy);
//        InetSocketAddress crunchifyAddr = new InetSocketAddress("demomb.vnpay.vn", 20154);
//        client = SocketChannel.open();
//        client.connect(crunchifyAddr);
//        client.configureBlocking(false);
//
//        int operations = SelectionKey.OP_CONNECT | SelectionKey.OP_READ
//                | SelectionKey.OP_WRITE;
//        client.register(selector, operations);
//        SSLSocketFactory sk = create(R.raw.vnpaybin);
//        sk.createSocket(client.socket(), "demomb.vnpay.vn", 20154, false);
//        RecvThread rt = new RecvThread("Receive THread");
//        rt.start();
//        ArrayList<String> companyDetails = new ArrayList<String>();
//
//        companyDetails.add("a");
//        companyDetails.add("b");
//        companyDetails.add("c");
//        companyDetails.add("d");
//        for (String companyName : companyDetails) {
//            byte[] message = new String(companyName).getBytes();
//            ByteBuffer buffer = ByteBuffer.wrap(message);
//            client.write(buffer);
//            Log.d("BVB", companyName);
//            buffer.clear();
//        }
//
//    } catch (Exception e) {
//        e.printStackTrace();
//        close();
//    } finally {
//
//
//    }

    public SSLSocketFactory create(@RawRes int caRawFile) {
        InputStream caInput = null;
        try {
            // Generate the CA Certificate from the raw resource file
            caInput = getResources().openRawResource(caRawFile);
            Certificate ca = CertificateFactory.getInstance("X.509").generateCertificate(caInput);

            // Load the key store using the CA
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, null);
            keyStore.setCertificateEntry("ca", ca);

            // Initialize the TrustManager with this CA
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(keyStore);

            // Create an SSL context that uses the created trust manager
            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, tmf.getTrustManagers(), new SecureRandom());
            return sslContext.getSocketFactory();

        } catch (Exception ex) {
            throw new RuntimeException(ex);

        } finally {
            if (caInput != null) {
                try {
                    caInput.close();
                } catch (IOException ignored) {
                }
            }
        }
    }

    private void close() {
        try {
            client.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public class RecvThread extends Thread {

        public boolean val = true;

        public RecvThread(String str) {
            super(str);
        }

        public void run() {
            System.out.println("Inside receivemsg");
            int nBytes = 0;
            ByteBuffer buf = ByteBuffer.allocate(2048);
            try {
                while (val) {
                    while ((nBytes = client.read(buf)) > 0) {
                        buf.flip();
                        Charset charset = Charset.forName("us-ascii");
                        CharsetDecoder decoder = charset.newDecoder();
                        CharBuffer charBuffer = decoder.decode(buf);
                        String result = charBuffer.toString();
                        Log.d("BVB", result);
                        buf.flip();

                    }
                }

            } catch (IOException e) {
                e.printStackTrace();

            }
        }

    }

    public String Ping() {
        try {
            StringBuilder v = new StringBuilder();
            v.append(1);
            v.append(SEPERATOR_NEW_4);
            return v.toString();
        } catch (Exception e) {
            return null;
        }

    }
    public String GCM() {
        try {
            StringBuilder v = new StringBuilder();
            v.append(190);
            v.append(SEPERATOR_NEW_4);
            v.append("64565464655");
            return v.toString();
        } catch (Exception e) {
            return null;
        }
    }

    //    private void signatureData(){
//        StringBuilder sb = new StringBuilder();
//
//        // LogVnp.d("Vntalk","num pakcage " + tempSize);
//        for (int i = 0; i < tempSize; i++) {
//
//            sb.append(tempMsgs.get(i)).append(SEPERATOR_DIFF_MESSAGE);
//        }
//        sb.deleteCharAt(sb.length() - 1);
//
//    }
    public static boolean processReadySet(Set readySet) throws Exception {
        Iterator iterator = readySet.iterator();
        while (iterator.hasNext()) {
            SelectionKey key = (SelectionKey)
                    iterator.next();
            iterator.remove();
            if (key.isConnectable()) {
                boolean connected = processConnect(key);
                if (!connected) {
                    return true; // Exit
                }
            }
            if (key.isReadable()) {
                String msg = processRead(key);
                System.out.println("[Server]: " + msg);
            }
            if (key.isWritable()) {
                System.out.print("Please enter a message(Bye to quit):");

                SocketChannel sChannel = (SocketChannel) key.channel();
                ByteBuffer buffer = ByteBuffer.wrap("abc".getBytes());
                sChannel.write(buffer);
            }
        }
        return false; // Not done yet
    }

    public static String processRead(SelectionKey key) throws Exception {
        SocketChannel sChannel = (SocketChannel) key.channel();
        ByteBuffer buffer = ByteBuffer.allocate(1024);
        sChannel.read(buffer);
        buffer.flip();
        Charset charset = Charset.forName("UTF-8");
        CharsetDecoder decoder = charset.newDecoder();
        CharBuffer charBuffer = decoder.decode(buffer);
        String msg = charBuffer.toString();
        return msg;
    }

    public static boolean processConnect(SelectionKey key) throws Exception {
        SocketChannel channel = (SocketChannel) key.channel();
        while (channel.isConnectionPending()) {
            channel.finishConnect();
        }
        return true;
    }
}
