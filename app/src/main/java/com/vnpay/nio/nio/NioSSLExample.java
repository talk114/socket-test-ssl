package com.vnpay.nio.nio;

import android.content.Context;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.vnpay.nio.R;
import com.vnpay.nio.sslclient.SSLSocketChannel;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SelectionKey;
import java.nio.channels.Selector;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.concurrent.Executor;
import java.util.concurrent.Executors;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;

public class NioSSLExample {
    public static final String SEPERATOR_NEW_4 = new String(
            new byte[]{(byte) (4)});

    public void abc(Context context) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, KeyManagementException {
        InetSocketAddress address = new InetSocketAddress("ott.vnpay.vn", 20136);
//        Selector selector = Selector.open();
//        SocketChannel channel = SocketChannel.open();
//        channel.connect(address);
//        channel.configureBlocking(false);
//        int ops = SelectionKey.OP_CONNECT | SelectionKey.OP_READ;
//
//        SelectionKey key = channel.register(selector, ops);

        // create the worker threads
//        final Executor ioWorker = Executors.newSingleThreadExecutor();
//        final Executor taskWorkers = Executors.newFixedThreadPool(2);
        InputStream is = context.getResources().openRawResource(R.raw.vnpaybin);

        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate caCert = (X509Certificate) cf.generateCertificate(is);

        TrustManagerFactory tmf = TrustManagerFactory
                .getInstance(TrustManagerFactory.getDefaultAlgorithm());
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null); // You don't need the KeyStore instance to come from a file.
        ks.setCertificateEntry("caCert", caCert);

        tmf.init(ks);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        // create the SSLEngine
        final SSLEngine engine = sslContext.createSSLEngine();
        engine.setUseClientMode(true);
        engine.beginHandshake();
        final int ioBufferSize = 32 * 1024;
        final SSLSocketChannel<String> channel = SSLSocketChannel.open(address, engine, 256, 8192);
        StringBuilder v = new StringBuilder();
        v.append(1);
        v.append(SEPERATOR_NEW_4);
        channel.send(v.toString());
        final String response = channel.receive();
        Log.d("Res", response);
//        final NioSSLProvider ssl = new NioSSLProvider(key, engine, ioBufferSize, ioWorker, taskWorkers) {
//            @Override
//            public void onFailure(Exception ex) {
//                System.out.println("handshake failure");
//                ex.printStackTrace();
//            }
//
//            @Override
//            public void onSuccess() {
//                System.out.println("handshake success");
//                SSLSession session = engine.getSession();
//                try {
//                    System.out.println("local principal: " + session.getLocalPrincipal());
//                    System.out.println("remote principal: " + session.getPeerPrincipal());
//                    System.out.println("cipher: " + session.getCipherSuite());
//                } catch (Exception exc) {
//                    exc.printStackTrace();
//                }
//
//                //HTTP request
//                StringBuilder v = new StringBuilder();
//                v.append(1);
//                v.append(SEPERATOR_NEW_4);
//                byte[] data = v.toString().getBytes();
//                ByteBuffer send = ByteBuffer.wrap(data);
//                this.sendAsync(send);
//            }
//
//            @Override
//            public void onInput(ByteBuffer decrypted) {
//                // HTTP response
//                byte[] dst = new byte[decrypted.remaining()];
//                decrypted.get(dst);
//                String response = new String(dst);
//                System.out.print(response);
//                System.out.flush();
//            }
//
//            @Override
//            public void onClosed() {
//                System.out.println("ssl session closed");
//            }
//        };
//
//        // NIO selector
//        while (true) {
//            key.selector().select();
//            Iterator<SelectionKey> keys = key.selector().selectedKeys().iterator();
//            while (keys.hasNext()) {
//                keys.next();
//                keys.remove();
//                ssl.processInput();
//            }
//        }
    }


}
