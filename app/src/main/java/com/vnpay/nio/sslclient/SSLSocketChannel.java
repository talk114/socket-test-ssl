/*
 * Copyright 2015 Jesper de Jong
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.vnpay.nio.sslclient;

import android.annotation.TargetApi;
import android.os.Build;
import android.support.annotation.RequiresApi;
import android.util.Log;

import com.vnpay.nio.sslclient.codec.Decoder;
import com.vnpay.nio.sslclient.codec.Encoder;

import javax.net.ssl.*;

import java.io.IOException;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;

/**
 * Socket channel with SSL for sending and receiving messages.
 * <p/>
 * NOTE: {@code SSLSocketChannel} objects are not thread-safe. Multiple threads should not be sending and receiving
 * messages from the same instance without synchronization.
 * <p/>
 * NOTE: This example does blocking I/O. This is just meant as an example to show how to work with {@code SSLEngine},
 * it is not meant as an example of how to do high-performance, non-blocking I/O.
 * <p/>
 * Java Secure Socket Extension (JSSE) Reference Guide
 * http://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html
 *
 * @param <M> The type of the messages to send and receive.
 */
@TargetApi(Build.VERSION_CODES.KITKAT)
public final class SSLSocketChannel<M> implements AutoCloseable {

    private final SocketChannel socketChannel;

    private final SSLEngine sslEngine;


    private final ByteBuffer appOutBuffer;
    private ByteBuffer netOutBuffer;

    private ByteBuffer netInBuffer;
    private ByteBuffer appInBuffer;

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private static void encode(String request, ByteBuffer buffer) {
        buffer.put(request.getBytes(StandardCharsets.US_ASCII));
    }

    @RequiresApi(api = Build.VERSION_CODES.KITKAT)
    private static String decode(ByteBuffer buffer) {
        if (buffer.hasRemaining()) {

            final byte[] bytes = new byte[buffer.remaining()];
            buffer.get(bytes);
            return new String(bytes, StandardCharsets.UTF_8);
        } else {
            return null;
        }
    }

    private SSLSocketChannel(SocketChannel socketChannel, SSLEngine sslEngine, int appOutBufferSize, int appInBufferSize) {
        this.socketChannel = socketChannel;
        this.sslEngine = sslEngine;
        final SSLSession sslSession = sslEngine.getSession();
        final int applicationBufferSize = sslSession.getApplicationBufferSize();
        final int packetBufferSize = sslSession.getPacketBufferSize();

        // The network output, network input and application input buffers must have a capacity that is as least what
        // the SSL session needs. The capacity of the application output is not constrained by the SSL session.

        this.appOutBuffer = ByteBuffer.allocate(appOutBufferSize);
        this.netOutBuffer = ByteBuffer.allocate(packetBufferSize);

        this.netInBuffer = ByteBuffer.allocate(packetBufferSize);
        this.appInBuffer = ByteBuffer.allocate(Math.max(applicationBufferSize, appInBufferSize));
    }

    /**
     * Opens a connection and does the initial SSL handshake. The returned {@code SSLSocketChannel} is ready to send
     * and receive messages.
     * <p/>
     * Note about the message decoder: The message decoder should return {@code null} if the buffer passed to it does
     * not contain enough data to decode a complete message.
     *
     * @param address          The address of the server to connect to.
     * @param appOutBufferSize The size of the application output buffer. This must be at least large enough to fit
     *                         the largest possible encoded message.
     * @param appInBufferSize  The size of the application input buffer. This must be at least large enough to fit the
     *                         largest possible message to be decoded.
     * @param <M>              The type of the messages to send and receive.
     * @return An {@code SSLSocketChannel} that is connected to the specified server, ready to send and receive
     * messages.
     * @throws IOException              If an I/O error occurs.
     * @throws NoSuchAlgorithmException If a necessary encryption algorithm is not available.
     */
    public static <M> SSLSocketChannel<M> open(SocketAddress address, SSLEngine sslEngine, int appOutBufferSize, int appInBufferSize)
            throws IOException, NoSuchAlgorithmException {
        final SocketChannel socketChannel = SocketChannel.open();
        socketChannel.connect(address);

        final SSLSocketChannel<M> channel = new SSLSocketChannel<M>(socketChannel, sslEngine, appOutBufferSize, appInBufferSize);

        // Perform initial handshake
        channel.checkHandshakeStatus();
        Log.d("SKConnect", "ST: " + socketChannel.isConnected());
        return channel;
    }

    /**
     * Sends a message. This method blocks until the message has been sent.
     *
     * @param message The message to send.
     * @throws IOException If an I/O error occurs.
     */
    public void send(String message) throws IOException {
        encode(message, appOutBuffer);
        doWrap();
    }

    /**
     * Receives a message. This method blocks until a message has been received. It can be interrupted by closing the
     * connection from another thread, which will result in this method throwing an {@link
     * java.nio.channels.AsynchronousCloseException AsynchronousCloseException}.
     *
     * @return The received message.
     * @throws IOException If an I/O error occurs.
     */
    public String receive() throws IOException {
        while (true) {
            appInBuffer.flip();
            try {
                final String message = decode(appInBuffer);
                if (message != null) {
                    return message;
                }
            } finally {
                appInBuffer.compact();
            }

            // No complete message available, read from the channel and unwrap and try again
            doUnwrap();
        }
    }

    private void checkHandshakeStatus() throws IOException {
        checkHandshakeStatus(sslEngine.getHandshakeStatus());
    }

    // Perform the appropriate action for the specified handshake status
    private void checkHandshakeStatus(SSLEngineResult.HandshakeStatus handshakeStatus) throws IOException {
        switch (handshakeStatus) {
            case NOT_HANDSHAKING:
                // No action necessary
                return;

            case FINISHED:
                Log.d("Initial SSL handshake", sslEngine.getSession().getProtocol());
                return;

            case NEED_WRAP:
                doWrap();
                break;

            case NEED_UNWRAP:
                doUnwrap();
                break;

            case NEED_TASK:
                // The SSLEngine has some task(s) that must be run before continuing
                Runnable task;
                while ((task = sslEngine.getDelegatedTask()) != null) {
                    task.run();
                }
                checkHandshakeStatus();
                break;

            default:
                throw new IllegalStateException("Invalid SSL handshake status: " + handshakeStatus);
        }
    }

    private void doWrap() throws IOException {
        appOutBuffer.flip();
        final SSLEngineResult result;
        try {
            result = sslEngine.wrap(appOutBuffer, netOutBuffer);
        } catch (SSLException e) {
            closeChannel();
            return;
        }
        appOutBuffer.compact();

        // It is important to perform the appropriate action for the result status and the result handshake status.
        // NOTE: The handshake status FINISHED is a transient status. It is important to look at the status in the
        // result and not just call sslEngine.getStatus() because the FINISHED status will only be reported once,
        // in the result returned by wrap() or unwrap().

        final SSLEngineResult.Status status = result.getStatus();
        switch (status) {
            case OK:
                flush();
                checkHandshakeStatus(result.getHandshakeStatus());

                // Repeat wrap if there is still data in the application output buffer
                if (appOutBuffer.position() > 0) {
                    doWrap();
                }
                break;

            case CLOSED:
                flush();
                checkHandshakeStatus(result.getHandshakeStatus());
                close();
                break;

            case BUFFER_OVERFLOW:
                // The network output buffer does not have enough space, re-allocate and retry wrap
                // (NOTE: packet buffer size as reported by the SSL session might change dynamically)
                netOutBuffer = ensureRemaining(netOutBuffer, sslEngine.getSession().getPacketBufferSize());
                doWrap();
                break;

            default:
                throw new IllegalStateException("Invalid SSL status: " + status);
        }
    }

    private void flush() throws IOException {
        // Flush the content of the network output buffer to the socket channel
        netOutBuffer.flip();
        try {
            while (netOutBuffer.hasRemaining()) {
                socketChannel.write(netOutBuffer);
            }
        } finally {
            netOutBuffer.compact();
        }
    }

    private void doUnwrap() throws IOException {
        if (netInBuffer.position() == 0) {
            // The network input buffer is empty; read data from the channel before doing the unwrap
            final int count = socketChannel.read(netInBuffer);
            if (count == -1) {
                handleEndOfStream();
                return;
            }
        }

        netInBuffer.flip();
        final SSLEngineResult result;
        try {
            result = sslEngine.unwrap(netInBuffer, appInBuffer);
        } catch (SSLException e) {
            closeChannel();
            return;
        }
        netInBuffer.compact();

        // It is important to perform the appropriate action for the result status and the result handshake status.
        // NOTE: The handshake status FINISHED is a transient status. It is important to look at the status in the
        // result and not just call sslEngine.getStatus() because the FINISHED status will only be reported once,
        // in the result returned by wrap() or unwrap().

        final SSLEngineResult.Status status = result.getStatus();
        switch (status) {
            case OK:
                checkHandshakeStatus(result.getHandshakeStatus());
                break;

            case CLOSED:
                checkHandshakeStatus(result.getHandshakeStatus());
                close();
                break;

            case BUFFER_UNDERFLOW:
                // The network input buffer might not have enough space, re-allocate if necessary
                // (NOTE: packet buffer size as reported by the SSL session might change dynamically)
                netInBuffer = ensureRemaining(netInBuffer, sslEngine.getSession().getPacketBufferSize());

                // Read data from the channel, retry unwrap if not end-of-stream
                final int count = socketChannel.read(netInBuffer);
                if (count == -1) {
                    handleEndOfStream();
                    return;
                }
                doUnwrap();
                break;

            case BUFFER_OVERFLOW:
                // The application input buffer does not have enough space, re-allocate and retry unwrap
                // (NOTE: application buffer size as reported by the SSL session might change dynamically)
                appInBuffer = ensureRemaining(appInBuffer, sslEngine.getSession().getApplicationBufferSize());
                doUnwrap();
                break;

            default:
                throw new IllegalStateException("Invalid SSL status: " + status);
        }
    }

    private void handleEndOfStream() throws IOException {
        try {
            // This will check if the server has sent the appropriate SSL close handshake alert and throws an exception
            // if it did not. Note that some servers don't, so this should not be treated as a fatal exception.
            sslEngine.closeInbound();
            close();
        } catch (SSLException e) {
            // This exception might happen because some servers do not respond to the client's close notify alert
            // message during the SSL close handshake; they just close the connection. This is normally not a problem.
            closeChannel();
        }
    }

    // Allocate a new buffer, copy what's in the old buffer, make sure there's newRemaining remaining in the new buffer
    private ByteBuffer ensureRemaining(ByteBuffer oldBuffer, int newRemaining) {
        if (oldBuffer.remaining() < newRemaining) {
            oldBuffer.flip();
            final ByteBuffer newBuffer = ByteBuffer.allocate(oldBuffer.remaining() + newRemaining);
            newBuffer.put(oldBuffer);
            return newBuffer;
        } else {
            // Buffer does not need to be reallocated, there is already enough remaining
            return oldBuffer;
        }
    }

    /**
     * Closes the connection. This will attempt to do the SSL close handshake before closing the connection.
     *
     * @throws IOException If an I/O error occurs.
     */
    @Override
    public void close() throws IOException {
        // This tells the SSLEngine that we are not going to pass it any more application data
        // and prepares it for the close handshake
        sslEngine.closeOutbound();

        // Perform close handshake
        checkHandshakeStatus();

        closeChannel();
    }

    private void closeChannel() throws IOException {
        if (socketChannel.isOpen()) {
            socketChannel.close();
        }
    }
}
