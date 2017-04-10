package com.vnpay.nio.client;

import javax.net.ssl.SSLEngine;

import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelPipeline;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.codec.LengthFieldBasedFrameDecoder;
import io.netty.handler.codec.LengthFieldPrepender;
import io.netty.handler.codec.string.StringDecoder;
import io.netty.handler.codec.string.StringEncoder;
import io.netty.handler.ssl.SslHandler;



public class SecureSocketClientInitializer extends ChannelInitializer<SocketChannel> {

    @Override
    public void initChannel(SocketChannel ch) throws Exception {
        ChannelPipeline pipeline = ch.pipeline();

        // Add SSL handler first to encrypt and decrypt everything.
        // In this example, we use a bogus certificate in the server side
        // and accept any invalid certificates in the client side.
        // You will need something more complicated to identify both
        // and server in the real world.

        SSLEngine engine =
                SecureMessage.provideSSL(null).createSSLEngine();
        engine.setUseClientMode(true);

        pipeline.addLast("ssl", new SslHandler(engine));
        // On top of the SSL handler, add the text line codec.
        // pipeline.addLast("framer", new DelimiterBasedFrameDecoder(8192, Delimiters.lineDelimiter()));
        pipeline.addLast("length-decoder", new LengthFieldBasedFrameDecoder(Integer.MAX_VALUE, 0, 4, 0, 4));
        pipeline.addLast("String-decoder", new StringDecoder());  
        pipeline.addLast("length-encoder", new LengthFieldPrepender(4));
        pipeline.addLast("String-encoder", new StringEncoder()); 
        pipeline.addLast("handler", new SecureSocketClientHandler());
    }
}
