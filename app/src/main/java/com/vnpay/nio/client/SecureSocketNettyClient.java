package com.vnpay.nio.client;

import com.vnpay.nio.Sign;

import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioSocketChannel;

import java.io.BufferedReader;
import java.io.InputStreamReader;

public class SecureSocketNettyClient {

    private final String host;
    private final int port;

    public SecureSocketNettyClient(String host, int port) {
        this.host = host;
        this.port = port;
    }

    public void run(String line) throws Exception {
        EventLoopGroup group = new NioEventLoopGroup();
        try {
            Bootstrap b = new Bootstrap();
            b.group(group).channel(NioSocketChannel.class)
                    .handler(new SecureSocketClientInitializer());

            // Start the connection attempt.
            Channel ch = b.connect(host, port).sync().channel();
            ChannelFuture lastWriteFuture = null;
            lastWriteFuture = ch.writeAndFlush(Sign.SignData(line));
            System.out.println(line + " sent.");
            if (lastWriteFuture != null) {
                lastWriteFuture.sync();
            }
        } finally {
            // The connection is closed automatically on shutdown.
//			group.shutdownGracefully();
        }
    }
}