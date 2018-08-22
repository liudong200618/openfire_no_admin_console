/**
 * $Revision: $
 * $Date: $
 *
 * Copyright (C) 2005-2008 Jive Software. All rights reserved.
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

package org.jivesoftware.openfire.nio;

import java.nio.charset.StandardCharsets;
import java.util.Collection;

import org.apache.mina.core.service.IoHandlerAdapter;
import org.apache.mina.core.session.IdleStatus;
import org.apache.mina.core.session.IoSession;
import org.dom4j.io.XMPPPacketReader;
import org.jivesoftware.openfire.Connection;
import org.jivesoftware.openfire.net.MXParser;
import org.jivesoftware.openfire.net.ServerTrafficCounter;
import org.jivesoftware.openfire.net.StanzaHandler;
import org.jivesoftware.openfire.spi.ConnectionConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;
import org.xmpp.packet.StreamError;

/**
 * A ConnectionHandler is responsible for creating new sessions, destroying sessions and delivering
 * received XML stanzas to the proper StanzaHandler.
 *
 * @author Gaston Dombiak
 */
public abstract class ConnectionHandler extends IoHandlerAdapter {

	private static final Logger Log = LoggerFactory.getLogger(ConnectionHandler.class);

    static final String XML_PARSER = "XML-PARSER";
    protected static final String HANDLER = "HANDLER";
    protected static final String CONNECTION = "CONNECTION";

    private static final ThreadLocal<XMPPPacketReader> PARSER_CACHE = new ThreadLocal<XMPPPacketReader>()
            {
               @Override
               protected XMPPPacketReader initialValue()
               {
                  final XMPPPacketReader parser = new XMPPPacketReader();
                  parser.setXPPFactory( factory );
                  return parser;
               }
            };
    /**
     * Reuse the same factory for all the connections.
     */
    private static XmlPullParserFactory factory = null;

    static {
        try {
            factory = XmlPullParserFactory.newInstance(MXParser.class.getName(), null);
            factory.setNamespaceAware(true);
        }
        catch (XmlPullParserException e) {
            Log.error("Error creating a parser factory", e);
        }
    }

    /**
     * The configuration for new connections.
     */
    protected final ConnectionConfiguration configuration;

    protected ConnectionHandler( ConnectionConfiguration configuration ) {
        this.configuration = configuration;
    }
    @Override
    public void sessionCreated(IoSession session) throws Exception {
    	super.sessionCreated(session);
    	Log.info("jaydon --- 创建一个新连接：{}", session.getRemoteAddress());
       // session.write("welcome to the chat room !");
    }

    @Override
	public void sessionOpened(IoSession session) throws Exception {
        // Create a new XML parser for the new connection. The parser will be used by the XMPPDecoder filter.
    	Log.info("---jaydon-sessionOpened---"+session.getId());
    	final XMLLightweightParser parser = new XMLLightweightParser(StandardCharsets.UTF_8);
        session.setAttribute(XML_PARSER, parser);
        // Create a new NIOConnection for the new session
        final NIOConnection connection = createNIOConnection(session);
        session.setAttribute(CONNECTION, connection);
        session.setAttribute(HANDLER, createStanzaHandler(connection));
        // Set the max time a connection can be idle before closing it. This amount of seconds
        // is divided in two, as Openfire will ping idle clients first (at 50% of the max idle time)
        // before disconnecting them (at 100% of the max idle time). This prevents Openfire from
        // removing connections without warning.
        final int idleTime = getMaxIdleTime() / 2;
        Log.info("---jaydon-idleTime 11---"+idleTime);
        if (idleTime > 0) {
        	Log.info("---jaydon-idleTime---"+idleTime);
            session.getConfig().setIdleTime(IdleStatus.READER_IDLE, idleTime);
        }
    }

    @Override
    public void sessionClosed(IoSession session) throws Exception {
        final Connection connection = (Connection) session.getAttribute(CONNECTION);
        //Log.info("-jaydon--服务器准备关闭 IoSession---id="+session.getId());
        if ( connection != null ) {
        	 Log.info("-jaydon(sessionClosed)--服务器关闭了 IoSession---id="+session.getId());
            connection.close();
        }
    }

    /**
	 * Invoked when a MINA session has been idle for half of the allowed XMPP
	 * session idle time as specified by {@link #getMaxIdleTime()}. This method
	 * will be invoked each time that such a period passes (even if no IO has
	 * occurred in between).
	 *
	 * Openfire will disconnect a session the second time this method is
	 * invoked, if no IO has occurred between the first and second invocation.
	 * This allows extensions of this class to use the first invocation to check
	 * for livelyness of the MINA session (e.g by polling the remote entity, as
	 * {@link ClientConnectionHandler} does).
	 *
	 * @see IoHandlerAdapter#sessionIdle(IoSession, IdleStatus)
	 */
    @Override
	public void sessionIdle(IoSession session, IdleStatus status) throws Exception {
    	  Log.info("-jaydon(getIdleCount)=----"+session.getIdleCount(status));
    	if (session.getIdleCount(status) > 1) {
            // Get the connection for this session
            final Connection connection = (Connection) session.getAttribute(CONNECTION);
            if (connection != null) {
                // Close idle connection
                if (Log.isDebugEnabled()) {
                    Log.debug("ConnectionHandler: Closing connection that has been idle: " + connection);
                }
                connection.close();
                Log.info("-jaydon(sessionIdle)--服务器关闭了 IoSession---id="+session.getId());
            }
        }
    }

    @Override
    public void exceptionCaught(IoSession session, Throwable cause) throws Exception {
        Log.warn("Closing connection due to exception in session: " + session, cause);

        try {
            // OF-524: Determine stream:error message.
            final StreamError error;
            if ( cause != null && (cause instanceof XMLNotWellFormedException || (cause.getCause() != null && cause.getCause() instanceof XMLNotWellFormedException) ) ) {
                error = new StreamError( StreamError.Condition.not_well_formed );
            } else {
                error = new StreamError( StreamError.Condition.internal_server_error );
            }

            final Connection connection = (Connection) session.getAttribute( CONNECTION );
            connection.deliverRawText( error.toXML() );
        } finally {
            final Connection connection = (Connection) session.getAttribute( CONNECTION );
            if (connection != null) {
            	 Log.info("-jaydon(exceptionCaught)--服务器关闭了 IoSession---id="+session.getId());
                connection.close();
            }
        }
    }

    @Override
	public void messageReceived(IoSession session, Object message) throws Exception {
    	// 拿到所有的客户端Session
        Collection<IoSession> sessions = session.getService().getManagedSessions().values();
        // 向所有客户端发送数据
//        for (IoSession sess : sessions) {
//        	sess.write("<message  from=\"admin@mydomain\" to=\"liujiandong@mydomain/Smack\" type=\"chat\"><body>12345678</body></message>");
//        }
    	Log.info("---jaydon-sessionsSize:---"+sessions.size());
    	Log.info("---current IoSession:---"+session.getId());
        // Get the stanza handler for this session
        StanzaHandler handler = (StanzaHandler) session.getAttribute(HANDLER);
        // Get the parser to use to process stanza. For optimization there is going
        // to be a parser for each running thread. Each Filter will be executed
        // by the Executor placed as the first Filter. So we can have a parser associated
        // to each Thread
        final XMPPPacketReader parser = PARSER_CACHE.get();
        // Update counter of read btyes
        updateReadBytesCounter(session);
        //System.out.println("RCVD: " + message);
        // Let the stanza handler process the received stanza
        try {
        	Log.info("服务器-收到客户端  "+session.getId()+" 的xml:"+message);
            handler.process((String) message, parser);
        } catch (Exception e) {
            Log.error("Closing connection due to error while processing message: " + message, e);
            final Connection connection = (Connection) session.getAttribute(CONNECTION);
            if ( connection != null ) {
                connection.close();
            }

        }
    }

    @Override
    public void messageSent(IoSession session, Object message) throws Exception {
        super.messageSent(session, message);
        Log.info("---jaydon--messageSent--Iosession--"+session.getId());
//    	Log.info("jaydon-of发送的xml:"+message);
        // Update counter of written btyes
        updateWrittenBytesCounter(session);
        //System.out.println("SENT: " + Charset.forName("UTF-8").decode(((ByteBuffer)message).buf()));
    }

    abstract NIOConnection createNIOConnection(IoSession session);

    abstract StanzaHandler createStanzaHandler(NIOConnection connection);

    /**
     * Returns the max number of seconds a connection can be idle (both ways) before
     * being closed.<p>
     *
     * @return the max number of seconds a connection can be idle.
     */
    abstract int getMaxIdleTime();

    /**
     * Updates the system counter of read bytes. This information is used by the incoming
     * bytes statistic.
     *
     * @param session the session that read more bytes from the socket.
     */
    private void updateReadBytesCounter(IoSession session) {
        long currentBytes = session.getReadBytes();
        Long prevBytes = (Long) session.getAttribute("_read_bytes");
        long delta;
        if (prevBytes == null) {
            delta = currentBytes;
        }
        else {
            delta = currentBytes - prevBytes;
        }
        session.setAttribute("_read_bytes", currentBytes);
        ServerTrafficCounter.incrementIncomingCounter(delta);
    }

    /**
     * Updates the system counter of written bytes. This information is used by the outgoing
     * bytes statistic.
     *
     * @param session the session that wrote more bytes to the socket.
     */
    private void updateWrittenBytesCounter(IoSession session) {
        long currentBytes = session.getWrittenBytes();
        Long prevBytes = (Long) session.getAttribute("_written_bytes");
        long delta;
        if (prevBytes == null) {
            delta = currentBytes;
        }
        else {
            delta = currentBytes - prevBytes;
        }
        session.setAttribute("_written_bytes", currentBytes);
        ServerTrafficCounter.incrementOutgoingCounter(delta);
    }
}
