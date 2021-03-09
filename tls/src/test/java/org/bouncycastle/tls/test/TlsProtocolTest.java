package org.bouncycastle.tls.test;

import java.io.*;
import java.security.SecureRandom;

import org.bouncycastle.tls.TlsClientProtocol;
import org.bouncycastle.tls.TlsServerProtocol;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.io.Streams;

import junit.framework.TestCase;

public class TlsProtocolTest
    extends TestCase
{
    private static final String SYSTEM_PROPERTY_IDENTIFIER_JAVAX_NET_DEBUG = "javax.net.debug";
    private static final String SYSTEM_PROPERTY_VALUE_DEBUG_ALL = "all";
    private static final String EMPTY_STRING = "";

    public void testClientServer() throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();

        PipedInputStream clientRead = TlsTestUtils.createPipedInputStream();
        PipedInputStream serverRead = TlsTestUtils.createPipedInputStream();
        PipedOutputStream clientWrite = new PipedOutputStream(serverRead);
        PipedOutputStream serverWrite = new PipedOutputStream(clientRead);

        TlsClientProtocol clientProtocol = new TlsClientProtocol(clientRead, clientWrite);
        TlsServerProtocol serverProtocol = new TlsServerProtocol(serverRead, serverWrite);

        ServerThread serverThread = new ServerThread(serverProtocol);
        serverThread.start();

        MockTlsClient client = new MockTlsClient(null);
        clientProtocol.connect(client);

        // NOTE: Because we write-all before we read-any, this length can't be more than the pipe capacity
        int length = 1000;

        byte[] data = new byte[length];
        secureRandom.nextBytes(data);

        OutputStream output = clientProtocol.getOutputStream();
        output.write(data);

        byte[] echo = new byte[data.length];
        int count = Streams.readFully(clientProtocol.getInputStream(), echo);

        assertEquals(count, data.length);
        assertTrue(Arrays.areEqual(data, echo));

        output.close();

        serverThread.join();
    }

    public void testEnableLoggingOfMasterSecret() throws Exception {
        String log = performHandshake(SYSTEM_PROPERTY_VALUE_DEBUG_ALL);

        assertTrue("Did not log master secret as expected!", log.contains("TLS master secret: "));
    }

    public void testDoNotEnableLoggingOfMasterSecret() throws Exception {
        String log = performHandshake(EMPTY_STRING);

        assertFalse("Unexpectedly logged master secret!", log.contains("TLS master secret: "));
    }

    static class ServerThread
        extends Thread
    {
        private final TlsServerProtocol serverProtocol;

        ServerThread(TlsServerProtocol serverProtocol)
        {
            this.serverProtocol = serverProtocol;
        }

        public void run()
        {
            try
            {
                MockTlsServer server = new MockTlsServer();
                serverProtocol.accept(server);
                Streams.pipeAll(serverProtocol.getInputStream(), serverProtocol.getOutputStream());
                serverProtocol.close();
            }
            catch (Exception e)
            {
//                throw new RuntimeException(e);
            }
        }
    }

    private String performHandshake(String systemPropertyJavaxNetDebugValue) throws Exception {
        System.setProperty(SYSTEM_PROPERTY_IDENTIFIER_JAVAX_NET_DEBUG,
                           systemPropertyJavaxNetDebugValue);
        PrintStream oldSystemErr = System.err;
        String log;
        try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
            PrintStream printStream = new PrintStream(byteArrayOutputStream);
            System.setErr(printStream);
            printStream.flush();
            testClientServer();
            log = byteArrayOutputStream.toString();
        } finally {
            System.setErr(oldSystemErr);
            System.setProperty(SYSTEM_PROPERTY_IDENTIFIER_JAVAX_NET_DEBUG,
                               EMPTY_STRING);
        }
        return log;
    }
}
