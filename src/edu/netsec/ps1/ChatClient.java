package edu.netsec.ps1;

import java.io.*;
import java.net.*;

/**
 * ChatClient
 * <p>
 * Class registers with the chat server which broadcasts messages that is sent
 * to it from any registered client. Basically the chat server behaves like a
 * chat room.
 * </p>
 * 
 * @author arpitm
 * 
 */
public class ChatClient {
	// IPAddress of the Chat server
	String ipAddress;

	// Port to which the client establishes a connection to the server
	int portNum;

	// UDP Client Socket
	DatagramSocket socket;

	// Buffer size for packet data
	byte[] inputBuffer = new byte[1024];

	/* Constructor */
	ChatClient(String[] args) {
		verifyInput(args);
		createSocket();
		sendDataPacket();
		receiveDataPacket();
	}

	/**
	 * Checks input from user for server IP Address and port number. If they are
	 * not entered correctly then program terminates with proper usage
	 * instructions.
	 * 
	 * @param args
	 */
	private void verifyInput(String[] args) {
		try {
			if (args.length != 2) {
				System.err
						.println("USAGE: java ChatClient IPAddress PortNumber");
				System.exit(0);
			} else {
				ipAddress = args[0];
				portNum = Integer.parseInt(args[1]);
			}
		} catch (NumberFormatException e) {
			System.err
					.println("Error: "
							+ e.getMessage()
							+ ". Please enter the IP Address and Port Number correctly.");
			System.err.println("USAGE: java ChatClient IPAddress PortNumber");
			System.exit(0);
		}
	}

	/**
	 * Creates a data gram socket and send greeting to server
	 */
	private void createSocket() {
		try {
			socket = new DatagramSocket();

			/* Send GREETING message to the chat server. */
			String greetMsg = "GREETING";
			byte buf[] = greetMsg.getBytes();
			DatagramPacket greetPkt = new DatagramPacket(buf, buf.length,
					new InetSocketAddress(ipAddress, portNum));
			socket.send(greetPkt);
			System.out.println("Greeting sent to chat server.");

		} catch (SocketException error) {
			System.err.println("Socket not created." + error.getMessage());
			System.err.println("Client logging out.");
			System.exit(0);
		} catch (IOException error) {
			System.err.println("Greeting message not sent to server."
					+ error.getMessage());
		}
	}

	/**
	 * Sends a data packets to the chat server
	 */
	private void sendDataPacket() {
		Thread sendThread = new Thread(new Runnable() {
			public void run() {
				try {
					BufferedReader in = new BufferedReader(
							new InputStreamReader(System.in));
					String tx_message;
					while ((tx_message = in.readLine()) != null) {
						tx_message = "MESSAGE: " + tx_message;
						byte[] buf = tx_message.getBytes();
						socket.send(new DatagramPacket(buf, buf.length,
								new InetSocketAddress(ipAddress, portNum)));
						System.out.println("MESSAGE SENT TO SERVER: "
								+ tx_message);
					}
				} catch (IOException error) {
					System.err.println(error.getMessage());
				}
			}
		});
		sendThread.start();
	}

	/**
	 * Receives the incoming data packets from the chat server and displays the
	 * message
	 */
	private void receiveDataPacket() {
		Thread receiveThread = new Thread(new Runnable() {
			public void run() {
				DatagramPacket msgPacket = new DatagramPacket(inputBuffer,
						inputBuffer.length);
				String rx_message;
				while (true) {
					try {
						socket.receive(msgPacket);
						rx_message = new String(msgPacket.getData(), 0,
								msgPacket.getLength());
						if (rx_message.startsWith("INCOMING: ")) {
							String msgString = rx_message.substring(8,
									rx_message.indexOf("\n"));
							String port = rx_message.substring((rx_message
									.indexOf("\n") + 1));
							System.out.println("<From " + port + ">: "
									+ msgString);
						}

						inputBuffer = null;
					} catch (IOException error) {
						System.err.println("Packet not received");
						System.err.println(error.getMessage());
					}
				}
			}
		});

		receiveThread.start();
	}

	/**
	 * main
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		new ChatClient(args);
	}
}