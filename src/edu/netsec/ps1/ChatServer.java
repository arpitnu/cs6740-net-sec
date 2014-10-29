package edu.netsec.ps1;

import java.io.*;
import java.net.*;
import java.util.*;

/**
 * The ChatServer class is used to broadcast incoming messages from all
 * registered clients to all other registered clients connected to the server.
 * 
 * @author arpitm
 * 
 */
public class ChatServer {
	// Buffer size for dataPacket data
	byte[] dataBuffer = new byte[1024];

	// ArrayList of IP address of the registered clients
	ArrayList<InetAddress> clientAddrList = new ArrayList<>();

	// ArrayList of portNumber numbers of the registered clients
	ArrayList<Integer> clientPortList = new ArrayList<>();

	// Chat Server Socket
	DatagramSocket serverSocket = null;

	// Port on which the socket is created and connected
	int portNumber;

	// Constructor
	ChatServer(String[] args) {
		verifyServerInput(args);
		createSocket();
		receiveDataPacket();
	}

	/** 
	 * Validate server input for the portNumber number 
	 * */
	private void verifyServerInput(String[] args) {
		if (args.length != 1) {
			System.err.println("Usage is: java Server PortNumber");
			System.exit(0);
		} else {
			portNumber = Integer.parseInt(args[0]);
		}
	}

	/** 
	 * Creating a datagram socket at the server side. 
	 * */
	private void createSocket() {
		try {
			serverSocket = new DatagramSocket(portNumber);
		} catch (SocketException error) {
			System.err.println("Socket not created." + error.getMessage());
			System.exit(0);
		}
		System.out.println("Server Initialization Successful.");
	}

	/**
	 * Verify if the GREETING message is received from the registered client.
	 * Once that is done, receive data from the client.
	 */
	private void receiveDataPacket() {
		while (true) {
			DatagramPacket dataPacket = new DatagramPacket(dataBuffer,
					dataBuffer.length);
			try {
				serverSocket.receive(dataPacket);
			} catch (IOException error) {
				System.err.println("Data not received");
				System.err.println(error.getMessage());
			}

			/* Retrieve the message received */
			String clientMsg = new String(dataPacket.getData(), 0,
					dataPacket.getLength());
			System.out.println("Packet Received from "
					+ dataPacket.getSocketAddress().toString() + " : "
					+ clientMsg);

			/* Check the type of the message */
			if (clientMsg.equals("GREETING")) {
				clientAddrList.add(dataPacket.getAddress());
				clientPortList.add(new Integer(dataPacket.getPort()));
			} else if (clientMsg.startsWith("MESSAGE")) {
				broadcastMessage(clientMsg, dataPacket);
			}
		}
	}

	/**
	 * Broadcasts the message received from a registered client to all other
	 * registered clients
	 * 
	 * @param message
	 * 
	 * @param dataPacket
	 */
	private void broadcastMessage(String message, DatagramPacket dataPacket) {
		String msgText = message.substring(8);
		String broadcastdMsgStr = "INCOMING: " + msgText + "\n"
				+ dataPacket.getSocketAddress().toString();
		byte[] broadcastMsg = broadcastdMsgStr.getBytes();

		int clientListSize = clientAddrList.size();

		if (!(clientListSize >= 1)) {
			return;
		}

		for (int i = 0; i < clientListSize; i++) {
			if (!(clientAddrList.get(i).equals(dataPacket.getAddress()) && clientPortList
					.get(i).equals(dataPacket.getPort()))) {
				try {
					serverSocket.send(new DatagramPacket(broadcastMsg,
							broadcastMsg.length, clientAddrList.get(i),
							clientPortList.get(i)));
				} catch (IOException error) {
					System.err.println("Message not broadcasted.");
					System.err.println(error.getMessage());
				}
			}
		}
	}

	/**
	 * Main ()
	 * 
	 * @param args
	 */
	public static void main(String args[]) {
		new ChatServer(args);
	}
}