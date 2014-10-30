package edu.netsec.sim;
import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.EncodedKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Arpit Mehta & Ananthanarayanan Balachandran
 * 
 */
public class SIMClient {
	
	
	public static final int PKT_SIZE = 4098;
	private static int serverPort;
	private static InetAddress serverIpAddr;
	private static DatagramSocket dSock;
	private static byte[] sndPktBuffer = new byte[PKT_SIZE];
	private String onlineClientList;

	private String userName;
	private byte[] w;
	private byte[] wPrime;
	private static PrivateKey dhPvtKey;
	private static PublicKey dhPubKey;

	// Diffie-Hellman parameter variables
	private static final BigInteger DH_P = new BigInteger(
			"118539106163103455536379147004961367288843953236491023527594295060060859680741589469770990497791240951568655167946823593107118424420940518582947778487487989116692658067363411263318937721491573236667816363175510013718506361043376316374497960667110912165612271045737683283219912755118746405028518492721139034801");
	private static final BigInteger DH_G = new BigInteger(
			"66769902729453773529591131231569572102735544195993481143033457484815030002596316655928306151074126943049377614450028533734323959138888686552706761807171386969245696096129361633104534226150835208919251885611066228846063597270995942371116296807245855582424161473422149566011004210899105193304176803779403265090");
	private static final int DH_L = 1023;
	private static final String SER_PUB_KEY_NAME = "ServerPublicKey";
	private PrivateKey clientPvtKey;
	private byte[] encryptedUserName;
	private SecretKey c2sSessionKey;

	HashMap<String, String> clientAddrMap;
	HashMap<String, String> clientPortMap;
	private String otherClientMessage;
	private String otherUser;
	private String otherUserAddr;
	private String otherUserPort;
	private int nonce1;
	private int nonceToOtherUser;
	private int nonce3;
	private byte[] c2cSessionKey;
	private static final int retryAttempts = 5;
	private int retryAttempt = retryAttempts;
	private Boolean isClientOnline;
	Timestamp errorTime;

	private SIMClientCryptoHelper clientCryptoHelper;

	private static void buildSendPktBuf(byte b, final byte[] message) {
		if (message.length == 0)
			return;
		else {
			sndPktBuffer[0] = b;
			for (int i = 1; i <= message.length; i++)
				sndPktBuffer[i] = message[i - 1];
		}
	}

	public static void main(String[] args) {

		// User must input input the server IP address
		// If Server IP is not entered, then the server is assumed to be running
		// on the localhost
		try {
			if (args.length > 0) {
				serverIpAddr = InetAddress.getByName(args[0]);
			} else {
				serverIpAddr = InetAddress.getByName("localhost");
			}

			if (args.length > 1) {
				serverPort = Integer.parseInt(args[1]);
			} else {
				System.out.println("Usage: java SIMCLient serverIP serverPort");
				System.exit(0);
			}
		} catch (Exception e1) {
			System.out
			.println("Incorrect Server Address/Port Number Specified! \n");
			System.out.println("Usage: java SIMCLient serverIP serverPort");
			System.exit(0);
		}

		SIMClient client = new SIMClient();
		client.startThreads();
	}

	public SIMClient() {
		testConnectionToServer();
		initialize();
		clientCryptoHelper = SIMClientCryptoHelper.getInstance();
		KeyPair kp = clientCryptoHelper.generateDHKeyPair(DH_P, DH_G, DH_L);
		dhPvtKey = kp.getPrivate();
		dhPubKey = kp.getPublic();
	}

	private void startThreads() {
		ClientSender();
		ClientReceiver();
	}

	private void initialize() {
		try {
			dSock = new DatagramSocket();
			dSock.setSoTimeout(0);
		} catch (SocketException e) {
			System.out.println("Error creating Datagram socket.");
			System.exit(0);
		}

		System.out.println("Hello! Please use the following commands:");
		System.out.println("Log In: > login <username> <password>");
		System.out.println("List Of Online Users: > list");
		System.out.println("Send Message To User: >	send <username> <message>");
		System.out.println("Log Out: > logout");
	}

	private static void testConnectionToServer() {
		try {
			DatagramSocket testConnectionSocket = new DatagramSocket();
			byte dataBuf[] = new byte[PKT_SIZE];
			dataBuf[0] = 100;
			DatagramPacket testDPkt = new DatagramPacket(dataBuf,
					dataBuf.length, serverIpAddr, serverPort);
			testConnectionSocket.send(testDPkt);
			testConnectionSocket.setSoTimeout(5000);

			DatagramPacket receivePkt = new DatagramPacket(new byte[PKT_SIZE],
					PKT_SIZE);
			testConnectionSocket.receive(receivePkt);

			ByteArrayInputStream bin = new ByteArrayInputStream(
					receivePkt.getData());
			byte receiveBuf[] = new byte[PKT_SIZE];
			for (int count = 0; count < receivePkt.getLength(); count++) {
				int data = bin.read();
				if (data == -1) {
					break;
				} else
					receiveBuf[count] = (byte) data;
			}
			if (receiveBuf[0] == 101) {
				System.out.println("Connected To Server successfully!");
			}
			testConnectionSocket.close();
		} catch (SocketTimeoutException e) {
			System.err.println(e.getMessage());
			System.exit(0);
		} catch (IOException e) {
			System.err.println(e.getMessage());
			System.exit(0);
		}
	}

	private void ClientReceiver() {
		Thread clientReceiver = new Thread(new Runnable() {
			// @Override
			public void run() {
				while (true) {
					try {
						DatagramPacket receivePkt = new DatagramPacket(
								new byte[PKT_SIZE], PKT_SIZE);
						dSock.receive(receivePkt);

						ByteArrayInputStream bin = new ByteArrayInputStream(
								receivePkt.getData());
						int count;
						byte rcvBuffer[] = new byte[PKT_SIZE];

						for (count = 0; count < receivePkt.getLength(); count++) {
							int data = bin.read();
							if (data == -1)
								break;
							else
								rcvBuffer[count] = (byte) data;
						}

						int c1 = 0;

						/*
						 * Process Login Message 1. Message: cookie
						 */
						if (rcvBuffer[0] == 103) {
							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							byte[] s2cCookie = new byte[dis.readInt()];
							dis.read(s2cCookie);

							/*
							 * Send Login Message 2 Message:
							 * cookie,{username,c1}Ks,W{(g^a) mod p}
							 */
							encryptedUserName = (clientCryptoHelper
									.encUsingRSA(userName, SER_PUB_KEY_NAME));

							c1 = SIMClientHelper.generateNonceChallenge();

							byte[] dhPubKeyBytes = dhPubKey.getEncoded();
							byte[] encryptedClientPubKeyBytes = clientCryptoHelper
									.encUsingPwdHash(dhPubKeyBytes, w);

							ByteArrayOutputStream bos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(bos);

							dos.writeInt(encryptedUserName.length);
							dos.write(encryptedUserName);

							dos.writeInt(s2cCookie.length);
							dos.write(s2cCookie);

							dos.writeInt(c1);

							dos.writeInt(encryptedClientPubKeyBytes.length);
							dos.write(encryptedClientPubKeyBytes);

							dos.flush();

							byte[] dataBytes = bos.toByteArray();

							buildSendPktBuf((byte) 104, dataBytes);

							DatagramPacket sendPkt = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, receivePkt
									.getAddress(), receivePkt.getPort());

							dSock.send(sendPkt);
						}
						/*
						 * Process Login Message 3 Message: W{(g^b) mod
						 * p},((g^ab) mod p){Y,c1-1},c2 Where Y = W'{Ka} Ka =
						 * Clients private key
						 */
						else if (rcvBuffer[0] == 105) {
							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							int len = dis.readInt();
							byte[] encryptedServerPubKeyBytes = new byte[len];
							dis.read(encryptedServerPubKeyBytes);
							len = dis.readInt();
							byte[] encryptedYC1Bytes = new byte[len];
							dis.read(encryptedYC1Bytes);
							int C2 = dis.readInt();

							byte[] decryptedServerPubKeyBytes = clientCryptoHelper
									.decUsingPwdHash(
											encryptedServerPubKeyBytes, w);

							c2sSessionKey = clientCryptoHelper
									.generateSharedSecretKey(dhPvtKey,
											decryptedServerPubKeyBytes);

							Cipher cipher = Cipher.getInstance("DES");
							cipher.init(Cipher.DECRYPT_MODE, c2sSessionKey);
							byte[] decryptedYAndC1Minus1Bytes = cipher
									.doFinal(encryptedYC1Bytes);

							dis = new DataInputStream(new ByteArrayInputStream(
									decryptedYAndC1Minus1Bytes));
							len = dis.readInt();
							byte[] encryptedClientPvtKeyBytes = new byte[len];
							dis.read(encryptedClientPvtKeyBytes);

							byte[] decryptedPrivKey = clientCryptoHelper
									.decUsingPwdHash(
											encryptedClientPvtKeyBytes, wPrime);
							KeyFactory keyFactory = KeyFactory
									.getInstance("RSA");
							EncodedKeySpec privateKeySpec = new PKCS8EncodedKeySpec(
									decryptedPrivKey);
							clientPvtKey = keyFactory
									.generatePrivate(privateKeySpec);

							ByteArrayOutputStream bos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(bos);

							dos.write(c2sSessionKey.getEncoded());
							dos.write(C2 - 1);
							dos.flush();

							/*
							 * Send Login Message 4. Message: [hash{((g^ab) mod
							 * p),c2-1}]Ka
							 */
							byte[] dataToHash = bos.toByteArray();
							byte[] hashValue = clientCryptoHelper
									.hashingFunction(new String(dataToHash));

							/* Sign the data */
							Signature sign = Signature
									.getInstance("SHA1withRSA");
							sign.initSign(clientPvtKey);
							sign.update(hashValue);
							byte[] signData = sign.sign();

							/*
							 * Construct Authentication Message 4
							 */
							bos = new ByteArrayOutputStream();
							dos = new DataOutputStream(bos);
							dos.writeInt(encryptedUserName.length);
							dos.write(encryptedUserName);
							dos.writeInt(hashValue.length);
							dos.write(hashValue);
							dos.writeInt(signData.length);
							dos.write(signData);
							dos.flush();
							byte[] data = bos.toByteArray();

							buildSendPktBuf((byte) 106, data);

							DatagramPacket sndPkt = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, receivePkt
									.getAddress(), receivePkt.getPort());

							dSock.send(sndPkt);
						} else if (rcvBuffer[0] == (byte) 107) {
							System.out.println("User Login Successful!");
							retryAttempt = retryAttempts;
							isClientOnline = true;
							System.out.print("> ");
						}
						/*
						 * Process List Response Message from server Message:
						 * Ksa{lsit}
						 */
						else if (rcvBuffer[0] == (byte) 116) {
							System.out.println("List of online users:");

							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							byte[] encryptedListUsersBytes = new byte[dis
							                                          .readInt()];
							dis.read(encryptedListUsersBytes);

							onlineClientList = new String(clientCryptoHelper
									.decUsingRSA(encryptedListUsersBytes,
											clientPvtKey));

							clientAddrMap = new HashMap<String, String>();
							clientPortMap = new HashMap<String, String>();

							String delimiter = "/";

							String[] split = onlineClientList.split(delimiter);

							for (int i = 1; i < split.length; i += 3) {
								clientAddrMap.put(split[i], split[i + 1]);
								clientPortMap.put(split[i], split[i + 2]);
							}

							Set<String> onlineClients = clientAddrMap.keySet();
							Iterator<String> iterator = onlineClients
									.iterator();

							String client;
							String address;
							String port;

							while (iterator.hasNext()) {
								client = (String) iterator.next();
								address = clientAddrMap.get(client);
								port = clientPortMap.get(client);
								System.out.println(client + " address:\t"
										+ address + ":" + port);
							}

							System.out.print("> ");
						}
						/*
						 * Process Ticket Response from server to talk to
						 * another client
						 */
						else if (rcvBuffer[0] == (byte) 108) {
							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							byte[] nonceByte = new byte[dis.readInt()];
							dis.read(nonceByte);

							byte[] otherUserName = new byte[dis.readInt()];
							dis.read(otherUserName);

							byte[] sharedKeyByte = new byte[dis.readInt()];
							dis.read(sharedKeyByte);

							c2cSessionKey = sharedKeyByte;

							byte[] encryptedTicket = new byte[dis.readInt()];
							dis.read(encryptedTicket);

							ByteArrayOutputStream baos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(baos);

							sndPktBuffer[0] = 30;

							/*
							 * Send Client-To-Client Authentication Message 1
							 * Message: Ticket,Kab{N2}
							 */

							nonceToOtherUser = SIMClientHelper
									.generateNonceChallenge();

							SecretKeySpec skeySpec = new SecretKeySpec(
									sharedKeyByte, "AES");
							// SecretKeySpec skeySpec = new
							// SecretKeySpec(c2cSessionKey, "AES");

							// Instantiate AES cipher to encrypt Nonce
							Cipher cipher = Cipher.getInstance("AES");
							cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

							byte[] encryptedNonceByte = cipher.doFinal(Integer
									.toString(nonceToOtherUser).getBytes());

							dos.writeInt(encryptedTicket.length);
							dos.write(encryptedTicket);
							dos.writeInt(encryptedNonceByte.length);
							dos.write(encryptedNonceByte);

							InetAddress otherClientAddr = InetAddress
									.getByName(otherUserAddr);
							int otherClientPort = Integer
									.parseInt(otherUserPort);

							dos.writeInt(userName.getBytes().length);
							dos.write(userName.getBytes());

							byte[] data = baos.toByteArray();

							for (int i = 1; i <= data.length; i++)
								sndPktBuffer[i] = data[i - 1];

							DatagramPacket sndPacket = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, otherClientAddr,
									otherClientPort);
							try {
								dSock.send(sndPacket);
							} catch (Exception e) {
								System.out
								.println("Error Sending Authentication Message 1 to other client");
								System.exit(0);
							}
						}
						/*
						 * Process Client-To-Client Authentication Message 1
						 * from another client
						 */
						else if (rcvBuffer[0] == (byte) 30) {
							sndPktBuffer[0] = 31;

							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							byte[] encryptedTicketByte = new byte[dis.readInt()];

							dis.read(encryptedTicketByte);

							byte[] ticketBytes = clientCryptoHelper
									.decUsingRSA(encryptedTicketByte,
											clientPvtKey);

							byte[] sharedKeyByte = ticketBytes;

							byte[] encryptedNonceByte = new byte[dis.readInt()];

							dis.read(encryptedNonceByte);

							// Instantiate AES cipher to decrypt Nonce from the
							// other client.
							Cipher cipher = Cipher.getInstance("AES");
							SecretKeySpec sks = new SecretKeySpec(
									sharedKeyByte, "AES");
							cipher.init(Cipher.DECRYPT_MODE, sks);
							byte[] nonceByte = cipher
									.doFinal(encryptedNonceByte);

							c2cSessionKey = sharedKeyByte;

							/*
							 * Send Client-To-Client Authentication Message 3 to
							 * other client. Message: Kab{N2-1,N3}
							 */
							@SuppressWarnings("unused")
							int Nonce2Minus1 = SIMClientHelper
							.byteArrayToInt(nonceByte) - 1;

							nonce3 = SIMClientHelper.generateNonceChallenge();

							sks = new SecretKeySpec(c2cSessionKey, "AES");

							// Instantiate AES cipher to encrypt N3.
							cipher = Cipher.getInstance("AES");
							cipher.init(Cipher.ENCRYPT_MODE, sks);

							byte[] encryptedN3Bytes = cipher.doFinal(Integer
									.toString(nonce3).getBytes());

							ByteArrayOutputStream bos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(bos);
							dos.writeInt(encryptedN3Bytes.length);
							dos.write(encryptedN3Bytes);

							byte[] data = bos.toByteArray();

							for (int i = 1; i <= data.length; i++)
								sndPktBuffer[i] = data[i - 1];

							DatagramPacket sendPkt = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, receivePkt
									.getAddress(), receivePkt.getPort());
							dSock.send(sendPkt);
						}
						/*
						 * Send Client-To-Client Authentication Message 3 to the
						 * other client.
						 */
						else if (rcvBuffer[0] == (byte) 31) {
							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							SecretKeySpec sks = new SecretKeySpec(
									c2cSessionKey, "AES");

							// Instantiate AES cipher to send messgae to other
							// client.
							Cipher cipher = Cipher.getInstance("AES");
							cipher.init(Cipher.ENCRYPT_MODE, sks);

							byte[] encryptedMessage = cipher
									.doFinal(otherClientMessage.getBytes());
							byte[] encryptedUserName = cipher.doFinal(userName
									.getBytes());

							sndPktBuffer[0] = 35;

							// Write encrypted bytes in the Data output stream.
							ByteArrayOutputStream bos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(bos);

							dos.writeInt(encryptedMessage.length);

							dos.write(encryptedMessage);

							dos.writeInt(encryptedUserName.length);

							dos.write(encryptedUserName);

							byte[] data = bos.toByteArray();

							for (int i = 1; i <= data.length; i++) {
								sndPktBuffer[i] = data[i - 1];
							}

							DatagramPacket sendPkt = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, receivePkt
									.getAddress(), receivePkt.getPort());

							try {
								dSock.send(sendPkt);
								System.out.println("Message sent to "
										+ otherUser + ":\t"
										+ otherClientMessage);
							} catch (Exception e) {
								System.out
								.println("Error Sending Message To Other User. Check if Other User is Online.");
								System.exit(0);
							}

							System.out.print("> ");
						}
						/*
						 * Process Client-To-client Authentication Message 1
						 * from another client.
						 */
						else if (rcvBuffer[0] == (byte) 33) {
							sndPktBuffer[0] = 34;

							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							byte[] encryptedTicket = new byte[dis.readInt()];

							dis.read(encryptedTicket);

							byte[] sharedKeyBytes = clientCryptoHelper
									.decUsingRSA(encryptedTicket, clientPvtKey);

							c2cSessionKey = sharedKeyBytes;

							byte[] encryptedNonce = new byte[dis.readInt()];

							dis.read(encryptedNonce);

							Cipher cipher = Cipher.getInstance("AES");
							SecretKeySpec sks = new SecretKeySpec(
									sharedKeyBytes, "AES");
							cipher.init(Cipher.DECRYPT_MODE, sks);
							byte[] n3Bytes = cipher.doFinal(encryptedNonce);

							int Nonce3Minus1 = SIMClientHelper
									.byteArrayToInt(n3Bytes) - 1;

							sks = new SecretKeySpec(c2cSessionKey, "AES");

							// Instantiate the cipher, and AES encrypts the
							// source file
							cipher = Cipher.getInstance("AES");
							cipher.init(Cipher.ENCRYPT_MODE, sks);

							byte[] encryptedN3 = cipher.doFinal(Integer
									.toString(Nonce3Minus1).getBytes());

							ByteArrayOutputStream baos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(baos);
							dos.writeInt(encryptedN3.length);
							dos.write(encryptedN3);

							byte[] data = baos.toByteArray();

							// System.out.println("data.length="+data.length);
							for (int i = 1; i <= data.length; i++)
								sndPktBuffer[i] = data[i - 1];

							DatagramPacket sndPacket = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, receivePkt
									.getAddress(), receivePkt.getPort());
							dSock.send(sndPacket);

						}
						/*
						 * Process Encrypted Message from other Client.
						 */
						else if (rcvBuffer[0] == (byte) 35) {

							DataInputStream dis = new DataInputStream(
									new ByteArrayInputStream(rcvBuffer));
							dis.readByte();

							byte[] encryptedMessage = new byte[dis.readInt()];

							dis.read(encryptedMessage);

							byte[] encryptedUserName = new byte[dis.readInt()];

							dis.read(encryptedUserName);

							SecretKeySpec skeySpec = new SecretKeySpec(
									c2cSessionKey, "AES");

							Cipher cipher = Cipher.getInstance("AES");
							cipher.init(Cipher.DECRYPT_MODE, skeySpec);
							byte[] messageByte = cipher
									.doFinal(encryptedMessage);
							byte[] userName = cipher.doFinal(encryptedUserName);

							System.out.println("Message from "
									+ new String(userName) + ":\t"
									+ new String(messageByte));
							System.out.print("> ");

						}
						/*
						 * Process Ping request Message from server.
						 */
						else if (rcvBuffer[0] == (byte) 109) {
							sndPktBuffer[0] = 110;

							String sourceName = userName;

							byte[] encryptedSourceNameByte = clientCryptoHelper
									.encUsingRSA(sourceName, SER_PUB_KEY_NAME);

							ByteArrayOutputStream bos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(bos);

							dos.writeInt(encryptedSourceNameByte.length);
							dos.write(encryptedSourceNameByte);

							byte[] data = bos.toByteArray();

							for (int i = 1; i <= data.length; i++)
								sndPktBuffer[i] = data[i - 1];

							DatagramPacket sndPacket = new DatagramPacket(
									sndPktBuffer, sndPktBuffer.length, serverIpAddr,
									serverPort);
							dSock.send(sndPacket);
						}
						/*
						 * Process Error Message from Server: User Already
						 * Logged In
						 */
						else if (rcvBuffer[0] == (byte) 113) {
							System.out.println("User Already Logged In!");
							retryAttempt--;

							if (retryAttempt == 0) {
								System.out.println("Number Of Trials Expired!");
								System.exit(0);
							}

							System.out.print("> ");
						}
						/*
						 * Process Error Message from Server: Server
						 * Authentication Error
						 */
						else if (rcvBuffer[0] == (byte) 112) {
							System.out
							.println("Server Authentication Failed! \n");
							System.out
							.println("Please use correct username and password!");
							retryAttempt--;

							if (retryAttempt == 0) {
								System.out.println("Number Of Trials Expired!");
								System.exit(0);
							}

							System.out.print("> ");
						}
						/*
						 * Process Error Message from Server: Other User Offline
						 */
						else if (rcvBuffer[0] == (byte) 114) {
							System.out.println("Other User Is Offline! \n");
							System.out
							.println("Please request the server for updated list of online users!");

							System.out.print("> ");
						} else {
						}
						;
					} catch (Exception x) {
						System.out.println(x.getMessage()
								+ " in receive thread!");
					}
				}
			}
		});
		clientReceiver.start();
	}

	private void ClientSender() {
		Thread clientSender = new Thread(new Runnable() {
			@Override
			public void run() {

				isClientOnline = false;

				while (true) {
					try {

						BufferedReader in = new BufferedReader(
								new InputStreamReader(System.in));
						while (true) {
							System.out.print("> ");
							String userCommand = in.readLine();

							if ((userCommand.trim().startsWith("Login"))
									|| (userCommand.trim().startsWith("login"))) {
								if (true == isClientOnline) {
									System.out
									.println("You're already logged in!");
									continue;
								}

								String[] components = userCommand.split(" ");

								if (components.length != 3) {
									System.out
									.println("Invalid Command: Username and/or Password Missing!");
									System.out
									.println("Login Usage: login <username> <password>");
									continue;
								}

								userName = components[1];
								String pwd = components[2];

								w = clientCryptoHelper.hashingFunction(pwd);
								wPrime = clientCryptoHelper.hashingFunction(pwd
										+ userName);

								sndPktBuffer[0] = 102;

								DatagramPacket login0Pkt = new DatagramPacket(
										sndPktBuffer, sndPktBuffer.length, serverIpAddr,
										serverPort);
								dSock.send(login0Pkt);

							} else if (userCommand.trim().equalsIgnoreCase("list")) {

								if (false == isClientOnline) {
									System.out
									.println("User Not Logged In! Please Login With Valid Username And Password.");
									continue;
								}

								sndPktBuffer[0] = 115;
								byte[] encNameByte = clientCryptoHelper
										.encUsingRSA(userName,
												SER_PUB_KEY_NAME);

								ByteArrayOutputStream baos = new ByteArrayOutputStream();
								DataOutputStream dos = new DataOutputStream(
										baos);
								dos.writeInt(encNameByte.length);
								dos.write(encNameByte);

								byte[] data = baos.toByteArray();

								for (int i = 1; i <= data.length; i++)
									sndPktBuffer[i] = data[i - 1];

								DatagramPacket sndPacket = new DatagramPacket(
										sndPktBuffer, sndPktBuffer.length, serverIpAddr,
										serverPort);
								dSock.send(sndPacket);
							} else if (userCommand.startsWith("Send")
									|| userCommand.startsWith("send")) {

								if (false == isClientOnline) {
									System.out
									.println("User Not Logged In! Please Login With Valid Username And Password.");
									continue;
								}

								sndPktBuffer[0] = 107;
								String[] commandSplit = userCommand.split(" ");

								if (commandSplit.length < 3) {
									System.out.println("Invalid Command!");
									System.out
									.println("Send Usage: send <username> <message>");
									continue;
								}

								otherUser = commandSplit[1];

								if (otherUser.isEmpty()) {
									System.out
									.println("Invalid Command: Username Not Present!");
									System.out
									.println("Send Usage: send <username> <message>");
									System.out.print("> ");
									continue;
								}

								otherUserAddr = clientAddrMap.get(otherUser);
								otherUserPort = clientPortMap.get(otherUser);

								if (otherUser.equalsIgnoreCase(userName)) {
									System.out
									.println("Invalid Command: User can't send message to self!");
									System.out
									.println("Send Usage: send <username> <message>");
									System.out.print("> ");
									continue;
								} else if (otherUserAddr == null) {
									System.out
									.println("You can't send message to an offline or unknown client!");
									System.out
									.println("Please try the command list to get the online clients!");
									System.out.print("> ");
									continue;
								}

								otherClientMessage = commandSplit[2].trim();
								if (otherClientMessage.isEmpty()) {
									System.out
									.println("Empty message, please refer to the following:");
									System.out
									.println("Usage: Send userName message");
									System.out.print("> ");
									continue;
								}

								nonce1 = SIMClientHelper
										.generateNonceChallenge();
								String requestMessage = nonce1 + " " + userName
										+ " to " + otherUser;

								byte[] encryptedRequestMessage = clientCryptoHelper
										.encUsingRSA(requestMessage,
												SER_PUB_KEY_NAME);

								ByteArrayOutputStream baos = new ByteArrayOutputStream();
								DataOutputStream dos = new DataOutputStream(
										baos);

								dos.writeInt(encryptedRequestMessage.length);
								dos.write(encryptedRequestMessage);

								byte[] data = baos.toByteArray();

								for (int i = 1; i <= data.length; i++)
									sndPktBuffer[i] = data[i - 1];

								DatagramPacket sndPacket = new DatagramPacket(
										sndPktBuffer, sndPktBuffer.length, serverIpAddr,
										serverPort);
								dSock.send(sndPacket);
							} else if (userCommand.trim().equalsIgnoreCase("logout")) {

								if (false == isClientOnline) {
									System.out
									.println("You haven't logged in yet!");
									continue;
								}
								sndPktBuffer[0] = 111;
								String sourceName = userName;
								byte[] encryptedSourceNameByte = clientCryptoHelper
										.encUsingRSA(sourceName,
												SER_PUB_KEY_NAME);
								ByteArrayOutputStream baos = new ByteArrayOutputStream();
								DataOutputStream dos = new DataOutputStream(
										baos);
								dos.writeInt(encryptedSourceNameByte.length);
								dos.write(encryptedSourceNameByte);

								byte[] data = baos.toByteArray();

								for (int i = 1; i <= data.length; i++)
									sndPktBuffer[i] = data[i - 1];

								DatagramPacket sndPacket = new DatagramPacket(
										sndPktBuffer, sndPktBuffer.length, serverIpAddr,
										serverPort);
								dSock.send(sndPacket);

								System.out.println("Successfully Logout!");
								System.exit(0);
							} else if (!(userCommand.isEmpty())) {
								System.out.println("Hello! Please use the following commands:");
								System.out.println("Log In: > login <username> <password>");
								System.out.println("List Of Online Users: > list");
								System.out.println("Send Message To User: >	send <username> <message>");
								System.out.println("Log Out: > logout");
							}
						}
					} catch (Exception e) {
						e.printStackTrace();
					} 
				}

			}
		});
		clientSender.start();
	}
}
