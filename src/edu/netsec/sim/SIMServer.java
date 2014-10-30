package edu.netsec.sim;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.ConcurrentHashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

/**
 * @author Ananthanarayanan Balachandran (ananth@ccs.neu.edu)
 * @author Arpit Mehta (arpitm@ccs.neu.edu)
 * 
 */

public class SIMServer {

	public enum ServerMessageFlag {
		TESTSOCKETREQ((byte) 100),
		LOGIN0((byte) 102),
		LOGIN2((byte) 104),
		LOGIN4((byte) 106),
		TTBREQ((byte)107),
		POLLRES((byte)110),
		LOGOUT((byte)111),
		AUTHFAIL((byte)112),
		SAMEUSER((byte)113),
		CLIOFFLINE((byte)114),
		LISTREQ((byte) 115);
		
		public final byte flag;

		ServerMessageFlag(byte t) {
			flag = t;
		}

		static ServerMessageFlag getFlag(byte firstByte) {
			if (firstByte == 100)
				return ServerMessageFlag.TESTSOCKETREQ;
			if (firstByte == 102)
				return ServerMessageFlag.LOGIN0;
			if (firstByte == 104)
				return ServerMessageFlag.LOGIN2;
			if (firstByte == 106)
				return ServerMessageFlag.LOGIN4;
			if (firstByte == 115)
				return ServerMessageFlag.LISTREQ;
			if (firstByte == 107)
				return ServerMessageFlag.TTBREQ;
			if (firstByte == 111)
				return ServerMessageFlag.LOGOUT;
			if (firstByte == 110)
				return ServerMessageFlag.POLLRES;
			if (firstByte == 112)
				return ServerMessageFlag.AUTHFAIL;
			if (firstByte == 113)
				return ServerMessageFlag.SAMEUSER;
			if (firstByte == 114)
				return ServerMessageFlag.CLIOFFLINE;
			return null;
		}
	}

	private byte[] dPktBuffer = new byte[PKT_SIZE];

	private static final int PKT_SIZE = 4098;
	
	private static final BigInteger DH_G = new BigInteger(
			"66769902729453773529591131231569572102735544195993481143033457484815030002596316655928306151074126943049377614450028533734323959138888686552706761807171386969245696096129361633104534226150835208919251885611066228846063597270995942371116296807245855582424161473422149566011004210899105193304176803779403265090");
	private static final BigInteger DH_P = new BigInteger(
			"118539106163103455536379147004961367288843953236491023527594295060060859680741589469770990497791240951568655167946823593107118424420940518582947778487487989116692658067363411263318937721491573236667816363175510013718506361043376316374497960667110912165612271045737683283219912755118746405028518492721139034801");
	private static final int DH_L = 1023;
	private static final String SER_PRIVATE_KEY_NAME = "ServerPrivateKey";
	private static final String CLIENTLIST_FILE_NAME = "ClientNameList";

	private PrivateKey dhPrivateKey;
	private PublicKey dhPublicKey;
	private String secret = "serverSecret";

	private static DatagramSocket dSock;
	private static int port;

	private SIMServerCryptoHelper serverCryptoHelper;

	private ConcurrentHashMap<String, String> loginClientList;
	private ConcurrentHashMap<String, String> dubiousClientList;
	private ConcurrentHashMap<String, String> onlineClientList;
	private ConcurrentHashMap<String, SecretKey> secretKeyMap;
	private ConcurrentHashMap<String, Integer> challengeMap;
	
	public static void main(String[] args) {
		if (args.length > 0)
			port = Integer.parseInt(args[0]);
		else {
			System.err.println("USAGE: java SIMServer <Port>");
			System.exit(1);
		}
		try {
			dSock = new DatagramSocket(port);
		} catch (SocketException e) {
			e.printStackTrace();
		}
		SIMServer server = new SIMServer();
		System.out.println("Server running on the port: " + port);

		server.startThreads();

		server.runMain();
	}

	/**
	 * Default constructor
	 */
	public SIMServer() {
		serverCryptoHelper = SIMServerCryptoHelper.getInstance();
		loginClientList = new ConcurrentHashMap<String, String>();
		dubiousClientList = new ConcurrentHashMap<String, String>();
		onlineClientList = new ConcurrentHashMap<String, String>();
		secretKeyMap = new ConcurrentHashMap<String, SecretKey>();
		challengeMap = new ConcurrentHashMap<String, Integer>();

		serverCryptoHelper.generateDHKeys(DH_P, DH_G, DH_L);
		dhPrivateKey = serverCryptoHelper.getDHPrivateKey();
		dhPublicKey = serverCryptoHelper.getDHPublicKey();
	}

	/**
	 * starts the 2 threads
	 */
	private void startThreads() {
		pollOnlineClients();
		updateOnlineClients();
	}
	
	/**
	 * This function starts a thread which keeps polling all the loggedin
	 * clients to see if the are still online So a request is sent to the client
	 * and the client responds back which is handled as part of the
	 * processPollResp()
	 * 
	 */
	private void pollOnlineClients() {
		Thread pollClients = new Thread(new Runnable() {
			@SuppressWarnings("static-access")
			public void run() {
				while (true) {
					try {
						if (loginClientList.size() == 0) {
							Thread.currentThread().sleep(50000);
							continue;
						}

						for (String uName : loginClientList.keySet()) {
							byte[] encUserNameBytes = serverCryptoHelper
									.encUsingPubKey(uName.getBytes(), uName
											+ "PublicKey");
							dPktBuffer[0] = 109;
							ByteArrayOutputStream baos = new ByteArrayOutputStream();
							DataOutputStream dos = new DataOutputStream(baos);
							dos.writeInt(encUserNameBytes.length);
							dos.write(encUserNameBytes);
							dos.flush();
							byte[] data = baos.toByteArray();
							for (int i = 1; i <= data.length; i++)
								dPktBuffer[i] = data[i - 1];
							
							String delimiter = "/";
							String[] split = loginClientList.get(uName).split(delimiter);
							InetAddress ipAddr = InetAddress.getByName(split[1]);
							int clientPort = Integer.parseInt(split[2]);
							
							DatagramPacket dPktPollMsg = new DatagramPacket(
									dPktBuffer, dPktBuffer.length, ipAddr, clientPort);
							dSock.send(dPktPollMsg);

							dubiousClientList.put(uName, "online");
						}
						Thread.currentThread().sleep(50000);
					} catch(Exception e){
						e.printStackTrace();
					}
				}
			}
		});
		pollClients.start();
	}

	/**
	 * This function updates the online clients, every 5 sec if the client is
	 * present in the doubiouslist and not part of the onlinelist, the the
	 * loggedin client list updated
	 */
	private void updateOnlineClients() {
		Thread updateOnlineClients = new Thread(new Runnable() {
			@SuppressWarnings("static-access")
			public void run() {
				while (true) {
					try {
						for (String uName : loginClientList.keySet()) {
							if ((dubiousClientList.get(uName) != null)
									&& (onlineClientList.get(uName) == null)) {
								loginClientList.remove(uName);
							}
						}
						dubiousClientList.clear();
						onlineClientList.clear();
						Thread.currentThread().sleep(50000);
					} catch (Exception e) {
						e.printStackTrace();
					}
				}
			}
		});
		updateOnlineClients.start();
	}

	private void buildPktBuffer(byte[] msg) {
		int mLen = msg.length;
		if (mLen == 0) {
			return;
		} else {
			for (int i = 1; i <= mLen; i++)
				dPktBuffer[i] = msg[i - 1];
		}
	}

	private byte[] getHashFromFile(byte[] name) {
		try {
			@SuppressWarnings("resource")
			DataInputStream dis = new DataInputStream(new FileInputStream(
					CLIENTLIST_FILE_NAME));
			String uName = new String(name);
			while (dis.available() != 0) {
				int len = dis.readInt();
				byte[] uNameBytes = new byte[len];
				dis.read(uNameBytes);
				if (new String(uNameBytes).equals(uName)) {
					len = dis.readInt();
					byte[] hashBytes = new byte[len];
					dis.read(hashBytes);
					return hashBytes;
				}
			}
			dis.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	private void runMain() {
		while (true) {
			DatagramPacket rcvPkt = new DatagramPacket(new byte[PKT_SIZE],
					PKT_SIZE);
			try {
				dSock.receive(rcvPkt);
			} catch (IOException e2) {
				e2.printStackTrace();
			}

			ByteArrayInputStream bais = new ByteArrayInputStream(
					rcvPkt.getData());
			int cnt;
			byte pktBuffer[] = new byte[PKT_SIZE];

			for (cnt = 0; cnt < rcvPkt.getLength(); cnt++) {
				int data = bais.read();
				if (data == -1)
					break;
				else
					pktBuffer[cnt] = (byte) data;
			}

			String clientIP = rcvPkt.getAddress() + ":" + rcvPkt.getPort();
			try {
				switch (ServerMessageFlag.getFlag(pktBuffer[0])) {
				case TESTSOCKETREQ:
					processTestConnReq(pktBuffer, rcvPkt);
					break;
				case LOGIN0:
					processLogin0Msg(pktBuffer, rcvPkt);
					break;
				case LOGIN2:
					processLogin2Msg(pktBuffer, rcvPkt);
					break;
				case LOGIN4:
					processLogin4Msg(pktBuffer, rcvPkt, clientIP);
					break;
				case LISTREQ:
					processListRequestMsg(pktBuffer, rcvPkt);
					break;
				case TTBREQ:
					processTicketToClientReq(pktBuffer, rcvPkt);
					break;
				case LOGOUT:
					processLogoutMsg(pktBuffer, rcvPkt);
					break;
				case POLLRES:
					processPollResponse(pktBuffer, rcvPkt);
					break;
				default:
					break;
				}
			} catch (Exception e) {
				sendAuthError(pktBuffer, rcvPkt);
			}
			//
			// try {
			// if (pktBuffer[0] == (byte) 0) {
			// processLogin1Msg(pktBuffer, recvPkt);
			// } else if (pktBuffer[0] == (byte) 2) {
			// processMessage2(pktBuffer, recvPkt);
			// } else if (pktBuffer[0] == (byte) 4) {
			// processMessage4(pktBuffer, recvPkt, clientIP);
			// } else if (pktBuffer[0] == (byte) 10) {
			// processListRequestMsg(pktBuffer, recvPkt);
			// } else if (pktBuffer[0] == (byte) 20) {
			// processTicketToClientReq(pktBuffer, recvPkt);
			// } else if (pktBuffer[0] == (byte) 40) {
			// processLogoutMsg(pktBuffer, recvPkt);
			// } else if (pktBuffer[0] == (byte) 81) {
			// processPollResponse(pktBuffer, recvPkt);
			// } else if (pktBuffer[0] == (byte) 82) {
			// processTestConnection(pktBuffer, recvPkt);
			// }
			// } catch (Exception e) {
			// sendAuthenticationError(pktBuffer, recvPkt);
			// }
			continue;
		}

	}

	/**
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void sendAuthError(byte[] pktBuffer,
			DatagramPacket rcvPkt) {
		try {
			dPktBuffer[0] = 112;
			DatagramPacket dPktAuthErr = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(dPktAuthErr);
		} catch (IOException e1) {
			e1.printStackTrace();
		}

	}

	/**
	 * This method is to test the socket connection
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processTestConnReq(byte[] pktBuffer, DatagramPacket rcvPkt) {
		// test connection
		try {
			dPktBuffer[0] = 101;
			DatagramPacket dPktTestRes = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(dPktTestRes);
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}
	
	/**
	 * This function process the poll response sent by the client, for which the
	 * poll request was sent. The client is added to the online client list,
	 * which contains the active client list
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processPollResponse(byte[] pktBuffer, DatagramPacket rcvPkt) {
		try {
			DataInputStream dis = new DataInputStream(new ByteArrayInputStream(
					pktBuffer));
			dis.readByte();

			byte[] encUserNameByte = new byte[dis.readInt()];
			dis.read(encUserNameByte);

			String uName = new String(serverCryptoHelper.decUsingPrivKey(
					encUserNameByte, SER_PRIVATE_KEY_NAME));

			if (onlineClientList.get(uName) == null) {
				onlineClientList.put(uName, "online");
			}
		} catch (IOException e1) {
			e1.printStackTrace();
		}
	}

	/**
	 * This function process the logout request sent by the client. The client
	 * is removed from the online client list, which contains the active client list
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processLogoutMsg(byte[] pktBuffer, DatagramPacket rcvPkt) {
		try{
			DataInputStream dis = new DataInputStream(
					new ByteArrayInputStream(pktBuffer));
			dis.readByte();

			byte[] encUserNameByte = new byte[dis.readInt()];
			dis.read(encUserNameByte);

			String uName = new String(
					serverCryptoHelper
							.decUsingPrivKey(encUserNameByte,
									SER_PRIVATE_KEY_NAME));

			if (loginClientList.get(uName) != null) {
				loginClientList.remove(uName);
			}
		} catch (IOException e){
			e.printStackTrace();
		}
	}

	/**
	 * This function processes the ticket rquest sent by the client.
	 * The client requests a ticket to talk to the other client.
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processTicketToClientReq(byte[] pktBuffer,
			DatagramPacket rcvPkt) {
		try {
			dPktBuffer[0] = 108;

			DataInputStream dis = new DataInputStream(new ByteArrayInputStream(
					pktBuffer));
			dis.readByte();

			byte[] encReqByt = new byte[dis.readInt()];
			dis.read(encReqByt);

			String reqMsg = new String(
					serverCryptoHelper.decUsingPrivKey(encReqByt,
							SER_PRIVATE_KEY_NAME));

			String[] split = reqMsg.split(" ");
			String nonce1 = split[0];
			String otherClientName = split[3];

			if (loginClientList.get(otherClientName) == null) {
				dPktBuffer[0] = 114;
				DatagramPacket sndPacket = new DatagramPacket(dPktBuffer,
						dPktBuffer.length, rcvPkt.getAddress(),
						rcvPkt.getPort());
				dSock.send(sndPacket);
				return;
			}

			KeyGenerator kgen = KeyGenerator.getInstance("AES");
			kgen.init(128);

			SecretKey shareLey = kgen.generateKey();

			byte[] shareKeyByt = shareLey.getEncoded();
			String targetPublicKeyFileName = otherClientName + "PublicKey";

			byte[] tktByt = serverCryptoHelper.encUsingPubKey(
					shareKeyByt, targetPublicKeyFileName);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);

			dos.writeInt(nonce1.getBytes().length);
			dos.write(nonce1.getBytes());
			dos.writeInt(otherClientName.getBytes().length);
			dos.write(otherClientName.getBytes());
			dos.writeInt(shareKeyByt.length);
			dos.write(shareKeyByt);
			dos.writeInt(tktByt.length);
			dos.write(tktByt);

			byte[] data = baos.toByteArray();

			for (int i = 1; i <= data.length; i++)
				dPktBuffer[i] = data[i - 1];

			DatagramPacket ttbResPkt = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(ttbResPkt);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

	
	/**
	 * This function processes the LIST request sent to the server, by the client.
	 * This requests returns the client the list of online clients.
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processListRequestMsg(byte[] pktBuffer, DatagramPacket rcvPkt) {
		try {
			dPktBuffer[0] = 116;

			DataInputStream dis = new DataInputStream(new ByteArrayInputStream(
					pktBuffer));
			dis.readByte();

			byte[] encUserNamebyte = new byte[dis.readInt()];
			dis.read(encUserNamebyte);

			String uNameStr = new String(serverCryptoHelper.decUsingPrivKey(
					encUserNamebyte, SER_PRIVATE_KEY_NAME));

			String onlineClientList = "";
			for (String s : loginClientList.keySet()) {
				onlineClientList += "/" + s + loginClientList.get(s);
			}

			byte[] encryptedListBytes = serverCryptoHelper.encUsingPubKey(
					onlineClientList.getBytes(), uNameStr + "PublicKey");

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);

			dos.writeInt(encryptedListBytes.length);
			dos.write(encryptedListBytes);
			dos.flush();
			
			byte[] data = baos.toByteArray();

			for (int i = 1; i <= data.length; i++)
				dPktBuffer[i] = data[i - 1];

			DatagramPacket dPktListResp = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(dPktListResp);
		} catch (IOException e) {
			e.printStackTrace();
		}

	}

	/**
	 * This function process the final login message which is sent from the
	 * client to the server which is the hash of the shared DH key the challenge
	 * -1 signed using the RSA key of the client
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 * @param clientIP
	 */
	private void processLogin4Msg(byte[] pktBuffer, DatagramPacket rcvPkt,
			String clientIP) {
		try {
			DataInputStream dis = new DataInputStream(new ByteArrayInputStream(
					pktBuffer));
			dis.readByte();

			int length = dis.readInt();
			byte[] encUserNamebyte = new byte[length];
			dis.read(encUserNamebyte);
			length = dis.readInt();
			byte[] hashValue = new byte[length];
			dis.read(hashValue);
			length = dis.readInt();
			byte[] signData = new byte[length];
			dis.read(signData);

			byte[] decUserNameByte = serverCryptoHelper.decUsingPrivKey(
					encUserNamebyte, SER_PRIVATE_KEY_NAME);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			EncodedKeySpec x509keySpec = new X509EncodedKeySpec(
					serverCryptoHelper.readFromFile(new String(decUserNameByte)
					+ "PublicKey"));
			PublicKey clientPubKey = kf.generatePublic(x509keySpec);

			Signature sign = Signature.getInstance("SHA1withRSA");
			sign.initVerify(clientPubKey);
			sign.update(hashValue);
			if (!sign.verify(signData)) {
				dPktBuffer[0] = 112;
				DatagramPacket sndPacket = new DatagramPacket(dPktBuffer,
						dPktBuffer.length, rcvPkt.getAddress(),
						rcvPkt.getPort());
				dSock.send(sndPacket);
				return;
			}

			int challengeC2 = challengeMap.get(new String(decUserNameByte));
			SecretKey secretKey = secretKeyMap.get(new String(decUserNameByte));

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);
			dos.write(secretKey.getEncoded());
			dos.write(challengeC2 - 1);
			dos.flush();
			String addr = rcvPkt.getAddress() + "/" + rcvPkt.getPort();

			String newClient = new String(decUserNameByte);
			if (loginClientList.get(newClient) != null) {
				dPktBuffer[0] = 113;
			} else {
				dPktBuffer[0] = 107;
				loginClientList.put(newClient, addr);
				System.out.println("Client " + newClient + " joined from "
						+ clientIP);
			}

			DatagramPacket logSuccPkt = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(logSuccPkt);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	/**
	 * This function processes the login request sent from the client and send a
	 * cookie to the client which is the hash of the IP and a salt
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processLogin0Msg(byte[] pktBuffer, DatagramPacket rcvPkt) {
		try {
			byte[] cookie = serverCryptoHelper.buildCookie(
					rcvPkt.getAddress(), rcvPkt.getPort(), secret);

			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			DataOutputStream dos = new DataOutputStream(baos);

			dos.writeInt(cookie.length);
			dos.write(cookie);

			dos.flush();
			byte[] data = baos.toByteArray();

			dPktBuffer[0] = 103;
			buildPktBuffer(data);

			DatagramPacket dPktMsg1 = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(dPktMsg1);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * This function process login message 2 which the cookie and the publickey
	 * of the client which is encrypted using the public key of server and a
	 * challenge with the hash of the DH public key
	 * 
	 * @param pktBuffer
	 * @param rcvPkt
	 */
	private void processLogin2Msg(byte[] pktBuffer, DatagramPacket rcvPkt) {
		try {
		DataInputStream dis = new DataInputStream(
				new ByteArrayInputStream(pktBuffer));
			dis.readByte();
		

		int len = dis.readInt();
		byte[] encName = new byte[len];
		dis.read(encName);

		len = dis.readInt();
		byte[] retCookie = new byte[len];
		dis.read(retCookie);

		int challengeC1 = dis.readInt();

		len = dis.readInt();
		byte[] encCliPubByt = new byte[len];
		dis.read(encCliPubByt);

		byte[] cookie = serverCryptoHelper.buildCookie(
				rcvPkt.getAddress(), rcvPkt.getPort(),
				secret);
		
		if (!validateCookie(cookie,retCookie)){
			System.out.println("Cookies doesn't match !!");
			dPktBuffer[0] = 91;
			DatagramPacket dPkt = new DatagramPacket(dPktBuffer,
					dPktBuffer.length, rcvPkt.getAddress(),
					rcvPkt.getPort());
			dSock.send(dPkt);
			return;
		}

		byte[] decUserName = serverCryptoHelper.decUsingPrivKey(
				encName, SER_PRIVATE_KEY_NAME);

		byte[] pwdHashBytes = getHashFromFile(decUserName);

		byte[] decCliPubKeyByt = serverCryptoHelper
				.decUsingPwdHash(encCliPubByt, pwdHashBytes);
		SecretKey secKey = serverCryptoHelper.genSecretKey(
				dhPrivateKey, decCliPubKeyByt);

		secretKeyMap.put(new String(decUserName), secKey);

		byte[] dhPubKeyBytes = dhPublicKey.getEncoded();
		byte[] encDHPubKeyByt = serverCryptoHelper
				.encUsingPwdHash(dhPubKeyBytes, pwdHashBytes);

		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		DataOutputStream dos = new DataOutputStream(baos);

		String pbePrivFileName = new String(decUserName)
				+ "PBEPrivKey";
		byte[] ybytes = serverCryptoHelper.readFromFile(pbePrivFileName);

		dos.writeInt(ybytes.length);
		dos.write(ybytes);

		dos.writeInt(challengeC1 - 1);
		dos.flush();
		byte[] data = baos.toByteArray();
		Cipher cipher = Cipher.getInstance("DES");
		cipher.init(Cipher.ENCRYPT_MODE, secKey);
		byte[] encryptedYC1Bytes = cipher.doFinal(data);

		int challengeC2 = serverCryptoHelper.generateNonce();
		challengeMap.put(new String(decUserName), challengeC2);

		baos = new ByteArrayOutputStream();
		dos = new DataOutputStream(baos);
		dos.writeInt(encDHPubKeyByt.length);
		dos.write(encDHPubKeyByt);
		dos.writeInt(encryptedYC1Bytes.length);
		dos.write(encryptedYC1Bytes);
		dos.writeInt(challengeC2);
		dos.flush();
		byte[] msg3Bytes = baos.toByteArray();

		dPktBuffer[0] = 105;
		buildPktBuffer(msg3Bytes);

		DatagramPacket dPktMsg3 = new DatagramPacket(dPktBuffer,
				dPktBuffer.length, rcvPkt.getAddress(),
				rcvPkt.getPort());
		dSock.send(dPktMsg3);
		} catch (IOException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}

	/**
	 * Validates the cookies whether it the same that was sent previously
	 * 
	 * @param cookie
	 * @param retCookie
	 * @return
	 */
	private boolean validateCookie(byte[] cookie, byte[] retCookie) {
		String cookieStr = new String(cookie);
		String retCookieStr = new String(retCookie);
		if (cookieStr.equals(retCookieStr)) {
			return true;
		} else {
			return false;
		}
	}

		

}
