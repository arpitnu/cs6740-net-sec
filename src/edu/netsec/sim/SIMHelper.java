package edu.netsec.sim;

import java.io.Console;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Ananthanarayanan Balachandran (ananth@ccs.neu.edu)
 * @author Arpit Mehta (arpitm@ccs.neu.edu)
 * 
 */

public class SIMHelper {

	private List<String> pwdList;
	private List<String> unameList;

	public SIMHelper() {
		pwdList = new ArrayList<String>();
		unameList = new ArrayList<String>();
		getUsernamePassword();
		generateUserFiles();
		generateServerKeys();
	}

	/**
	 * Generates the server RSA keys
	 */
	void generateServerKeys() {
		try {
			FileOutputStream serPubKey = new FileOutputStream("ServerPublicKey");
			FileOutputStream serPrivKey = new FileOutputStream(
					"ServerPrivateKey");

			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(2048);
			KeyPair kp = kpg.genKeyPair();
			Key PubKey = kp.getPublic();
			Key PrivKey = kp.getPrivate();

			serPubKey.write(PubKey.getEncoded());
			serPrivKey.write(PrivKey.getEncoded());

			serPubKey.close();
			serPrivKey.close();
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * For the entered username password, the password hash and private is used
	 * for each user
	 */
	private void generateUserFiles() {
		try {
			FileOutputStream fos = new FileOutputStream("ClientNameList");
			DataOutputStream dos = new DataOutputStream(fos);

			int userLstSize = unameList.size();
			for (int i = 0; i < userLstSize; i++) {
				String uName = unameList.get(i);
				String pwd = pwdList.get(i);
				generateUserKeyFiles(uName);

				dos.writeInt(uName.length());
				dos.write(uName.getBytes());

				byte[] pwdHash = generatePasswordHash(pwd);

				dos.writeInt(pwdHash.length);
				dos.write(pwdHash);

				FileOutputStream pbePrivateKey = new FileOutputStream(uName
						+ "PBEPrivKey");
				DataOutputStream dosPbePrivateKey = new DataOutputStream(
						pbePrivateKey);
				dosPbePrivateKey.write(pbePrivKeyGeneration(readFile(uName
						+ "PrivateKey"), generatePasswordHash(pwd + uName)));
				dosPbePrivateKey.close();
			}
			dos.close();
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	/**
	 * This function gets the username and password from the console and
	 * generates the user list
	 */
	private void getUsernamePassword() {
		
		Console con = System.console();
		if(con == null )
		{
			System.out.println("Error retrieving console object.");
			System.exit(-1);
		}
		for (int i = 0; i < 4; i++) {
			con.printf("Username: ");
			String user = con.readLine();
			unameList.add(user);
			con.printf("Password:");
			char[] pass = con.readPassword();
			String pwd = new String(pass);
			pwdList.add(pwd);
		}

//		for (int i = 0; i < 4; i++) {
//			@SuppressWarnings("resource")
//			Scanner in = new Scanner(System.in);
//			System.out.println("Username: ");
//			String user = in.nextLine();
//			unameList.add(user);
//			System.out.println("Password:");
//			String pwd = in.nextLine();
//			pwdList.add(pwd);
//		}

	}

	public static void main(String[] args) {
		new SIMHelper();
	}

	@SuppressWarnings("resource")
	private void generateUserKeyFiles(String userName) {
		try {
			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
			kpg.initialize(1024);
			KeyPair kp = kpg.genKeyPair();
			PublicKey pubKey = kp.getPublic();
			String pubFileName = userName + "PublicKey";
			String privFileName = userName + "PrivateKey";
			FileOutputStream fos = new FileOutputStream(pubFileName);
			DataOutputStream dos = new DataOutputStream(fos);
			dos.write(pubKey.getEncoded());
			fos = new FileOutputStream(privFileName);
			dos = new DataOutputStream(fos);
			dos.write(kp.getPrivate().getEncoded());
			dos.close();
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
	}

	/**
	 * Hashing function
	 * 
	 * @param pwd
	 * @return
	 */
	private byte[] generatePasswordHash(String pwd) {
		try {
			byte[] txt = pwd.getBytes("UTF-8");
			MessageDigest md = MessageDigest.getInstance("SHA-1");
			byte[] hash = md.digest(txt);
			byte[] finalHash = Arrays.copyOf(hash, 16);
			return finalHash;
		} catch (UnsupportedEncodingException e) {
			System.err.println(e.getMessage());
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		}
		return null;

	}

	/**
	 * generates the PBEbasedPrivate key
	 * 
	 * @param plainText
	 * @param key
	 * @return
	 */
	private byte[] pbePrivKeyGeneration(byte[] plainText, byte[] key) {
		try {
			SecretKeySpec sks = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, sks);
			byte[] cipherText = cipher.doFinal(plainText);
			return cipherText;
		} catch (NoSuchAlgorithmException e) {
			System.err.println(e.getMessage());
		} catch (NoSuchPaddingException e) {
			System.err.println(e.getMessage());
		} catch (InvalidKeyException e) {
			System.err.println(e.getMessage());
		} catch (IllegalBlockSizeException e) {
			System.err.println(e.getMessage());
		} catch (BadPaddingException e) {
			System.err.println(e.getMessage());
		}
		return null;
	}

	/**
	 * Reeads the data from the filename given
	 * 
	 * @param fileName
	 * @return
	 */
	private byte[] readFile(String fileName) {
		try {
			File file = new File(fileName);
			int size = (int) file.length();
			byte[] bytes = new byte[size];
			@SuppressWarnings("resource")
			DataInputStream dis = new DataInputStream(new FileInputStream(file));
			int read = 0;
			int numRead = 0;
			while (read < bytes.length
					&& (numRead = dis.read(bytes, read, bytes.length - read)) >= 0) {
				read += numRead;
			}
			if (read < bytes.length) {
				System.err.println("Cannot read file " + fileName);
			}
			return bytes;
		} catch (FileNotFoundException e) {
			System.err.println(e.getMessage());
		} catch (IOException e) {
			System.err.println(e.getMessage());
		}
		return null;

	}

}