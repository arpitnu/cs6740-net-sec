package edu.netsec.sim;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyAgreement;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * @author Ananthanarayanan Balachandran (ananth@ccs.neu.edu)
 * @author Arpit Mehta (arpitm@ccs.neu.edu)
 * 
 */

class SIMServerCryptoHelper {

	private PrivateKey dhPrivateKey;
	private PublicKey dhPublicKey;

	private static SIMServerCryptoHelper instance;

	// To avoid multiple instantiation.
	private SIMServerCryptoHelper() {
	}

	static synchronized SIMServerCryptoHelper getInstance() {
		if (instance == null)
			instance = new SIMServerCryptoHelper();

		return instance;
	}

	/**
	 * Generates the hash for the given text
	 * 
	 * @param plainText
	 * @return
	 */
	byte[] hashFunction(String plainText) {
		try {
			byte[] txt = plainText.getBytes("UTF-8");
			MessageDigest sha = MessageDigest.getInstance("SHA-1");
			byte[] hashText = sha.digest(txt);
			hashText = Arrays.copyOf(hashText, 16);
			return hashText;
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Generates a random cookie, using the hash function
	 * 
	 * @param addr
	 * @param port
	 * @param secret
	 * @return
	 */
	byte[] buildCookie(InetAddress addr, int port, String secret) {
		return hashFunction(addr.getHostAddress() + port + secret);
	}

	/**
	 * Generates a random nonce for the client and server messages
	 * 
	 * @return
	 */
	int generateNonce() {
		Random randomGenerator = new Random();
		int randomInt = randomGenerator.nextInt();
		return randomInt;
	}

	/**
	 * Encrypts using the password hash
	 * 
	 * @param plainText
	 * @param key
	 * @return
	 */
	byte[] encUsingPwdHash(byte[] plainText, byte[] key) {
		try {
			SecretKeySpec sks = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, sks);
			byte[] cipherText = cipher.doFinal(plainText);
			return cipherText;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Decryption using the pwd hash
	 * 
	 * @param cipherText
	 * @param key
	 * @return
	 */
	byte[] decUsingPwdHash(byte[] cipherText, byte[] key) {
		try {
			SecretKeySpec sks = new SecretKeySpec(key, "AES");
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.DECRYPT_MODE, sks);
			byte[] plainText = cipher.doFinal(cipherText);
			return plainText;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * Encryption using the public key
	 * 
	 * @param plainText
	 * @param keyFileName
	 * @return
	 */
	byte[] encUsingPubKey(byte[] plainText, String keyFileName) {
		try {
			byte[] clientPublicKey = readFromFile(keyFileName);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			X509EncodedKeySpec x509 = new X509EncodedKeySpec(clientPublicKey);
			PublicKey pubKey = kf.generatePublic(x509);

			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, pubKey);
			byte[] cipherText = cipher.doFinal(plainText);
			return cipherText;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * decryption using the private key
	 * 
	 * @param cipherText
	 * @param fileName
	 * @return
	 */
	byte[] decUsingPrivKey(byte[] cipherText, String fileName) {
		try {
			byte[] privKeyByte = readFromFile(fileName);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(privKeyByte);
			PrivateKey privKey = kf.generatePrivate(privKeySpec);
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, privKey);
			byte[] plainText = cipher.doFinal(cipherText);
			return plainText;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
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
		return null;
	}

	/**
	 * This function generates the DH keys
	 * 
	 * @param p
	 * @param g
	 * @param l
	 */
	void generateDHKeys(BigInteger p, BigInteger g, int l) {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DH");
			DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
			keyGen.initialize(dhSpec);
			KeyPair keypair = keyGen.generateKeyPair();
			setDHPrivateKey(keypair.getPrivate());
			setDHPublicKey(keypair.getPublic());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * This generates the final shared key between the 2 parties which does the
	 * DH key exchange
	 * 
	 * @param privKey
	 * @param pubKeyBytes
	 * @return
	 */
	SecretKey genSecretKey(PrivateKey privKey, byte[] pubKeyBytes) {
		try {
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(pubKeyBytes);
			KeyFactory kf = KeyFactory.getInstance("DH");
			PublicKey publicKey = kf.generatePublic(x509Spec);

			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(privKey);
			ka.doPhase(publicKey, true);
			String algorithm = "DES";
			SecretKey secretKey = ka.generateSecret(algorithm);
			return secretKey;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * This function is uesd to read from the file, given a file name
	 * 
	 * @param fileName
	 * @return
	 */
	@SuppressWarnings("resource")
	byte[] readFromFile(String fileName) {
		try {

			FileInputStream fis = new FileInputStream(fileName);
			byte[] data = new byte[fis.available()];
			fis.read(data);
			return data;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	/**
	 * @return the dhPrivateKey
	 */
	public PrivateKey getDHPrivateKey() {
		return dhPrivateKey;
	}

	/**
	 * @param dhPrivateKey
	 *            the dhPrivateKey to set
	 */
	public void setDHPrivateKey(PrivateKey dhPrivateKey) {
		this.dhPrivateKey = dhPrivateKey;
	}

	/**
	 * @return the dhPublicKey
	 */
	public PublicKey getDHPublicKey() {
		return dhPublicKey;
	}

	/**
	 * @param dhPublicKey
	 *            the dhPublicKey to set
	 */
	public void setDHPublicKey(PublicKey dhPublicKey) {
		this.dhPublicKey = dhPublicKey;
	}
}
