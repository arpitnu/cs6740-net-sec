package edu.netsec.sim;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

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
public class SIMClientCryptoHelper {

	private static SIMClientCryptoHelper instance;

	// To avoid multiple instantiation.
	private SIMClientCryptoHelper() {
	}

	static synchronized SIMClientCryptoHelper getInstance() {
		if (instance == null)
			instance = new SIMClientCryptoHelper();

		return instance;
	}

	byte[] decUsingRSA(byte[] ciphertext, PrivateKey key) {
		try {
			Cipher cipher;
			cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.DECRYPT_MODE, key);
			byte[] plainText = cipher.doFinal(ciphertext);

			return plainText;
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
		return null;

	}

	byte[] encUsingRSA(String plaintext, String keyfile) {
		try {
		byte[] receiverPublicKey = SIMClientHelper.readFile(keyfile);
		KeyFactory kf;
			kf = KeyFactory.getInstance("RSA");
		
		X509EncodedKeySpec encodedKey = new X509EncodedKeySpec(
				receiverPublicKey);
		PublicKey publicKey = kf.generatePublic(encodedKey);

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		byte[] cipherText = cipher.doFinal(plaintext.getBytes());
		return cipherText;
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

	byte[] hashingFunction(String plaintext) {
		try {
		byte[] txt;
			txt = plaintext.getBytes("UTF-8");
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

	byte[] encUsingPwdHash(byte[] plaintext, byte[] key) {
		try {
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		
			cipher.init(Cipher.ENCRYPT_MODE, sks);
		
		byte[] cipherText = cipher.doFinal(plaintext);
		return cipherText;
	} catch (NoSuchAlgorithmException e1) {
		e1.printStackTrace();
	} catch (NoSuchPaddingException e1) {
		e1.printStackTrace();
	} catch (InvalidKeyException e) {
		e.printStackTrace();
	} catch (IllegalBlockSizeException e) {
		e.printStackTrace();
	} catch (BadPaddingException e) {
		e.printStackTrace();
	}
		return null;
	}

	byte[] decUsingPwdHash(byte[] plaintext, byte[] key) {
		try {
		SecretKeySpec sks = new SecretKeySpec(key, "AES");
		Cipher cipher;
			cipher = Cipher.getInstance("AES");
		
		cipher.init(Cipher.DECRYPT_MODE, sks);

		byte[] cipherText = cipher.doFinal(plaintext);
		return cipherText;
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
		return null;
	}

	KeyPair generateDHKeyPair(BigInteger p, BigInteger g, int l) {
		try {
			KeyPairGenerator kgen = KeyPairGenerator.getInstance("DH");
			DHParameterSpec dhSpec = new DHParameterSpec(p, g, l);
			kgen.initialize(dhSpec);
			KeyPair keypair = kgen.generateKeyPair();
			return keypair;
		} catch (Exception e) {
			System.out.println("Error in generating DH Key Pairs.");
			System.exit(0);
		}
		return null;
	}

	SecretKey generateSharedSecretKey(PrivateKey pvtkey, byte[] pubkeybytes) {
		try {
			X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(pubkeybytes);
			KeyFactory keyFact = KeyFactory.getInstance("DH");
			PublicKey pubkey = keyFact.generatePublic(x509KeySpec);
			KeyAgreement ka = KeyAgreement.getInstance("DH");
			ka.init(pvtkey);
			ka.doPhase(pubkey, true);
			SecretKey secretKey = ka.generateSecret("DES");
			return secretKey;
		} catch (Exception e) {
			System.out.println("Error in generating Secret Key.");
			System.exit(0);
		}
		return null;
	}
}
