package edu.netsec.ps2;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;

/** 
 * The RSAKeyGen class is used to generate 1024 bit RSA keys required for 
 * file encryption and decryption application.
 */

class RSAKeyGen{
	
    public static void main (String[] args) {
        try {
            KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
            
            keyPairGen.initialize(1024);
            
            KeyPair keyPair = keyPairGen.genKeyPair();

            KeyFactory fact = KeyFactory.getInstance("RSA");
            
            RSAPublicKeySpec publicKeySpec = fact.getKeySpec(keyPair.getPublic(), RSAPublicKeySpec.class);
            
            RSAPrivateKeySpec privateKeySpec = fact.getKeySpec(keyPair.getPrivate(), RSAPrivateKeySpec.class);

            writeToFile("publicKey.key", publicKeySpec.getModulus(), publicKeySpec.getPublicExponent());
            
            writeToFile("privateKey.key", privateKeySpec.getModulus(), privateKeySpec.getPrivateExponent());
        } catch (Exception e) {
            System.out.println("Unexpected error .. " + e);
            
            // Error termination.
            System.exit(-1);
        }
    }   

    public static void writeToFile(String keyFile, BigInteger modulus, BigInteger exponent) 
    		throws IOException {
        BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(keyFile));
        ObjectOutputStream oos = new ObjectOutputStream(bos);

        try {
        	oos.writeObject(modulus);
        	oos.writeObject(exponent);
        } catch (Exception e) {
            throw new IOException("IO error while writing RSA key to file", e);
        } 
        
        finally {
        	oos.close();
        }
    }
}