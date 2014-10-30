package edu.netsec.sim;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Random;

/**
 * @author Ananthanarayanan Balachandran (ananth@ccs.neu.edu)
 * @author Arpit Mehta (arpitm@ccs.neu.edu)
 * 
 */
public class SIMClientHelper {
	
	
	static byte[] readFile(final String fileName)  {
		try {
		File file = new File(fileName);
		int size = (int) file.length();
		byte[] bytes = new byte[size];
		DataInputStream dis = new DataInputStream(new FileInputStream(file));
		int read = 0;
		int nRead = 0;
		while (read < bytes.length
				&& (nRead = dis.read(bytes, read, bytes.length - read)) >= 0) {
			read += nRead;
		}

		if (read < bytes.length) {
			System.out.println("Could not read: " + fileName);
		}

		return bytes;
		} catch (FileNotFoundException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	static int generateNonceChallenge() {
		Random randomGenerator = new Random();
		int randomInt = randomGenerator.nextInt();
		return randomInt;
	}

	byte[] readNextField(DataInputStream dis) {
		try {
			int len = dis.readInt();
			byte[] data = new byte[len];
			dis.read(data);
			return data;
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}

	static void addNextField(DataOutputStream dos, byte[] data)
			throws Exception {
		dos.writeInt(data.length);
		dos.write(data);
	}

	static int byteArrayToInt(byte[] bytes) {
		int result = 0;
		for (int i = 0; i < 4; i++) {
			result = (result << 8) - Byte.MIN_VALUE + (int) bytes[i];
		}
		return result;
	}
}
