package encrypt;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class EncryptManager {
	private static final String MODE = "AES/CBC/PKCS5Padding";
	
	private byte[] shared_key;
	private SecretKeySpec key;
	private Cipher cipher;
	private Cipher decode;
	
	public EncryptManager (byte[] shared_key) throws NoSuchAlgorithmException, NoSuchPaddingException {
		key = new SecretKeySpec(shared_key, "AES");
		this.shared_key = shared_key;
	}
	
	public void init_decode (byte[] nonce) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
//		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//		
//		IvParameterSpec iv = new IvParameterSpec(nonce, 0, 16);
//		
//		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		decode = Cipher.getInstance(MODE);
		
		IvParameterSpec iv = new IvParameterSpec(nonce, 0, 16);
		
		decode.init(Cipher.DECRYPT_MODE, key, iv);
	}

	public byte[] init_decode (byte[] src, byte[] shared_key, byte[] nonce) throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, InvalidKeyException, InvalidAlgorithmParameterException {
		SecretKeySpec key = new SecretKeySpec(shared_key, "AES");
		
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
//		Cipher cipher = Cipher.getInstance("AES/CBC/NoPadding");
//		final int BLOCK_SIZE = cipher.getBlockSize();
//		
//		AlgorithmParameters iv = AlgorithmParameters.getInstance("AES");
		IvParameterSpec iv = new IvParameterSpec(nonce, 0, 16);
//		iv.init(BinaryHexConverter.HexStringToBytes("3dafba429d9eb430b422da802c9fac41"));
		
//		cipher.init(Cipher.DECRYPT_MODE, key, iv);
//		return cipher.doFinal(src, BLOCK_SIZE, src.length - BLOCK_SIZE);
		cipher.init(Cipher.DECRYPT_MODE, key, iv);
		
		System.out.println("**** Decode");
		System.out.println("Input byte: " + BinaryHexConverter.bytesToHexString(src));
		System.out.println("Shared key: " + BinaryHexConverter.bytesToHexString(shared_key));
		System.out.println("Nonce byte: " + BinaryHexConverter.bytesToHexString(nonce));
		System.out.println("     End ****");
		
		byte[] decoded = cipher.doFinal(src);
		
		return decoded;
	}
	
	public byte[] init_encode (byte[] src, byte[] shared_key, byte[] nonce) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		SecretKeySpec key = new SecretKeySpec(shared_key, "AES");
		
		cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		decode = Cipher.getInstance("AES/CBC/PKCS5Padding");
		
		IvParameterSpec iv = new IvParameterSpec(nonce);
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		decode.init(Cipher.DECRYPT_MODE, key, iv);
		
		byte[] encoded = cipher.doFinal(src);
		
		System.out.println("**** Encode");
		System.out.println("Input byte: " + BinaryHexConverter.bytesToHexString(src));
		System.out.println("Shared key: " + BinaryHexConverter.bytesToHexString(shared_key));
		System.out.println("Nonce byte: " + BinaryHexConverter.bytesToHexString(nonce));
		System.out.println("Encoded byte: " + BinaryHexConverter.bytesToHexString(encoded));
		System.out.println("     End ****");
		
		return encoded;
	}
	
	public byte[] encode (byte[] src) throws IllegalBlockSizeException, BadPaddingException {
		byte[] encoded = cipher.doFinal(src);
		
		System.out.println("**** Encode");
		System.out.println("Input byte: " + BinaryHexConverter.bytesToHexString(src));
		System.out.println("Shared key: " + BinaryHexConverter.bytesToHexString(shared_key));
		System.out.println("Encoded byte: " + BinaryHexConverter.bytesToHexString(encoded));
		System.out.println("     End ****");
		
		return encoded;
	}
	
	public byte[] decode (byte[] src) throws IllegalBlockSizeException, BadPaddingException {
		byte[] decoded = decode.doFinal(src);
		
		System.out.println("**** Decode");
		System.out.println("Input byte: " + BinaryHexConverter.bytesToHexString(src));
		System.out.println("Shared key: " + BinaryHexConverter.bytesToHexString(shared_key));
		System.out.println("Decoded byte: " + BinaryHexConverter.bytesToHexString(decoded));
		System.out.println("     End ****");
		
		return decoded;
	}
}
