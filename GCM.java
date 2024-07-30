/**
 * 
 */
package com.org.bhfl.mobilecommonservices.utils;

import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class GCM {

	private static final int GCM_IV_LENGTH = 12;
	private static final int GCM_TAG_LENGTH = 128;

	private static final String MasterKey = "EMa8dPoqJ1chundc--o4Gg==";

	public static String makeKey() throws Exception {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		SecretKey secretKey = keyGen.generateKey();
		byte[] secretKeyEncoded = secretKey.getEncoded();
		return encodeToStr(secretKeyEncoded);
	}

	public String decrypt(String cipherText) {
		String response = "";
		try {
			SecretKey secretKey = generateSecretKey(MasterKey);
			String[] parts = cipherText.split(":");
			byte[] IV = decodeToByte(parts[0]);
			response = decrypt(IV, cipherText, secretKey);
		} catch (Exception e) {
//            //e.printStackTrace
		}
		return response;
	}

	private String decrypt(byte[] IV, String cipherText, SecretKey secretKey) {
		byte[] decryptedText = null;
		try {
			String[] parts = cipherText.split(":");
			byte[] decodedCipher = decodeToByte(parts[1]);
// Get Cipher Instance
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
// Create SecretKeySpec
			SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
// Create GCMParameterSpec
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, IV);
// Initialize Cipher for DECRYPT_MODE
			cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);
//byte[] aad = new byte[128];
			byte[] aad = new byte[] { (byte) 0x80, 0x53, 0x1c, (byte) 0x87, (byte) 0xa0, 0x42, 0x69, 0x10, (byte) 0xa2,
					(byte) 0xea, 0x08, 0x00, 0x2b, 0x30, 0x30, (byte) 0x9d };
			cipher.updateAAD(aad);
// Perform Decryption
			decryptedText = cipher.doFinal(decodedCipher);
		} catch (Exception e) {
//            //e.printStackTrace
		}
		return new String(decryptedText);

	}

	public String encrypt(String plainText) {
		String response = "";
		try {
			SecretKey secretKey = generateSecretKey(MasterKey);
			response = encrypt(generateIV(), plainText, secretKey);
		} catch (Exception e) {
//            //e.printStackTrace
		}
		return response;
	}

	private SecretKey generateSecretKey(String encodedKey) {

		byte[] decodedKey = decodeToByte(encodedKey);
		SecretKey secretKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
//        System.out.println("secretKey : " + secretKey);
		return secretKey;
	}

	private String encrypt(byte[] IV, String plaintext, SecretKey secretKey) {
		byte[] encrypted = null;
		StringBuilder cipherText = null;
		try {
// Get Cipher Instance
			Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
// Create SecretKeySpec
			SecretKeySpec keySpec = new SecretKeySpec(secretKey.getEncoded(), "AES");
// Create GCMParameterSpec
			GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH, IV);
// Initialize Cipher for ENCRYPT_MODE
			cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);
//byte[] aad = new byte[128];
			byte[] aad = new byte[] { (byte) 0x80, 0x53, 0x1c, (byte) 0x87, (byte) 0xa0, 0x42, 0x69, 0x10, (byte) 0xa2,
					(byte) 0xea, 0x08, 0x00, 0x2b, 0x30, 0x30, (byte) 0x9d };
			cipher.updateAAD(aad);
// Perform Encryption
			encrypted = cipher.doFinal(plaintext.getBytes());
			cipherText = new StringBuilder();
			// cipherText.append(Base64.getEncoder().encodeToString(IV));
			cipherText.append(encodeToStr(IV));
			cipherText.append(":");
			cipherText.append(encodeToStr(encrypted));
		} catch (Exception e) {
//            //e.printStackTrace
		}

		return cipherText.toString();
	}

	private static byte[] generateIV() {
		byte[] IV = new byte[GCM_IV_LENGTH];
		SecureRandom random = new SecureRandom();
		random.nextBytes(IV);
		return IV;

	}

//	public static String encodeToStr(byte[] bytes) {
//		return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
//	}
//
//	public static byte[] decodeToByte(String str) {
//		return android.util.Base64.decode(str, android.util.Base64.NO_WRAP);
//	}

	public static String encodeToStr(byte[] bytes) {
		Base64.Encoder encoder = Base64.getUrlEncoder();
//		return android.util.Base64.encodeToString(bytes, android.util.Base64.NO_WRAP);
		return encoder.encodeToString(bytes);
	}

	public static byte[] decodeToByte(String str) {
		Base64.Decoder decoder = Base64.getUrlDecoder();
//		return android.util.Base64.decode(str, android.util.Base64.NO_WRAP);
		return decoder.decode(str);
	}

	public static void main(String args[]) throws Exception {

		String encodedKey = makeKey();
		String cif = "609";
		byte cifarray[] = cif.getBytes();
		GCM cryptoUtils = new GCM();
		System.out.println(cryptoUtils.encrypt(cif));
		String encryptedValue = cryptoUtils.encrypt(cif);
		String decodedValue = cryptoUtils.decrypt(encryptedValue);
		System.out.println(decodedValue);

//		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
//		keyGen.init(128);
//		SecretKey secretKey = keyGen.generateKey();
//		byte[] secretKeyEncoded = secretKey.getEncoded();
//		System.out.println(encodeToStr(secretKeyEncoded));

	}
}
