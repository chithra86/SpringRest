package com.example.util;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.AlgorithmParameters;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.example.config.GenerateKeyPairConfig;
import com.example.domain.EncryptedText;

@Component
public class GenerateKeyPairUtil {
	
	private static final String ALGORITHM = "RSA";

	@Autowired
	private GenerateKeyPairConfig genKeyPairconfig;
	
	@Autowired
	private EncryptedText encryText;
	
	public PrivateKey getPrivate(byte[] privateKey)
			throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(privateKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	public byte[] signString(String data, byte[] privateKey) throws NoSuchAlgorithmException, InvalidKeyException,
			InvalidKeySpecException, IOException, SignatureException {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(getPrivate(privateKey));
		rsa.update(data.getBytes());
		return rsa.sign();
	}

	public boolean verifySignature(byte[] data, byte[] signature, byte[] publicKey) throws Exception {
		Signature sig = Signature.getInstance("SHA1withRSA");
		sig.initVerify(getPublic(publicKey));
		sig.update(data);

		return sig.verify(signature);
	}

	// Method to retrieve the Public Key from a file
	public PublicKey getPublic(byte[] publicKey) throws Exception {
		X509EncodedKeySpec spec = new X509EncodedKeySpec(publicKey);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePublic(spec);
	}

	public void signatureVerification() throws Exception {
		String dataToBeSigned = "Please encrypt me";
		byte[] publicKey = genKeyPairconfig.getPublicKey();
		byte[] privateKey = genKeyPairconfig.getPrivateKey();
		byte[] signedString = signString(dataToBeSigned, privateKey);
		System.out.println(signedString);
		boolean isValid = verifySignature(dataToBeSigned.getBytes(), signedString, publicKey);
		if (isValid)
			System.out.println(dataToBeSigned);
		else
			System.out.println("Not valid");
	}

	public void encryptDecrypt() throws Exception {
		PublicKey  publicKey = genKeyPairconfig.getGeneratedKeyPair().getPublicKey();
		PrivateKey privateKey = genKeyPairconfig.getGeneratedKeyPair().getPrivateKey();
			
		String data = "Text to be encrypted";
		
		byte[] encryptedData = encrypt(publicKey, data.getBytes());

        byte[] decryptedData = decrypt(privateKey, encryptedData);

        System.out.println(new String(decryptedData));
		
	}

	 public static byte[] encrypt(PublicKey key, byte[] inputData) throws Exception {

	        Cipher cipher = Cipher.getInstance(ALGORITHM);
	        cipher.init(Cipher.PUBLIC_KEY, key);

	        return cipher.doFinal(inputData);

	    }

	    public static byte[] decrypt(PrivateKey key, byte[] inputData) throws Exception {

	        Cipher cipher = Cipher.getInstance(ALGORITHM);
	        cipher.init(Cipher.PRIVATE_KEY, key);

	        return cipher.doFinal(inputData);

	    }

		public void aesFileDecryption() throws Exception{
			String password = "Toronto2018";

			FileInputStream saltFis = new FileInputStream("output/salt.enc");
			byte[] salt = new byte[8];	
			saltFis.read(salt);
			saltFis.close();

			FileInputStream ivFis = new FileInputStream("output/iv.enc");
			byte[] iv = new byte[16];
			ivFis.read(iv);
			ivFis.close();

			SecretKeyFactory factory = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
			KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536,
					256);
			SecretKey tmp = factory.generateSecret(keySpec);
			SecretKey secret = new SecretKeySpec(tmp.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, secret, new IvParameterSpec(iv));
			FileInputStream fis = new FileInputStream("output/encryptedfile.des");
			FileOutputStream fos = new FileOutputStream("output/plainfile_decrypted.txt");
			byte[] in = new byte[1024];
			int read;
			while ((read = fis.read(in)) != -1) {
				byte[] output = cipher.update(in, 0, read);
				if (output != null)
					fos.write(output);
			}

			byte[] output = cipher.doFinal();
			if (output != null)
				fos.write(output);
			fis.close();
			fos.flush();
			fos.close();
			System.out.println("File Decrypted. Please check output/plainfile_decrypted.txt");			
		}
		
		public void aesFileEncryption() throws Exception{
			FileInputStream inFile = new FileInputStream("input/DatatoEncrypt.txt");

			FileOutputStream outFile = new FileOutputStream("output/encryptedfile.des");

			String password = "Toronto2018";

			byte[] salt = new byte[8];
			SecureRandom secureRandom = new SecureRandom();
			secureRandom.nextBytes(salt);
			FileOutputStream saltOutFile = new FileOutputStream("output/salt.enc");
			saltOutFile.write(salt);
			saltOutFile.close();

			SecretKeyFactory factory = SecretKeyFactory
					.getInstance("PBKDF2WithHmacSHA1");
			KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536,
					256);
			SecretKey secretKey = factory.generateSecret(keySpec);
			SecretKey secret = new SecretKeySpec(secretKey.getEncoded(), "AES");

			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.ENCRYPT_MODE, secret);
			AlgorithmParameters params = cipher.getParameters();

			FileOutputStream ivOutFile = new FileOutputStream("output/iv.enc");
			byte[] iv = params.getParameterSpec(IvParameterSpec.class).getIV();
			ivOutFile.write(iv);
			ivOutFile.close();

			byte[] input = new byte[1024];
			int bytesRead;

			while ((bytesRead = inFile.read(input)) != -1) {
				byte[] output = cipher.update(input, 0, bytesRead);
				if (output != null)
					outFile.write(output);
			}

			byte[] output = cipher.doFinal();
			if (output != null)
				outFile.write(output);

			inFile.close();
			outFile.flush();
			outFile.close();

			System.out.println("File Encrypted.");
		}

		public EncryptedText getEncryptedText() throws IOException {
			//FileInputStream infile = new FileInputStream("output/plainfile_decrypted.txt");
			FileInputStream infile = new FileInputStream("output/encryptedfile.des");
		    try( BufferedReader br =
		            new BufferedReader( new InputStreamReader(infile, "UTF-8" )))
		    {
		       StringBuilder sb = new StringBuilder();
		       String line;
		       while(( line = br.readLine()) != null ) {
		          sb.append( line );
		          sb.append( '\n' );
		       }
		       encryText.setEncryptedText(sb.toString());
		       return encryText;
		    }
			
		}
}