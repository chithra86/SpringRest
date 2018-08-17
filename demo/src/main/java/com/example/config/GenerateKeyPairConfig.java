package com.example.config;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

import org.bouncycastle.openssl.PEMWriter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import com.example.domain.GenerateKeyPair;

@Component
public class GenerateKeyPairConfig {

	@Autowired
	private GenerateKeyPair keyPair;
	
	
	@Bean
	public GenerateKeyPair generateKeys() throws NoSuchAlgorithmException, IOException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		KeyPair genKeyPair = keyGen.generateKeyPair();
		PublicKey pubKey = genKeyPair.getPublic();
		System.out.println(pubKey);
		keyPair.setPublicKey(pubKey);

		writeInDERFormat(pubKey.getEncoded(), "output/cert-public-key.der");
		writeInPEMFormat(pubKey, "output/cert-public-key.pem");
		
		
		PrivateKey privateKey = genKeyPair.getPrivate();
		keyPair.setPrivateKey(privateKey);

		writeInDERFormat(privateKey.getEncoded(), "output/cert-private-key.der");
		writeInPEMFormat(privateKey, "output/cert-private-key.pem");
		
		return keyPair;
		
	}	
	public void writeInDERFormat(byte[] pubKey, String fileName) throws IOException {
		FileOutputStream keyfos = new FileOutputStream(fileName);
		keyfos.write(pubKey);
		keyfos.close();
	}

	public void writeInPEMFormat(Object key, String fileName) throws IOException {
		PEMWriter pemWriter = new PEMWriter(new FileWriter(new File(fileName)));
		pemWriter.writeObject(key);
		pemWriter.close();
	}

	public byte[] getPublicKey() {
		return keyPair.getPublicKey().getEncoded();
	}
	
	public byte[] getPrivateKey() {
		return keyPair.getPrivateKey().getEncoded();
	}
	
	public GenerateKeyPair getGeneratedKeyPair() {
		return keyPair;
	}
}
