package com.example.util;

import java.io.File;
import java.io.FileOutputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import org.bouncycastle.openssl.PEMWriter;
import org.springframework.stereotype.Component;

@Component
public class GenerateKeyPairUtil {

	public KeyPair generateKeyPair() throws NoSuchAlgorithmException {
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
		keyGen.initialize(2048);
		return keyGen.generateKeyPair();
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

	
}
