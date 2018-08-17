package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

import com.example.util.GenerateKeyPairUtil;

@SpringBootApplication(scanBasePackages = {"com.example"})
public class DemoApplication implements CommandLineRunner{

	@Autowired
	GenerateKeyPairUtil genKeyPair;
	
	public static void main(String[] args) {
		SpringApplication.run(DemoApplication.class, args);
	}
	
	public void run(String... args) throws Exception{
		
		//Task 2: Take a basic string of characters (length between 50-100 characters) 
		//and sign the content with the Private Key, verify that signature content using the Public Key.
		
		genKeyPair.signatureVerification();
		
		//Task 3 : Encrypt other string of characters with the Public key and unencrypted with the Private Key.
		
		genKeyPair.encryptDecrypt();
		
		//Task 4 : Take a random text file between 1024 to 2048 (or more) bytes in length and using AES, 
		//encrypt the data and unencrypted using the password:   Toronto2018
		
		genKeyPair.aesFileEncryption();
		
		genKeyPair.aesFileDecryption();		
		
	}

	
}
