package com.example.domain;

import org.springframework.stereotype.Component;

@Component
public class GenerateKeyPair {
	
	private byte[] publicKey;
	
	private byte[] privateKey;

	public byte[] getPublicKey() {
		return publicKey;
	}

	public void setPublicKey(byte[] publicKey) {
		this.publicKey = publicKey;
	}

	public byte[] getPrivateKey() {
		return privateKey;
	}

	public void setPrivateKey(byte[] privateKey) {
		this.privateKey = privateKey;
	}
	
	

}
