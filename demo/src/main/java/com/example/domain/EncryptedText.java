package com.example.domain;

import org.springframework.stereotype.Component;

@Component
public class EncryptedText {

	private String encryptedTextMessage;

	public String getEncryptedText() {
		return encryptedTextMessage;
	}

	public void setEncryptedText(String encryptedText) {
		this.encryptedTextMessage = encryptedText;
	}
	
}
