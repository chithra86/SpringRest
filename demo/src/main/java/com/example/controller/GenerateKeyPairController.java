package com.example.controller;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.domain.EncryptedText;
import com.example.domain.ResponseKeyPair;
import com.example.service.GenerateKeyPairService;

@RestController
public class GenerateKeyPairController {
	
	@Autowired
	private GenerateKeyPairService genKeyPairService;
	
	@GetMapping("/getPublicKey")
	public ResponseKeyPair generateKeyPairs() throws NoSuchAlgorithmException, IOException {
        return genKeyPairService.getPublicKey();
    }
	
	@GetMapping("/getEncryptedText")
	public EncryptedText getencryptedText() throws IOException {
		return genKeyPairService.getAESEncryptedText();
	}
	
}
