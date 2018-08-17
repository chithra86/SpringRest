package com.example.service;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.example.config.GenerateKeyPairConfig;
import com.example.domain.EncryptedText;
import com.example.domain.ResponseKeyPair;
import com.example.util.GenerateKeyPairUtil;

@Service
@Component
public class GenerateKeyPairService {

	@Autowired
	private GenerateKeyPairConfig genKeyPairconfig;	
	
	@Autowired
	private GenerateKeyPairUtil genKeyPairUtil;
	
	@Autowired
	private ResponseKeyPair respKeyPair;
	
	public ResponseKeyPair getPublicKey() throws NoSuchAlgorithmException, IOException{
		
		respKeyPair.setPublicKey(genKeyPairconfig.getPublicKey());
		return respKeyPair;
	}

	public EncryptedText getAESEncryptedText() throws IOException {
		
		return genKeyPairUtil.getEncryptedText();
	}
}
