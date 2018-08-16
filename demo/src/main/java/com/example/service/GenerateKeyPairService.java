package com.example.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;

import com.example.domain.GenerateKeyPair;
import com.example.util.GenerateKeyPairUtil;

@Service
@Component
public class GenerateKeyPairService {

	@Autowired
	private GenerateKeyPairUtil genKeyPairUtil;

	@Autowired
	private GenerateKeyPair keyPair;

	public GenerateKeyPair getPublicKey() throws NoSuchAlgorithmException, IOException {

		PublicKey pubKey = genKeyPairUtil.generateKeyPair().getPublic();
		keyPair.setPublicKey(pubKey.getEncoded());

		genKeyPairUtil.writeInDERFormat(pubKey.getEncoded(), "C:\\certificates\\cert-public-key.der");
		genKeyPairUtil.writeInPEMFormat(pubKey, "C:\\certificates\\cert-public-key.pem");
		return keyPair;
	}

	public GenerateKeyPair getPrivateKey() throws NoSuchAlgorithmException, IOException {

		PrivateKey privateKey = genKeyPairUtil.generateKeyPair().getPrivate();
		keyPair.setPublicKey(privateKey.getEncoded());

		genKeyPairUtil.writeInDERFormat(privateKey.getEncoded(), "C:\\certificates\\cert-private-key.der");
		genKeyPairUtil.writeInPEMFormat(privateKey, "C:\\certificates\\cert-private-key.pem");
		return keyPair;
	}

	public PrivateKey getPrivate(String filename) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException   {
		byte[] keyBytes = Files.readAllBytes(new File(filename).toPath());
		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		KeyFactory kf = KeyFactory.getInstance("RSA");
		return kf.generatePrivate(spec);
	}

	
	public byte[] sign(String data, String keyFile) throws NoSuchAlgorithmException, InvalidKeyException, InvalidKeySpecException, IOException, SignatureException  {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(getPrivate(keyFile));
		rsa.update(data.getBytes());
		return rsa.sign();
	}

}
