package keyPairGenerator1;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

public class KeyPairGenerator1 {

public static void main(String[] args) {
	try {
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		String s = Base64.getEncoder().encodeToString(publicKey.getEncoded());
		System.out.println("Javni kljuc: " + s);
		s = Base64.getEncoder().encodeToString(privateKey.getEncoded());
		System.out.println("Privatni kljuc: " + s);
		
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	}


}

}
 