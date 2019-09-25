package keyPairGenerator3;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import javax.xml.bind.DatatypeConverter;

// Ako niste obradili program DataTypeConvertor, sada je vrijeme da to uradite
public class KeyPairGenerator3 {

	public static void main(String[] args) {
		try {		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		System.out.println("Ispis generisanih kljuceva:");
		byte[] encodedKey;		
		encodedKey = publicKey.getEncoded();
		String s = DatatypeConverter.printHexBinary(encodedKey); 
		System.out.println("Javni kljuc getEncoded() "
				+ "i DatatypeConverter Heksadekadno:");
		System.out.println("--------------");
		System.out.println(s);
		
		encodedKey = privateKey.getEncoded();
		s = DatatypeConverter.printHexBinary(encodedKey); 
		System.out.println("Privatni kljuc getEncoded() "
				+ "i DatatypeConverter Heksadekadno:");
		System.out.println("--------------");
		System.out.println(s);		
		
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	}

	}

}
