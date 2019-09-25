package keyPairGenerator3;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;

//Ako niste obradili program HexUtils, sada je vrijeme da to uradite
public class KeyPairGenerator3_1 {
	private static String cifre = "0123456789abcdef";
	public static String byteArrToHexStr(byte[] nizBajta, int duzina) {
	    StringBuffer string = new StringBuffer();
	    for (int i = 0; i != duzina; i++) {
	        int v = nizBajta[i];
	        v = nizBajta[i] & 0xff;
	        string.append(cifre.charAt(v >> 4));
	        string.append(cifre.charAt(v & 0xf));
	    }
	    return string.toString();
	}	
	public static String byteArrToHexStr(byte[] nizBajta) {
	    int duzina = nizBajta.length;
	    return byteArrToHexStr(nizBajta, duzina);
	}	

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
		String s = byteArrToHexStr(encodedKey); 
		System.out.println("Javni kljuc getEncoded() "
				+ "i DatatypeConverter Heksadekadno:");
		System.out.println("--------------");
		System.out.println(s);
		
		encodedKey = privateKey.getEncoded();
		s = byteArrToHexStr(encodedKey); 
		System.out.println("Privatni kljuc getEncoded() "
				+ "i DatatypeConverter Heksadekadno:");
		System.out.println("--------------");
		System.out.println(s);		
		
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	}

	}

}
