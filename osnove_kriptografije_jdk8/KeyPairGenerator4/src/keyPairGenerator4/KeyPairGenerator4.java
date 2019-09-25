package keyPairGenerator4;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import javax.xml.bind.DatatypeConverter;

public class KeyPairGenerator4 {

	public static void main(String[] args) {
		try {
			KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			// treba koristiti kljuceve duzine 2048 ili duze
			// ovdje je koristen 512 bitni kljuc samo radi duzine ispisa,
			// da bi uocili da su moduli privatnog i javnog kljuca isti			
			keyPairGenerator.initialize(512);
			KeyPair keyPair = keyPairGenerator.generateKeyPair();
			
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			System.out.println("-------------------");
			System.out.println("Ispis generisanih kljuceva - tezi dio posla:");
			System.out.println("-------------------");
			
			
			System.out.println("-------------------");
			System.out.println("Metoda publicKey.getEncoded() i ");
			System.out.println("klasa DatatypeConverter i metodprintHexBinary(),");
			System.out.println("a zatim i publicKey.getFormat() i publicKey.getAlgorithm():");
			System.out.println("-------------------");
			byte[] encodedKey;		
			encodedKey = publicKey.getEncoded();
			String s = DatatypeConverter.printHexBinary(encodedKey); 
			System.out.println("Javni kljuc HEX:");
			System.out.println(s);
			
			s = publicKey.getFormat(); 
			System.out.println("Format: " + s);
			s = publicKey.getAlgorithm(); 
			System.out.println("Algoritam: " + s);
			
			System.out.println("-------------------");
			System.out.println("publicKey.toString() - Metoda toString() samo za javni kljuc");
			System.out.println("-------------------");
			s = publicKey.toString(); 
			System.out.println(s);
			System.out.println("-------------------");
			System.out.println("Klasa RSAPublicKey i metode getModulus() i getPublicExponent():");
			System.out.println("-------------------");
			RSAPublicKey rsaPub  = (RSAPublicKey)(publicKey);
			BigInteger modulus = rsaPub.getModulus();
			BigInteger publicExponent = rsaPub.getPublicExponent();
			System.out.println("Modulus: " + modulus);
			System.out.println("Public exponent: " + publicExponent);
			System.out.println("-------------------");
			System.out.println("Javni kljuc: ");
			String encodedKeyB64 = 
	                Base64.getEncoder().encodeToString(publicKey.getEncoded());
		      System.out.println(encodedKeyB64);
		      
			System.out.println("-------------------");
			
			encodedKey = privateKey.getEncoded();
			s = DatatypeConverter.printHexBinary(encodedKey); 
			System.out.println("Privatni kljuc: ");
			System.out.println(s);
			RSAPrivateKey rsaPriv  = (RSAPrivateKey)(privateKey);
			BigInteger privModulus = rsaPriv.getModulus();
			BigInteger privExponent = rsaPriv.getPrivateExponent();
			System.out.println(privModulus);
			System.out.println(privExponent);
			System.out.println("-------------------");
			
			
			
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
	}

}
