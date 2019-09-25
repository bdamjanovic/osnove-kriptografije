package keyPairGenerator2;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

public class KeyPairGenerator2 {
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
		System.out.println("Klasa RSAPublicKey i metode "
				+ "getModulus() i getPublicExponent():");
		System.out.println("-------------------");
		RSAPublicKey rsaPub  = (RSAPublicKey)(publicKey);
		BigInteger modulus = rsaPub.getModulus();
		BigInteger publicExponent = rsaPub.getPublicExponent();
		System.out.println("getModulus()" + '\n' + modulus);
		System.out.println("getPublicExponent()" + '\n' + publicExponent);
		System.out.println("-------------------");
		System.out.println("Klasa RSAPrivateKey i metode getModulus() "
				+ "i getPrivateExponent():");
		System.out.println("-------------------");
		RSAPrivateKey rsaPriv  = (RSAPrivateKey)(privateKey);
		BigInteger privModulus = rsaPriv.getModulus();
		BigInteger privExponent = rsaPriv.getPrivateExponent();
		System.out.println("getModulus()" + '\n' + privModulus);
		System.out.println("getPrivateExponent()" + '\n' + privExponent);
		System.out.println("-------------------");	
	} catch (NoSuchAlgorithmException e) {
		e.printStackTrace();
	}

}

}

