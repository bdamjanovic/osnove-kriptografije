package keyGenerator3;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import java.security.Security;
import org.bouncycastle.jcajce.provider.BouncyCastleFipsProvider;
/*
Ako se u Eclipse IDE javi greska
Access restriction: 
The type 'BouncyCastleFipsProvider' is not API 
(restriction on required library 'D:\Program Files\Java\jre..........\lib\ext\bc-fips-1.0.0.jar')


 */


public class KeyGenerator3 {

		public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException {
			
			Security.addProvider(new BouncyCastleFipsProvider());
			
		      // Kreiranje KeyGenerator objekta
		      KeyGenerator keyGen = KeyGenerator.getInstance("AES", "BCFIPS");     
 
		      // Inicijalizacija KeyGenerator-a na 256 bita 
		      // uz pomoc instance SecureRandom klase
		      keyGen.init(256);
		      // Kreiranje kljuca
		      SecretKey key = keyGen.generateKey();
		      String encodedKey = 
	                Base64.getEncoder().encodeToString(key.getEncoded());
		      System.out.println(encodedKey);    
		}
	}

