package elGamalString;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Base64;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ElGamalString {

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

    public static String encrypt(String plainText, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("ElGamal");
        // verifikacija provajdera
		String providerName = cipher.getProvider().getName();
		String version = Double.toString(cipher.getProvider().getVersion());
		System.out.println("Koristimo provajder " + providerName + " " + version);
		
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] cipherText = cipher.doFinal(plainText.getBytes());
        return Base64.getEncoder().encodeToString(cipherText);
    }

    public static String decrypt(String cipherText, PrivateKey privateKey) throws Exception {
        byte[] bytes = Base64.getDecoder().decode(cipherText);

        Cipher cipher = Cipher.getInstance("ElGamal");
        // verifikacija provajdera
		String providerName = cipher.getProvider().getName();
		// Metoda getVersion() je oznacena kao zastarjela (Deprecated)
		// Od Java JDK 11 treba poceti korisititi cipher.getProvider().getVersionStr()
		String version = Double.toString(cipher.getProvider().getVersion());
		System.out.println("Koristimo provajder " + providerName + " " + version);

		cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(bytes));
    }

    
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());	
		
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ElGamal");
		keyPairGenerator.initialize(2048);
		KeyPair keyPair = keyPairGenerator.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		String s = encrypt("Tina Turner - Golden Eye", publicKey); 
		System.out.println("Sifrat: " + s);
		
		s = decrypt(s, privateKey); 
		System.out.println("Desifrovani otvoreni tekst: " + s);
		
	}

}
