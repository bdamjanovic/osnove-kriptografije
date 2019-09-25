package twofish;

import java.security.Security;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Twofish {
	public static byte[] hexStrToByteArr(String s) throws Exception {
		if ((s.length() % 2) != 0)
			throw new Exception();
		int len = s.length() / 2;
		byte[] niz = new byte[len];
		for (int i = 0; i < len; i++) {
			int prvaCifra = konvertujHuI(s.charAt(2 * i));
			int drugaCifra = konvertujHuI(s.charAt(2 * i + 1));
			niz[i] = (byte) ((prvaCifra << 4) + drugaCifra);
		}
		return niz;
	}

	private static int konvertujHuI(char hexChar) {
		int cifra = Character.digit(hexChar, 16);
		if (cifra == -1) {
			throw new IllegalArgumentException("Neispravan heksadekadni karakter: " + hexChar);
		}
		return cifra;
	}

	public static void main(String[] args) throws Exception {
		// Za novije verzije Java JDK, morate importovati datoteku bcprov-jdk15on-162.jar
		// desni klik na korijen projekta, Properties-Java Build Path-Add External Jars 
		Security.addProvider( new BouncyCastleProvider() );		

		int bufflen = 64;
		byte inBuff[] = new byte[] { 91, 92, 93, 94 };
		byte outBuff[] = new byte[bufflen];
		byte invCipOutBuff[] = new byte[bufflen];
		byte[] kljuc = hexStrToByteArr("00000000000000000000000000000000");
		// encrypt
		SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "Twofish/ECB/PKCS7Padding");
		Cipher cipher = Cipher.getInstance("Twofish", "BC");
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
		int obradjeno = cipher.doFinal(inBuff, 0, inBuff.length, outBuff);
		System.out.println("Rezultat sifrovanja (obradjeno je " + obradjeno + " bajta) je ");
		System.out.println(Arrays.toString(outBuff));
		// decrypt
		Cipher invCipher = Cipher.getInstance("Twofish");
		invCipher.init(Cipher.DECRYPT_MODE, skeySpec);
		int obradjeno2 = invCipher.doFinal(outBuff, 0, obradjeno, invCipOutBuff);
		System.out.println("Rezultat desifrovanja (obradjeno je " + obradjeno2 + " bajta) je ");
		System.out.println(Arrays.toString(invCipOutBuff));
	}
}
