package aesBuffCfb;

import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;


public class AesBuffCfb {

public static byte[] hexStrToByteArr(String s) throws Exception {
    if ( (s.length() % 2) != 0 )
        throw new Exception();
    int len = s.length() / 2;
    byte[] niz = new byte[len];
    for (int i = 0; i < len; i++) {
        int prvaCifra = konvertujHuI(s.charAt(2 * i));
        int drugaCifra = konvertujHuI(s.charAt(2 * i + 1));
        niz[i] =  (byte) ((prvaCifra << 4) + drugaCifra);
    }
    return niz;
}
private static int konvertujHuI(char hexChar) {
    int cifra = Character.digit(hexChar, 16);
    if(cifra == -1) {
        throw new IllegalArgumentException(
          "Neispravan heksadekadni karakter: "+ hexChar);
    }
    return cifra;
}  	
public static byte[][] cfbSifrovanje(SecretKey klljuc, byte[] otvoreni) throws Exception {
	Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
	cipher.init(Cipher.ENCRYPT_MODE, klljuc);
	return new byte[][] { 
		cipher.getIV(), 
		cipher.doFinal(otvoreni) 
	};
} 

public static byte[] cfbDesifrovanje(SecretKey kljuc, byte[] iv, byte[] sifrat) throws Exception {
	Cipher cipher = Cipher.getInstance("AES/CFB/NoPadding");
	cipher.init(Cipher.DECRYPT_MODE, kljuc, new IvParameterSpec(iv));
	return cipher.doFinal(sifrat);
}

public static void main(String[] args) throws Exception {
       byte[] kljuc = 
    		   hexStrToByteArr("01234567890123450123456789012345");
       byte[] optvoreni = 
    		   hexStrToByteArr("0102030405060708090A0B0C");		
       SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "AES");
       byte[][] rezultatSifrovanja = cfbSifrovanje(skeySpec, optvoreni);
       
       byte[] iv = rezultatSifrovanja[0];
       byte[] sifrat = rezultatSifrovanja[1];
       byte[] desifrovano = cfbDesifrovanje(skeySpec, iv, sifrat);
       // Iako smo otvoreni tekst zadali kao heksadekadne brojeve,
       // rezultate ispisujemo u dekadnom brojnom sistemu.
       // Za vjezbu pokusajte da ih pretvorite u heksadekadni brojni sistem
       System.out.println(Arrays.toString(desifrovano));
}
}
