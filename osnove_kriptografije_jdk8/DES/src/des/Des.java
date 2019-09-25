package des;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class Des {

public static void main(String[] args) throws Exception{
	// des 56 bita, ali 8 bajta. Po jedan bit u svakom bajtu je bit parnosti 
	// (parity bit)
	// ali biti parnosti se u stvari ne koriste.
	// Znaci, kljuc se sastoji od 64 bita, ali se koristi samo 56 bita, dok se 
	// najmanje znacajni biti
	// u svakom bajtu odbacuju.
	// Algoritmi PBKDF1 i PBKDF2  se koriste da bi se password konvertovao u 
	// simetricni kljuc; 
	// te klasa SecretKeyFactory.generateSecret( DESKeySpec) 
	// U praksi, biti parnosti se ignorisu. Algoritam funkcionise i bez 
	// konvertovanja
		byte[] kljuc = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08 };
        int bufflen = 2048;

        byte inBuff[] = new byte[bufflen];
        byte outBuff[] = new byte[bufflen];
        int ocitao = 0;
        FileInputStream fis = new FileInputStream("d://otvoreni.txt");
        FileOutputStream fos = new FileOutputStream("d://sifrat.txt");
        SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "DES");
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        while ((ocitao = fis.read(inBuff)) != -1) {
            int processed = cipher.update(inBuff, 0, ocitao, outBuff);
            fos.write(outBuff, 0, processed);
        }
        int count = cipher.doFinal(outBuff, 0);
        System.out.println("Rezultat sifrovanja nalazi se u datoteci sifrat.txt");
        fos.write(outBuff, 0, count);
        fis.close();
        fos.flush();
        fos.close();

   }
}
