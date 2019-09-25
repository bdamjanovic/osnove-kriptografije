package desInv;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class DesInv {

public static void main(String[] args) throws Exception {
	// des 56 bita, ali 8 bajta. Po jedan bit u svakom bajtu je bit parnosti (parity bit)
    // ali biti parnosti se u stvari ne koriste.
    // Znaci, kljuc se sastoji od 64 bita, ali se koristi samo 56 bita, dok se najmanje znacajni biti
    // u svakom bajtu odbacuju.
    byte[] kljuc = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x08 };
    int bufflen = 2048;

    byte inBuff[] = new byte[bufflen];
    byte outBuff[] = new byte[bufflen];
    int ocitao = 0;
    FileInputStream fis = new FileInputStream("d://sifrat.txt");
    FileOutputStream fos = new FileOutputStream("d://izlaz_desif.txt");
    SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "DES");
    Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");
    cipher.init(Cipher.DECRYPT_MODE, skeySpec);
    while ((ocitao = fis.read(inBuff)) != -1) {
        int processed = cipher.update(inBuff, 0, ocitao, outBuff);
        fos.write(outBuff, 0, processed);
    }
    int count = cipher.doFinal(outBuff, 0);
    fos.write(outBuff, 0, count);
    System.out.println("Rezultat desifrovanja nalazi se u datoteci izlaz_desif.txt");
    fis.close();
    fos.flush();
    fos.close();
}
}
