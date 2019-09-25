package blowfishInvDatoteka;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class BlowfishInvDatoteka {

public static void main(String[] args)  throws Exception{
    // Blowfish uzima 64-bitni blok i kljuc varijabline duzine od 32 bita do 448 bita.
    // To je Feistelov algoritam sa 16 rundi koji koristi velike S-Boksove koji zavise od kljuca. 

	byte[] kljuc = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    int bufflen = 2048;

    byte inBuff[] = new byte[bufflen];
    byte outBuff[] = new byte[bufflen];
    int ocitao = 0;
    FileInputStream fis = new FileInputStream("d:/sifrat.txt");
    FileOutputStream fos = new FileOutputStream("d:/izlaz_desif.txt");
    SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "Blowfish");
    Cipher cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding");
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
