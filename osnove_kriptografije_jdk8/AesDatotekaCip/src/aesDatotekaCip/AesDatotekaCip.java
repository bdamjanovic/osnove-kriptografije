package aesDatotekaCip;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AesDatotekaCip {

public static void main(String[] args) throws Exception {
    byte[] kljuc = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        int bufflen = 2048;
        byte inBuff[] = new byte[bufflen];
        byte outBuff[] = new byte[bufflen];
        int ocitao = 0;
        FileInputStream fis = new FileInputStream("d:/otvoreni.txt"); 
        FileOutputStream fos = new FileOutputStream("d:/sifrat.txt");
        SecretKeySpec skeySpec = new SecretKeySpec(kljuc, "AES");
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
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
