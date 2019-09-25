package sha256;

import java.security.MessageDigest;

public class Sha256 {
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

	public static void main(String[] args) throws Exception {
		String data = "Duran Duran - A View to a Kill"; 
		MessageDigest md = MessageDigest.getInstance("SHA-256");  
		byte nizBajta[] = md.digest(data.getBytes());  
        String s = byteArrToHexStr(nizBajta, nizBajta.length);
        System.out.println("Rezultat: " + s);

	}

}
