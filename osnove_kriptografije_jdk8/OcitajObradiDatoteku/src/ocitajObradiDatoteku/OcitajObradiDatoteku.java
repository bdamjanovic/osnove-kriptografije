package ocitajObradiDatoteku;

import java.io.FileInputStream;

public class OcitajObradiDatoteku {

	public static void algoritam(byte buff[] ) {
		int red = 0;
		// algoritam obradjuje npr. bafer abcdefgh 
		// blok po blok
		// ispisuje 
		// abcd
		// efgh
		while (red < 2) {
			for (int i = 0; i < 4; i++) {
				System.out.print( (char) buff[red*4 + i] );
			}
			System.out.println();
			red++; 
		}
	}
	
	public static void main(String[] args) throws Exception {
		// Sadrzaj datoteke je abcdefgh12345678
        // Ucitavamo 2 fragmenta (bafera) duzine 8 bajta
		FileInputStream fis = new FileInputStream("d:/test_datoteka.txt");
        int ocitao;
        byte inBuff[] = new byte[8];
        
        // algoritmu saljemo dva bafera - abcdefgh i 12345678
        while ((ocitao = fis.read(inBuff)) != -1) {
            algoritam(inBuff);
        }
        fis.close();

	}

}
