package xorBinarno;

public class XorBinarno {
	public static String uBinarno(int[] ch) {
		String rezultat = "";
		for (int i = 0; i < ch.length; i++) {
			rezultat = rezultat + String.format("%16s", 
					   Integer.toBinaryString(ch[i])).replace(' ', '0') + " "; 
		}
		return rezultat;
	}

	public static int[] sifrovanje(int[] otvoreniText, int[] kljuc, String S1, String S2) {
		int[] sifrat = new int[3];
		for (int i = 0; i < 3; i++)
			sifrat[i] = (otvoreniText[i] ^ kljuc[i]);
		return sifrat;
	}

	public static int[] desifrovanje(int[] sifrat, int[] kljuc, String S1, String S2) {
		int[] ponovoOtvoreni = new int[3];
		for (byte i = 0; i < 3; i++)
			ponovoOtvoreni[i] = (sifrat[i] ^ kljuc[i]);
		return ponovoOtvoreni; 
	}

	public static void main(String[] args) {
		int[] otvoreniText = new int[] { 'a', 'b', 'c' };
		int[] kljuc = new int[] { 'Q', 'W', 'E' };
		int[] sifrat = new int[3];
		int[] ponovoOtvoreni = new int[3];
		String S1 = "", S2 = "";
		// sifrovanje i desifrovanje
		sifrat = sifrovanje(otvoreniText, kljuc, S1, S2);
		ponovoOtvoreni = desifrovanje(sifrat, kljuc, S1, S2);
		// ispis
		System.out.println("Otvoreni (P): " + java.util.Arrays.toString(otvoreniText) + 
				           " " + uBinarno(otvoreniText));

		System.out.println("              XOR");
		System.out.println("Kljuc    (K): " + java.util.Arrays.toString(kljuc) + 
				           " " + uBinarno(kljuc));
		System.out.println("-----------------");
		for (int i = 0; i < 3; i++) {
			S1 = S1 + (char) sifrat[i];
		}
		System.out.println("Sifrat   (C): " + S1);
		System.out.println("Sifrat   (C): " + java.util.Arrays.toString(sifrat) + 
				" " + S2 + " " + uBinarno(sifrat) );
		System.out.println();
		System.out.println("Sifrat   (C): " + java.util.Arrays.toString(sifrat) + 
				" " + S2 + " " + uBinarno(sifrat));
		System.out.println("              XOR");
		System.out.println("Kljuc    (K): " + java.util.Arrays.toString(kljuc) + 
				" " + uBinarno(kljuc));
		System.out.println("-----------------");
		S1 = "";
		S2 = "";
		for (byte i = 0; i < 3; i++) {
			S1 = S1 + (char) ponovoOtvoreni[i];
		}
		System.out.println("Otvoreni (P): " + S1 + " " + S2 + 
				" " + uBinarno(ponovoOtvoreni));
	}
}
