package simetricniBlokovskiXor;

public class SimetricniBlokovskiXor {
	public static void sifruj(int[] otvoreniText, int[] kljuc, int sifrat[], int pozicija) {
		for (int i = 0; i < 3; i++)
			sifrat[i + pozicija] = otvoreniText[i + pozicija] ^ kljuc[i];
// sifrujemo XOR operacijom
	}

	public static void desifruj(int[] sifrat, int[] kljuc, int[] desifrovani, int pozicija) {
		for (int i = 0; i < 3; i++)
			desifrovani[i + pozicija] = sifrat[i + pozicija] ^ kljuc[i];
// desifrujemo
	}

	public static void main(String[] args) {
		// u memoriji npr. 97, 98, 99, 100, 101, 102
		int[] otvoreniText = new int[] { 'a', 'b', 'c', 'd', 'e', 'f' };
		int[] kljuc = new int[] { 'Q', 'W', 'E' };
		int[] sifrat = new int[6];
		int[] desifrovani = new int[6];
		int pozicija = 0;

// ** sifrujemo prvi blok podataka
		sifruj(otvoreniText, kljuc, sifrat, pozicija);
// ** sifrujemo drugi blok podataka
		pozicija = pozicija + 3;
		sifruj(otvoreniText, kljuc, sifrat, pozicija);

// ispis
		String ispis = "";
		for (int i = 0; i < 6; i++)
			ispis = ispis + (char) sifrat[i];
		System.out.println("Sifrovano: " + ispis);

// desifrovanje
		pozicija = 0;
// ** desifrujemo prvi blok podataka
		desifruj(sifrat, kljuc, desifrovani, pozicija);
// ** desifrujemo drugi blok podataka
		pozicija = pozicija + 3;
		desifruj(sifrat, kljuc, desifrovani, pozicija);
		ispis = "";
		for (int i = 0; i < 6; i++)
			ispis = ispis + (char) desifrovani[i];
		System.out.println("desifrovano: " + ispis);

	}

}
