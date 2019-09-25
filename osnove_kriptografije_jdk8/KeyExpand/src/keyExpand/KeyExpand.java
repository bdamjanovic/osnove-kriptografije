package keyExpand;

public class KeyExpand {
public static void main(String[] args) {
	byte[] inicijalni_kljuc = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 
			10, 11, 12, 13, 14, (byte) 255 };
	byte[] prosireni_kljuc = new byte[48];
	// prvih 16 bajta su isti
	for (int i = 0; i < 16; i++)
		prosireni_kljuc[i] = inicijalni_kljuc[i];

	for (int i = 16; i < 48; i++)
		prosireni_kljuc[i] = (byte) ((prosireni_kljuc[i - 16] + 1) % 256);

	for (int i = 0; i < 48; i++)
		System.out.println(prosireni_kljuc[i]);
}

} 
