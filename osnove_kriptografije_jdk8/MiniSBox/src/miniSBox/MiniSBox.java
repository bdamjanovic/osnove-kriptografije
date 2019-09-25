package miniSBox;
/*  Konstruisati mini S-Box (sa inverznim S-Boxom) od samo 30 elementa
 *  kojim mozemo izvrsiti supstituciju brojeva (0..29)
 *  Iskoristiti mastu!
 *
 */ 
public class MiniSBox {

	public static void main(String[] args) {
		int sb[] = new int[30];
		int isb[] = new int[30];
		int delta = 2;
		for (int i = 0; i < 30; i++) {
			sb[i] = (i + delta) % 30;
			isb[(i + delta) % 30] = i;
		}
		System.out.println("SBox");
		for (int i = 0; i < 30; i++)
			System.out.print(sb[i] + ", ");
		System.out.println();
		System.out.println("Inverzni SBox");
		for (int i = 0; i < 30; i++)
			System.out.print(isb[i] + ", ");
		System.out.println();

		/* kontrola rada */
		int plain = 10;
		System.out.println("Otvoreni " + plain);
		int cip = sb[plain];
		System.out.println("Sifrat " + cip);
		int plainAgain = isb[cip];
		System.out.println("Ponovo otvoreni " + plainAgain);
	}

}
