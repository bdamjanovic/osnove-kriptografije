package xorBrojevi;
public class XorInteger {
	public static void main(String[] args) {
        // varijable (u ovom primjeru, koristimo int i String)
        int[] otvoreniText = new int[] {'a', 'b', 'c'};
        int[] kljuc = new int[] {'Q', 'W', 'E'};
        int[] sifrat = new int[3];
        int[] ponovoOtvoreni = new int[3];
        String S = "";
        //*********************************** sifrovanje
        for (int i=0; i<3; i++){
            sifrat[i] = (otvoreniText[i] ^ kljuc[i]);  
            S = S + (char)sifrat[i];                  
        }
        System.out.println("Sifrat   (C): " + S);
        //************************************ desifrovanje
        S = "";
//desifrujemo ponovnom upotrebom XOR operacije, pomocu istog kljuca
        for (byte i=0; i<3; i++){
            ponovoOtvoreni[i] = (sifrat[i] ^ kljuc[i]); 
             S = S + (char)ponovoOtvoreni[i];
        }
        System.out.println("Otvoreni (P): " + S);
	}
}
