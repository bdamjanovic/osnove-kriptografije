package xorKarakteri;
public class XorKarakteri {
	public static void main(String[] args) {
        // char tip podatka - donekle neprecizno, 
        // jer Java koristi UTF16 (nije uvijek 1 bajt)
        char[] otvoreniText = new char[] {'a', 'b', 'c'};
        char[] kljuc = new char[] {'Q', 'W', 'E'};
        int[] sifrat = new int[3];
//***************************************** sifrovanje
        String S = "";
        System.out.println("Otvoreni (P): " +  
               String.valueOf(otvoreniText));
        System.out.println("              XOR");
        System.out.println("Kljuc    (K): " +                       
               String.valueOf(kljuc));
        System.out.println("-----------------");
        for (int i=0; i<3; i++){
            sifrat[i] = (otvoreniText[i] ^ kljuc[i]);  
            S = S + (char)sifrat[i];
        }
        System.out.println("Sifrat   (C): " + S);           
//*************************************** desifrovanje
        System.out.println();
        System.out.println("Sifrat   (C): " + S);
        System.out.println("              XOR");
        System.out.println("Kljuc    (K): " +            
               String.valueOf(kljuc));
        System.out.println("-----------------");
        int[] ponovoOtvoreni = new int[3];
        S = "";
// desifrujemo ponovnom upotrebom XOR operacije sa istim kljucem
        for (byte i=0; i<3; i++){
            ponovoOtvoreni[i] = (sifrat[i] ^ kljuc[i]); 
             S = S + (char)ponovoOtvoreni[i];
        }
        System.out.println("Otvoreni (P): " + S);
        
        
	}

}
