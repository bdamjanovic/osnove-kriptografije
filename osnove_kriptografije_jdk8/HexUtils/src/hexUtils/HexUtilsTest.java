package hexUtils;

import java.util.Arrays;

public class HexUtilsTest {
private static String cifre = "0123456789abcdef";

/** -----------------------------------------------------------------------
 * Test verzija, sa ispisom i objasnjenjima
 * Za ulazni niz bajta "nizBajta" duzine "duzina", vraca string u heksadekadnoj notaciji.
 *
 * @param nizBajta podaci koje treba pretvoriti.
 * @param duzina broj bajta u bloku koji treba pretvoriti.
 * @return String koji predstavlja podatke u heksadekadnoj notaciji.
 */
public static String byteArrToHexStrTest(byte[] nizBajta, int duzina) {
    StringBuffer string = new StringBuffer();
    for (int i = 0; i != duzina; i++) {
        // Jedna heksadekadna cifra je sekvenca od 4 bita (nibble), a dvije cine jedan bajt.
        // Za pretvaranje u heksadekadni brojni sistem, 
        // svaki bajt niza treba da sadrzi vrijednosti od 0 do 255.
        // Tip byte u prog.jeziku Java uzima vrijednosti od -128 do 127
        // pa nije dovoljno da ga pretvorimo u int, jer ce npr. negativan broj 
        // -127 binarno biti predstavljen kao 11111111111111111111111110000001, 
        // a potreban nam je niz bita 00000000000000000000000010000001 
        // odnosno 10000001, ili broj 129
        int v = nizBajta[i];
        System.out.println(Integer.toBinaryString(v) + " " + v);
        v = nizBajta[i] & 0xff;
        System.out.println(Integer.toBinaryString(v) + " " + v);
        
        string.append(cifre.charAt(v >> 4));
        string.append(cifre.charAt(v & 0xf));
    }
    return string.toString();
}

/** -----------------------------------------------------------------------
 * Za ulazni niz bajta "nizBajta" duzine "duzina", vraca string u heksadekadnoj notaciji.
 *
 * @param nizBajta podaci koje treba pretvoriti.
 * @param duzina broj bajta u bloku koji treba pretvoriti.
 * @return String koji predstavlja podatke u heksadekadnoj notaciji.
 */
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

/**
 * Za ulazni niz bajta "nizBajta" vraca string u heksadekadnoj notaciji.
 * Racuna duzinu, pa poziva ranije definisanu metodu toHex(byte[] nizBajta, int duzina) 
 * @param nizBajta podaci koje treba pretvoriti.
 * @return String koji predstavlja podatke u heksadekadnoj notaciji.
 */
public static String byteArrToHexStr(byte[] nizBajta) {
    int duzina = nizBajta.length;
    return byteArrToHexStr(nizBajta, duzina);
}

/** -----------------------------------------------------------------------
 * Za ulazni string "s", vraca niz bajta.
 *
 * @param s String koje treba pretvoriti.
 * @return niz bajta (byte[]).
 */
public static byte[] strToByteArr(String s) {
    return s.getBytes();
}

/** -----------------------------------------------------------------------
 * Za ulazni string "s" predstavljen kao heksadekadni broj, vraca niz bajta. Npr.
 * string "E9CA0F" rastavlja na heksadekadne brojeve od po dvije cifre, E9 CA 0F i
 * smjesta u niz od 3 bajta.
 *
 * @param s String koji treba pretvoriti.
 * @return niz bajta (byte[]).
 */
public static byte[] hexStrToByteArr(String s) throws Exception {
    if ( (s.length() % 2) != 0 )
        throw new Exception();
    int len = s.length() / 2;
    byte[] niz = new byte[len];
    for (int i = 0; i < len; i++) {
        int prvaCifra = konvertujHuI(s.charAt(2 * i));
        int drugaCifra = konvertujHuI(s.charAt(2 * i + 1));
        niz[i] =  (byte) ((prvaCifra << 4) + drugaCifra);
    }
    return niz;
}
/** -----------------------------------------------------------------------
 * Pomocna funkcija koja provjerava da li je heksadekadna cifra (karakter char) ispravna.
 * pa konvertuje heksadekadnu cifru u integer (H u I).
 *
 * @param hexChar char koji treba pretvoriti.
 * @return int cifra tipa integer.
 */
private static int konvertujHuI(char hexChar) {
    int cifra = Character.digit(hexChar, 16);
    if(cifra == -1) {
        throw new IllegalArgumentException(
          "Neispravan heksadekadni karakter: "+ hexChar);
    }
    return cifra;
}    



public static void main(String[] args) throws Exception {
    System.out.println("------ Test verzija byteArrToHexStrTest ------ ");
    byte[] nizBajta = {-127, -128, 1, };
    String s = byteArrToHexStrTest(nizBajta, nizBajta.length);
    System.out.println("Rezultat:");
    System.out.println(s);
    
    System.out.println("------ Produkcija byteArrToHexStr ------ ");
    s = byteArrToHexStr(nizBajta);
    System.out.println(s);
    
    System.out.println("------ Bilo koji string u niz bajta ------ ");
    byte[] rezultat1 = strToByteArr("abcčć");
    System.out.println(Arrays.toString(rezultat1));
    
    System.out.println("------ Heksadekadni string u niz bajta ------ ");
    byte[] rezultat2 = hexStrToByteArr("E9CA0F");
    System.out.println(Arrays.toString(rezultat2));

}

}
