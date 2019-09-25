/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package hexencoder;

import java.util.Arrays;

/**
 *
 * @author dbori
 */
public class HexEncoder {

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
        StringBuffer string = new StringBuffer();
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
     * Za ulazni string "s" predstavljen kao hex broj, vraca niz bajta. Npr.
     * string "191a1f" rastavlja na hex brojeve od po dvije cifre, 19 1a 1f i
     * smjesta u niz od 3 bajta.
     *
     * @param s String koji treba pretvoriti.
     * @return niz bajta (byte[]).
     */
    public static byte[] hexStrToByteArrSTARI(String s) throws Exception {
        if ( (s.length() % 2) != 0 )
            throw new Exception();
        String hex = "";
        int len = s.length() / 2;
        byte[] raw = new byte[len];
        for (int i = 0; i < len; i++) {
            int prvaCifra = Integer.parseInt( Character.toString(s.charAt(2 * i)), 16);
            int drugaCifra = Integer.parseInt( Character.toString(s.charAt(2 * i + 1)), 16);
            raw[i] =  (byte) ((prvaCifra << 4) + drugaCifra);
        }
        return raw;
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
        String hex = "";
        int len = s.length() / 2;
        byte[] raw = new byte[len];
        for (int i = 0; i < len; i++) {
            int prvaCifra = konvertujUCifru(s.charAt(2 * i));
            int drugaCifra = konvertujUCifru(s.charAt(2 * i + 1));
            raw[i] =  (byte) ((prvaCifra << 4) + drugaCifra);
        }
        return raw;
    }
    public static int konvertujUCifru(char hexChar) {
        int digit = Character.digit(hexChar, 16);
        if(digit == -1) {
            throw new IllegalArgumentException(
              "Invalid Hexadecimal Character: "+ hexChar);
        }
        return digit;
    }    
    
    
    /**
     * @param args the command line arguments
     */
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
