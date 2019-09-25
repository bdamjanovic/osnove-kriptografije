package bCHexDecode;

import java.util.Arrays;
import org.bouncycastle.util.encoders.Hex; 

public class BCHexDecode {

	public static void main(String[] args) { 
		byte[] kljuc = Hex.decode("0102FF"); 
		System.out.println(Arrays.toString(kljuc));
	} 
}
 