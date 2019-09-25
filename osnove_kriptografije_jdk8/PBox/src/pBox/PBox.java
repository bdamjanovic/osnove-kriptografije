package pBox;

public class PBox {
	public static String doEncrypt(String s) {
		byte p[] = new byte[8];
		byte pTemp[] = new byte[8];
		p = s.getBytes();
		pTemp = s.getBytes();
		p[0] = pTemp[2];
		p[1] = pTemp[4];
		p[2] = pTemp[5];
		p[3] = pTemp[0];
		p[4] = pTemp[6];
		p[5] = pTemp[7];
		p[6] = pTemp[1];
		p[7] = pTemp[3];

		return (new String(p));
	}

	public static String doDecrypt(String s) {
		byte p[] = s.getBytes();
		byte pTemp[] = s.getBytes();
		p[0] = pTemp[3];
		p[1] = pTemp[6];
		p[2] = pTemp[0];
		p[3] = pTemp[7];
		p[4] = pTemp[1];
		p[5] = pTemp[2];
		p[6] = pTemp[4];
		p[7] = pTemp[5];

		return (new String(p));
	}

	public static void main(String[] args) {
		// string od 8 znakova
		String s = "abcdefgh";
		s = doDecrypt(s);
		System.out.println(s);
		s = doEncrypt(s);
		System.out.println(s);
	}

}
