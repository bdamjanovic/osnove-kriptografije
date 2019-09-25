package datatypeConvertor;
import javax.xml.bind.DatatypeConverter;
public class DatatypeConvertor {
public static void main(String[] args) throws Exception {
       byte[] otvoreni = DatatypeConverter.parseHexBinary(
       "54686520526f6c6c696e672053746f6e6573202d204c6f7665204973205374726f6e67");
       System.out.println(new String(otvoreni, "UTF-8"));
}
}
