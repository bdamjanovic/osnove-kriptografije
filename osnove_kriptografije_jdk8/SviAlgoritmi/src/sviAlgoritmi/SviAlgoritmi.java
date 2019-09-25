package sviAlgoritmi;
import java.security.Provider;
import java.security.Security;

public class SviAlgoritmi {

	public static void main(String[] args) {
        try {
            for (Provider provider : Security.getProviders()) {
                System.out.println(provider.getName());
                for (String key : provider.stringPropertyNames()) {
                        System.out.println("\t" + key + "\t" + 
                               provider.getProperty(key));
                }
            }
        } catch (Exception e) {
            System.out.println(e);
        }
	}

}
