package HesAlgoritmi;

import java.security.MessageDigest;
import java.security.Provider;
import java.security.Provider.Service;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;


public class HesAlgoritmi {


    private static final void showAlgorithms(Provider prov, Class<?> typeClass) {
        String type = typeClass.getSimpleName();

        List<Service> algoritmi = new ArrayList<>();

        Set<Service> services = prov.getServices();
        for (Service service : services) {
            if (service.getType().equalsIgnoreCase(type)) {
            	algoritmi.add(service);
            }
        }

        if (!algoritmi.isEmpty()) {
            System.out.printf(" --- Provajder %s, verzija %.2f --- %n", prov.getName(), prov.getVersion());
            for (Service service : algoritmi) {
                String algo = service.getAlgorithm();
                System.out.printf("Naziv algoritma: \"%s\"%n", algo);
            }
        }

    }
    
    public static void showAliases(Provider prov, Class<?> typeClass) {
        Set<Object> keys = prov.keySet();
        String type = typeClass.getSimpleName();
        System.out.printf(" --- Provajder %s, verzija %.2f --- %n", prov.getName(), prov.getVersion());
        for (Object key : keys) {
            final String prefix = "Alg.Alias." + type + ".";
            if (key.toString().startsWith(prefix)) {
                String value = prov.get(key.toString()).toString();
                System.out.printf("Alias: \"%s\" -> \"%s\"%n",
                        key.toString().substring(prefix.length()),
                        value);
            }
        }    	
    }

    public static void main(String[] args) {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            showAlgorithms(provider, MessageDigest.class);
        }
        
        /*
        System.out.println("----------------------------------");
        System.out.println("---------LISTA POTPISA------------");
        System.out.println("----------------------------------");
        for (Provider provider : providers) {
            showAlgorithms(provider, Signature.class);
        }    
        
        System.out.println("----------------------------------");
        System.out.println("-----LISTA ALIASA POTPISA---------");
        System.out.println("----------------------------------");    
        
        for (Provider provider : providers) {
            showAliases(provider, Signature.class);
        }
        */         
    }

}
