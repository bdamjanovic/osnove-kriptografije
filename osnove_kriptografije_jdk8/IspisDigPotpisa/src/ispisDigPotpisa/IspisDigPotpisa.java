package ispisDigPotpisa;

import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

public class IspisDigPotpisa {


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
            System.out.printf(" --- Provajder %s, verzija %.2f --- %n", 
            		prov.getName(), prov.getVersion());
            for (Service service : algoritmi) {
                String algo = service.getAlgorithm();
                System.out.printf("Naziv algoritma: \"%s\"%n", algo);
            }
        }

    }

    public static void main(String[] args) {
        Provider[] providers = Security.getProviders();
        for (Provider provider : providers) {
            showAlgorithms(provider, Signature.class);
        }    
    }

}
