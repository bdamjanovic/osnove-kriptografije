package showHashAndSignAlgorithms;

import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.security.Provider.Service;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

import javax.crypto.KeyAgreement;

public class ShowHashAndSignAlgorithms {
    private static final void showHashAlgorithms(Provider prov, Class<?> typeClass) {
        String type = typeClass.getSimpleName();
        List<Service> algorithms = new ArrayList<>();
        Set<Service> services = prov.getServices();
        for (Service service : services) {
            if (service.getType().equalsIgnoreCase(type)) {
            	algorithms.add(service);
            }
        }
        if (!algorithms.isEmpty()) {
            System.out.printf(" --- Provajder %s, Verzija %.2f --- %n", prov.getName(), prov.getVersion());
            for (Service service : algorithms) {
                String algo = service.getAlgorithm();
                System.out.printf("Algorithm name: \"%s\"%n", algo);

            }
        }

    }
    
    
    public static void main(String[] args) {
        System.out.println("----------------------------------------------------------");
        System.out.println("Hes funkcije:");
        System.out.println("----------------------------------------------------------");
        Provider[] providers = Security.getProviders();
        //for (Provider provider : providers) {
        //    showHashAlgorithms(provider, MessageDigest.class);
        //}
        System.out.println("----------------------------------------------------------");
        System.out.println("Digitalni potpisi:");
        System.out.println("----------------------------------------------------------");
        //for (Provider provider : providers) {
        //    showHashAlgorithms(provider, Signature.class);
        //}    
        
        
        System.out.println("----------------------------------------------------------");
        System.out.println("KeyPairGenerator potpisi:");
        System.out.println("----------------------------------------------------------");
        for (Provider provider : providers) {
            showHashAlgorithms(provider, KeyAgreement.class);
        }          
    }

}
