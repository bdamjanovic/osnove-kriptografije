package ispisAliasaDigPotpisa;

import java.security.Provider;
import java.security.Security;
import java.security.Signature;
import java.util.Set;

public class IspisAliasaDigPotpisa {
	
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
            showAliases(provider, Signature.class);
        }

	}

}
