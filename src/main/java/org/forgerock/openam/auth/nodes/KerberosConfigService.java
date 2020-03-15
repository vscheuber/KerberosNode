package org.forgerock.openam.auth.nodes;

import java.util.Map;
import java.util.TreeMap;

import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.annotations.sm.Config;

import com.iplanet.am.util.SystemProperties;
import com.sun.identity.sm.RequiredValueValidator;

/**
 * Configuration for the node.
 */
@Config(scope = Config.Scope.GLOBAL)
public interface KerberosConfigService {
	
	final static String KRB5_CONF_FILE = SystemProperties.get(SystemProperties.CONFIG_PATH) + "/krb5.conf";
	
    /**
     * Maps service principal names to key tab file names.
     */
    @Attribute(order = 100, validators = {RequiredValueValidator.class})
    default boolean useKrb5Config() { return false; }
	
    /**
     * Settings used by the Kerberos V5 library
     */
    @Attribute(order = 200)
    default Map<String, String> libdefaults() { return new TreeMap<String, String>(); }
	
    /**
     * Realm-specific contact information and settings
     * 
     * Each tag in the [realms] section of the file is the name of a Kerberos 
     * realm. The value of the tag is a subsection with relations that define 
     * the properties of that particular realm.
     */
    @Attribute(order = 300)
    default Map<String, String> realms() { return new TreeMap<String, String>(); }
	
    /**
     * Maps server hostnames and Active Directory domains to Kerberos realms
     * 
     * The [domain_realm] section provides a translation from a domain name or 
     * hostname to a Kerberos realm name. The tag name can be a host name or 
     * domain name, where domain names are indicated by a prefix of a period 
     * (.). The value of the relation is the Kerberos realm name for that 
     * particular host or domain. A host name relation implicitly provides 
     * the corresponding domain name relation, unless an explicit domain name 
     * relation is provided. The Kerberos realm may be identified either in 
     * the realms section or using DNS SRV records. Host names and domain 
     * names should be in lower case.
     */
    @Attribute(order = 400)
    default Map<String, String> domain_realm() { return new TreeMap<String, String>(); }
	
    /**
     * Authentication paths for non-hierarchical cross-realm
     * 
     * In order to perform direct (non-hierarchical) cross-realm 
     * authentication, configuration is needed to determine the authentication 
     * paths between realms.
     * 
     * A client will use this section to find the authentication path between 
     * its realm and the realm of the server. The server will use this section 
     * to verify the authentication path used by the client, by checking the 
     * transited field of the received ticket.
     * 
     * There is a tag for each participating client realm, and each tag has 
     * subtags for each of the server realms. The value of the subtags is an 
     * intermediate realm which may participate in the cross-realm 
     * authentication. The subtags may be repeated if there is more then one 
     * intermediate realm. A value of ”.” means that the two realms share keys 
     * directly, and no intermediate realms should be allowed to participate.
     * 
     * Only those entries which will be needed on the client or the server need 
     * to be present. A client needs a tag for its local realm with subtags for 
     * all the realms of servers it will need to authenticate to. A server 
     * needs a tag for each realm of the clients it will serve, with a subtag 
     * of the server realm.
     */
    @Attribute(order = 500)
    default Map<String, String> capaths() { return new TreeMap<String, String>(); }
    
}
