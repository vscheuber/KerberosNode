package org.forgerock.openam.auth.nodes;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;
import java.util.Arrays;
import java.util.Iterator;
import java.util.List;

import javax.security.auth.Subject;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import javax.servlet.http.HttpServletRequest;

import org.forgerock.http.util.Json;
import org.forgerock.json.JsonValue;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.SharedStateConstants;
import org.forgerock.openam.auth.nodes.KerberosNode.Config;
import org.forgerock.openam.core.realms.Realm;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.GSSName;
import org.slf4j.Logger;

import com.sun.identity.authentication.spi.HttpCallback;
import com.sun.identity.authentication.util.DerValue;
import com.sun.identity.idm.AMIdentity;
import com.sun.identity.idm.IdUtils;
import com.sun.identity.shared.encode.Base64;

public class KerberosUtils {
	
    private static final String REALM_SEPARATOR = "@";
    public static final String NEGOTIATE = "Negotiate";
    public static final String AUTHORIZATION = "Authorization";
    private final static byte[] spnegoOID = {
            (byte) 0x06, (byte) 0x06, (byte) 0x2b, (byte) 0x06, (byte) 0x01,
            (byte) 0x05, (byte) 0x05, (byte) 0x02};
    private final static byte[] KERBEROS_V5_OID = {
            (byte) 0x06, (byte) 0x09, (byte) 0x2a, (byte) 0x86, (byte) 0x48,
            (byte) 0x86, (byte) 0xf7, (byte) 0x12, (byte) 0x01, (byte) 0x02,
            (byte) 0x02};
    private static final String FAILURE_ATTRIBUTE = "failure";
    private static final String REASON_ATTRIBUTE = "reason";
	
    private final Logger logger;
    private final Config config;
    private KerberosConfigService serviceConfig;
    private final Realm realm;
	
	public KerberosUtils(Config config, KerberosConfigService serviceConfig, Realm realm, Logger logger) {
		this.config = config;
		this.serviceConfig = serviceConfig;
		this.logger = logger;
		this.realm = realm;
	}

    public JsonValue authenticateToken(final byte[] kerberosToken, JsonValue sharedState)
            throws PrivilegedActionException, NodeProcessException {
        Iterator<String> principals = config.principalKeytab().keySet().iterator();
        while (principals.hasNext()) {
			String principal = (String) principals.next();
			String keytabFileName = config.principalKeytab().get(principal);
	    	Subject serviceSubject;
			try {
				serviceSubject = serviceLogin(principal, keytabFileName);
		        return Subject.doAs(serviceSubject, (PrivilegedExceptionAction<JsonValue>) () -> {
		            GSSContext context = GSSManager.getInstance().createContext((GSSCredential) null);
		            logger.debug("Context created.");
		            byte[] outToken = context.acceptSecContext(kerberosToken, 0, kerberosToken.length);
		
		            if (outToken != null) {
		                if (logger.isDebugEnabled()) {
		                    logger.debug("Token returned from acceptSecContext: \n" +
		                                         DerValue.printByteArray(outToken, 0, outToken.length));
		                }
		            }
		
		            if (!context.isEstablished()) {
		                throw new NodeProcessException("Cannot establish context !");
		            } else {
		                logger.debug("Context established !");
		                GSSName user = context.getSrcName();
		                final String userPrincipalName = user.toString();
		
		                // If the whitelist is empty, do not enforce it. This prevents issues with upgrading, and is the
		                // expected default behaviour.
		                if (!config.trustedKerberosRealms().isEmpty()) {
		                    boolean foundTrustedRealm = false;
		                    for (final String trustedRealm : config.trustedKerberosRealms()) {
		                        if (isTokenTrusted(userPrincipalName, trustedRealm)) {
		                            foundTrustedRealm = true;
		                            break;
		                        }
		                    }
		                    if (!foundTrustedRealm) {
		                        throw new NodeProcessException("Kerberos token for " + userPrincipalName + " not trusted");
		                    }
		                }
		                // Check if the user account from the Kerberos ticket exists in the realm.
		                String userValue = getUserName(userPrincipalName);
		                if (config.lookupUserInRealm()) {
		                    AMIdentity identity = IdUtils.getIdentity(userValue, realm);
		                    if (identity == null || !identity.isExists() || !identity.isActive()) {
		                        throw new NodeProcessException(
		                                "KerberosNode.authenticateToken: " + ": Unable to find the user " + userValue +
		                                        " in org " + realm.toString());
		                    }
		                }
		                logger.debug("KerberosNode.authenticateToken:" + "User authenticated: " + user.toString());
		                sharedState.put(SharedStateConstants.USERNAME, userValue);
		            }
		            context.dispose();
		            return sharedState;
		        });
			} catch (LoginException e) {
				logger.error("Unable to login service principal \"{}\" and keytab \"{}\"", principal, keytabFileName, e);
			}
        }
        return sharedState;
    }

    /**
     * Checks the request for an attribute "http-auth-failed".
     *
     * @param request THe HttpServletRequest.
     * @return If the attribute is present and set to true, true is returned, otherwise false is returned.
     */
    public boolean hasKerberosLoginFailed(HttpServletRequest request) throws NodeProcessException {
        try {
            JsonValue jsonBody = JsonValue.json(Json.readJson(request.getParameter("jsonContent")));
            return jsonBody.isDefined(FAILURE_ATTRIBUTE) && jsonBody.isDefined(REASON_ATTRIBUTE) &&
                    jsonBody.get(FAILURE_ATTRIBUTE).asBoolean().equals(true) &&
                    jsonBody.get(REASON_ATTRIBUTE).asString().equals("http-auth-failed");
        } catch (IOException e) {
            throw new NodeProcessException(e);
        }
    }

    public byte[] getSPNEGOTokenFromHTTPRequest(HttpServletRequest req) {
        byte[] spnegoToken = null;
        String header = req.getHeader(AUTHORIZATION);
        if ((header != null) && header.startsWith(NEGOTIATE)) {
            header = header.substring(NEGOTIATE.length()).trim();
            spnegoToken = Base64.decode(header);
        }
        return spnegoToken;
    }

    public byte[] getSPNEGOTokenFromCallback(List<HttpCallback> callbacks) {
        byte[] spnegoToken = null;
        if (callbacks != null && callbacks.size() != 0) {
            String spnegoTokenStr = callbacks.get(0).getAuthorization();
            spnegoToken = Base64.decode(spnegoTokenStr);
        }

        return spnegoToken;
    }

    public byte[] parseToken(byte[] rawToken) {
        byte[] token = rawToken;
        DerValue tmpToken = new DerValue(rawToken);
        if (logger.isDebugEnabled()) {
            logger.debug("token tag: {}", DerValue.printByte(tmpToken.getTag()));
        }
        if (tmpToken.getTag() != (byte) 0x60) {
            return null;
        }

        ByteArrayInputStream tmpInput = new ByteArrayInputStream(tmpToken.getData());

        // check for SPNEGO OID
        byte[] oidArray = new byte[spnegoOID.length];
        tmpInput.read(oidArray, 0, oidArray.length);
        if (Arrays.equals(oidArray, spnegoOID)) {
            logger.debug("SPNEGO OID found in the Auth Token");
            tmpToken = new DerValue(tmpInput);

            // 0xa0 indicates an init token(NegTokenInit); 0xa1 indicates an
            // response arg token(NegTokenTarg). no arg token is needed for us.

            if (tmpToken.getTag() == (byte) 0xa0) {
                logger.debug("DerValue: found init token");
                tmpToken = new DerValue(tmpToken.getData());
                if (tmpToken.getTag() == (byte) 0x30) {
                    logger.debug("DerValue: 0x30 constructed token found");
                    tmpInput = new ByteArrayInputStream(tmpToken.getData());
                    tmpToken = new DerValue(tmpInput);

                    // In an init token, it can contain 4 optional arguments:
                    // a0: mechTypes
                    // a1: contextFlags
                    // a2: octect string(with leading char 0x04) for the token
                    // a3: message integrity value

                    while (tmpToken.getTag() != (byte) -1 &&
                            tmpToken.getTag() != (byte) 0xa2) {
                        // look for next mech token DER
                        tmpToken = new DerValue(tmpInput);
                    }
                    if (tmpToken.getTag() != (byte) -1) {
                        // retrieve octet string
                        tmpToken = new DerValue(tmpToken.getData());
                        token = tmpToken.getData();
                    }
                }
            }
        } else {
            logger.debug("SPNEGO OID not found in the Auth Token");
            byte[] krb5Oid = new byte[KERBEROS_V5_OID.length];
            int i = 0;
            for (; i < oidArray.length; i++) {
                krb5Oid[i] = oidArray[i];
            }
            tmpInput.read(krb5Oid, i, krb5Oid.length - i);
            if (!Arrays.equals(krb5Oid, KERBEROS_V5_OID)) {
                logger.debug("Kerberos V5 OID not found in the Auth Token");
                token = null;
            } else {
                logger.debug("Kerberos V5 OID found in the Auth Token");
            }
        }
        return token;
    }

    private String getUserName(String user) {
        String userName = user;
        if (!config.returnPrincipalWithDomainName()) {
            int index = user.indexOf(REALM_SEPARATOR);
            if (index != -1) {
                userName = user.substring(0, index);
            }
        }
        return userName;
    }

    public Subject serviceLogin(String principalName, String keytabFileName) throws LoginException {
        logger.debug("New Service Login ...");
		if (serviceConfig.useKrb5Config()) {
			logger.debug("Using external krb5.conf file.");
			System.clearProperty("java.security.krb5.conf");
	        logger.debug("java.security.krb5.conf="+null==System.getProperty("java.security.krb5.conf")?"UNDEFINED":System.getProperty("java.security.krb5.conf"));
		}
		else {
			logger.debug("Using service configuration values.");
	        System.setProperty("java.security.krb5.conf", KerberosConfigService.KRB5_CONF_FILE);
	        logger.debug("java.security.krb5.conf="+KerberosConfigService.KRB5_CONF_FILE);
		}
        KerberosConfig kc = new KerberosConfig(Configuration.getConfiguration());
        kc.setRefreshConfig("true");
        kc.setPrincipalName(principalName);
        kc.setKeyTab(keytabFileName);
        kc.setIsInitiator(config.kerberosServiceIsInitiator());

        LoginContext lc;
        // perform service authentication using JDK Kerberos module
        lc = new LoginContext(KerberosConfig.defaultAppName, null, null, kc);
        lc.login();
        Subject serviceSubject = lc.getSubject();
        logger.debug("Service login succeeded.");
        return serviceSubject;
    }


    /**
     * Iterate until we extract the real exception
     * from PrivilegedActionException(s).
     */
    public Exception extractException(Exception e) {
        while (e instanceof PrivilegedActionException) {
            e = ((PrivilegedActionException) e).getException();
        }
        return e;
    }

    private boolean isTokenTrusted(final String UPN, final String realm) {
        boolean trusted = false;
        if (UPN != null) {
            final int param_index = UPN.indexOf(REALM_SEPARATOR);
            if (param_index != -1) {
                final String realmPart = UPN.substring(param_index + 1);
                if (realmPart.equalsIgnoreCase(realm)) {
                    trusted = true;
                }
            }
        }
        return trusted;
    }
}