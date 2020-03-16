/*
 * The contents of this file are subject to the terms of the Common Development and
 * Distribution License (the License). You may not use this file except in compliance with the
 * License.
 *
 * You can obtain a copy of the License at legal/CDDLv1.0.txt. See the License for the
 * specific language governing permission and limitations under the License.
 *
 * When distributing Covered Software, include this CDDL Header Notice in each file and include
 * the License file at legal/CDDLv1.0.txt. If applicable, add the following below the CDDL
 * Header, with the fields enclosed by brackets [] replaced by your own identifying
 * information: "Portions copyright [year] [name of copyright owner]".
 *
 * Copyright 2017-2018 ForgeRock AS.
 */


package org.forgerock.openam.auth.nodes;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PrivilegedActionException;
import java.util.Iterator;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.TreeMap;

import javax.inject.Inject;
import javax.servlet.http.HttpServletRequest;

import org.forgerock.json.JsonValue;
import org.forgerock.openam.annotations.sm.Attribute;
import org.forgerock.openam.auth.node.api.AbstractDecisionNode;
import org.forgerock.openam.auth.node.api.Action;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.auth.node.api.NodeProcessException;
import org.forgerock.openam.auth.node.api.TreeContext;
import org.forgerock.openam.core.realms.Realm;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.assistedinject.Assisted;
import com.iplanet.sso.SSOException;
import com.sun.identity.authentication.spi.HttpCallback;
import com.sun.identity.authentication.util.DerValue;
import com.sun.identity.sm.SMSException;

/**
 * Windows Desktop SSO Node
 */
@Node.Metadata(outcomeProvider = AbstractDecisionNode.OutcomeProvider.class,
        configClass = KerberosNode.Config.class)
public class KerberosNode extends AbstractDecisionNode {

    private final Logger logger = LoggerFactory.getLogger("amAuth");
    private final Config config;
    private KerberosConfigService serviceConfig;
    private final AnnotatedServiceRegistry serviceRegistry;
    private final KerberosUtils ku;

    /**
     * Configuration for the node.
     */
    public interface Config {
    	
        /**
         * Map service principals to keytab file names.
         */
        @Attribute(order = 100)
        default Map<String, String> principalKeytab() { return new TreeMap<String, String>(); }
    	
        /**
         * List of Trusted Kerberos Realms for User Kerberos tickets.
         */
        @Attribute(order = 200)
        Set<String> trustedKerberosRealms();

        /**
         * Return the fully qualified name of the authenticated user rather than just the username.
         */
        @Attribute(order = 300)
        default boolean returnPrincipalWithDomainName() {
            return false;
        }

        /**
         * Validate that the user has a matched user profile configured in the data store.
         */
        @Attribute(order = 400)
        default boolean lookupUserInRealm() {
            return false;
        }

        /**
         * True, if initiator. False, if acceptor only. Default is True.
         */
        @Attribute(order = 500)
        default boolean kerberosServiceIsInitiator() {
            return true;
        }
    }

    /**
     * Create the node using Guice injection. Just-in-time bindings can be used to obtain instances of other classes
     * from the plugin.
     *
     * @param config The service config.
     * @param realm  The realm the node is in.
     */
    @Inject
    public KerberosNode(@Assisted Config config, @Assisted Realm realm, AnnotatedServiceRegistry serviceRegistry) {
        this.config = config;
        this.serviceRegistry = serviceRegistry;

		try {
			logger.info("Loading service configuration...");
			serviceConfig = this.serviceRegistry.getGlobalSingleton(KerberosConfigService.class);
		} catch (SSOException | SMSException e) {
			logger.error("Couldn't load service configuration", e);
		}
		
		ku = new KerberosUtils(config, serviceConfig, realm, logger);
    }

    @Override
    public Action process(TreeContext context) throws NodeProcessException {

        HttpServletRequest request = context.request.servletRequest;
        if (request != null && ku.hasKerberosLoginFailed(request)) {
            logger.debug("Http Auth Failed");
            return goTo(false).build();
        }

        if (!context.getCallback(HttpCallback.class).isPresent()) {
            return Action.send(new HttpCallback(KerberosUtils.AUTHORIZATION, "WWW-Authenticate", KerberosUtils.NEGOTIATE, 401)).build();
        }

        // Check to see if the Rest Auth Endpoint has signified that IWA has failed.
        validateConfigParameters();

        byte[] spnegoToken = ku.getSPNEGOTokenFromHTTPRequest(Objects.requireNonNull(request));
        if (spnegoToken == null) {
            spnegoToken = ku.getSPNEGOTokenFromCallback(context.getCallbacks(HttpCallback.class));
        }

        if (spnegoToken == null) {
            logger.error("SPNEGO token is not valid.");
            return goTo(false).build();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("SPNEGO token: \n{}", DerValue.printByteArray(spnegoToken, 0, spnegoToken.length));
        }
        
        final byte[] kerberosToken = ku.parseToken(spnegoToken);

        if (kerberosToken == null) {
            logger.error("Kerberos token is not valid.");
            return goTo(false).build();
        }

        if (logger.isDebugEnabled()) {
            logger.debug("Kerberos token retrieved from SPNEGO token: \n{}",
                         DerValue.printByteArray(kerberosToken, 0, kerberosToken.length));
        }

        JsonValue sharedState;
        try {
            sharedState = ku.authenticateToken(kerberosToken, context.sharedState);
            return goTo(true).replaceSharedState(sharedState).build();
        } catch (PrivilegedActionException pe) {
            Exception e = ku.extractException(pe);
            logger.error("Exception thrown trying to authenticate the user", e);
            if (e instanceof GSSException) {
                int major = ((GSSException) e).getMajor();
                if (major == GSSException.CREDENTIALS_EXPIRED) {
                    logger.debug("Credential expired. Re-establish credential...");
                    try {
                        sharedState = ku.authenticateToken(kerberosToken, context.sharedState);
                        logger.debug("Authentication succeeded with new cred.");
                        return goTo(true).replaceSharedState(sharedState).build();
                    } catch (PrivilegedActionException ex) {
                        logger.debug("Authentication failed with new cred.", ex);
                        return goTo(false).build();
                    }
                }
            } else {
                logger.error("Authentication failed with PrivilegedActionException wrapped GSSException.", e);
                return goTo(false).build();
            }
        }
        return goTo(false).build();
    }

    private void validateConfigParameters() throws NodeProcessException {

    	String principalsKeytabs = "";
        Iterator<String> principals = config.principalKeytab().keySet().iterator();
        while (principals.hasNext()) {
			String principal = (String) principals.next();
			principalsKeytabs += "principal: \"" + principal + "\" keytab: \"" + config.principalKeytab().get(principal) + "\"";
		}
        
        if (logger.isDebugEnabled()) {
            logger.debug("WindowsDesktopSSO params: \n" + 
            		principalsKeytabs +
                    "\ndomain principal: " + config.returnPrincipalWithDomainName() +
                    "\nLookup user in realm:" + config.lookupUserInRealm() +
                    "\nAccepted Kerberos realms: " + config.trustedKerberosRealms() +
                    "\nisInitiator: " + config.kerberosServiceIsInitiator());
        }

        if (config.principalKeytab().isEmpty()) {
            throw new NodeProcessException("Service Principal and Keytab File map is empty");
        }

        principals = config.principalKeytab().keySet().iterator();
        while (principals.hasNext()) {
			String principal = (String) principals.next();
			String keytabFileName = config.principalKeytab().get(principal);
	        if (!Files.exists(Paths.get(keytabFileName))) {
	            throw new NodeProcessException("Key Tab File for principal \"" + principal + "\" does not exist at: \"" + keytabFileName + "\"");
	        }
		}

    }

}
