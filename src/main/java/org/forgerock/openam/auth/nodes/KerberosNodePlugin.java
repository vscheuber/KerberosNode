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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.security.AccessController;
import java.util.Collections;
import java.util.Iterator;
import java.util.Map;

import org.forgerock.openam.auth.node.api.AbstractNodeAmPlugin;
import org.forgerock.openam.auth.node.api.Node;
import org.forgerock.openam.plugins.PluginException;
import org.forgerock.openam.plugins.StartupType;
import org.forgerock.openam.sm.AnnotatedServiceRegistry;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.inject.Inject;
import com.iplanet.services.naming.ServiceListeners;
import com.iplanet.sso.SSOException;
import com.iplanet.sso.SSOToken;
import com.sun.identity.security.AdminTokenAction;
import com.sun.identity.sm.SMSException;
import com.sun.identity.sm.ServiceManager;

/**
 * Definition of an <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/auth/node/api/AbstractNodeAmPlugin.html">AbstractNodeAmPlugin</a>. 
 * Implementations can use {@code @Inject} setters to get access to APIs 
 * available via Guice dependency injection. For example, if you want to add an SMS service on install, you 
 * can add the following setter:
 * <pre><code>
 * {@code @Inject}
 * public void setPluginTools(PluginTools tools) {
 *     this.tools = tools;
 * }
 * </code></pre>
 * So that you can use the addSmsService api to load your schema XML for example.
 * PluginTools javadoc may be found 
 * <a href="https://backstage.forgerock.com/docs/am/6/apidocs/org/forgerock/openam/plugins/PluginTools.html#addSmsService-java.io.InputStream-">here</a> 
 * <p>
 *     It can be assumed that when running, implementations of this class will be singleton instances.
 * </p>
 * <p>
 *     It should <i>not</i> be expected that the runtime singleton instances will be the instances on which
 *     {@link #onAmUpgrade(String, String)} will be called. Guice-injected properties will also <i>not</i> be populated
 *     during that method call.
 * </p>
 * <p>
 *     Plugins should <i>not</i> use the {@code ShutdownManager}/{@code ShutdownListener} API for handling shutdown, as
 *     the order of calling those listeners is not deterministic. The {@link #onShutdown()} method for all plugins will
 *     be called in the reverse order from the order that {@link #onStartup()} was called, with dependent plugins being
 *     notified after their dependencies for startup, and before them for shutdown.
 * </p>
 * @supported.all.api
 * @since AM 5.5.0
 */
public class KerberosNodePlugin extends AbstractNodeAmPlugin {

	public static final String KERBEROS_CONFIG_SERVICE_NAME = "KerberosConfigService";
    private final Logger logger = LoggerFactory.getLogger("amAuth");
	static private String currentVersion = "1.0.0";
    private AnnotatedServiceRegistry serviceRegistry;
	private ServiceListeners serviceListeners;
	
    /** 
     * Specify the Map of list of node classes that the plugin is providing. These will then be installed and
     *  registered at the appropriate times in plugin lifecycle.
     *
     * @return The list of node classes.
     */
	@Override
	protected Map<String, Iterable<? extends Class<? extends Node>>> getNodesByVersion() {
		return Collections.singletonMap(KerberosNodePlugin.currentVersion,
                                        Collections.singletonList(KerberosNode.class));
	}

	/**
	 * Handle plugin installation. This method will only be called once, on first AM
	 * startup once the plugin is included in the classpath. The
	 * {@link #onStartup()} method will be called after this one.
	 * 
	 * No need to implement this unless your AuthNode has specific requirements on
	 * install.
	 */
	@Override
	public void onInstall() throws PluginException {
		logger.info("Installing KerberosConfigService service");
		pluginTools.installService(KerberosConfigService.class);
		super.onInstall();
	}

	/**
	 * Handle plugin startup. This method will be called every time AM starts, after
	 * {@link #onInstall()}, {@link #onAmUpgrade(String, String)} and
	 * {@link #upgrade(String)} have been called (if relevant).
	 * 
	 * No need to implement this unless your AuthNode has specific requirements on
	 * startup.
	 *
	 * @param startupType The type of startup that is taking place.
	 */
	@Override
	public void onStartup(StartupType startupType) throws PluginException {
		logger.info("Starting KerberosConfigService service");
		pluginTools.startService(KerberosConfigService.class);
		
		// register config change listener
		logger.info("Registering configuration change listener for service KerberosConfigService.");
		serviceListeners.forService(KERBEROS_CONFIG_SERVICE_NAME)
        .onGlobalChange(this::configurationChanged)
        .listen();

        configureKerberos();
		
		super.onStartup(startupType);
	}
	
	private void configurationChanged() {
		logger.info("KerberosConfigService configuration changed!");
        configureKerberos();
	}

	private void configureKerberos() {
		try {
			logger.info("Loading service configuration...");
			KerberosConfigService serviceConfig = this.serviceRegistry.getGlobalSingleton(KerberosConfigService.class);
			if (serviceConfig.useKrb5Config()) {
				logger.info("Using external krb5.conf file.");
				System.clearProperty("java.security.krb5.conf");
				File krb5File = new File(KerberosConfigService.KRB5_CONF_FILE);
				if (krb5File.exists())
					krb5File.delete();
			}
			else {
				logger.info("Using service configuration values to generate krb5.conf file.");
				PrintWriter writer;
				try {
					writer = new PrintWriter(KerberosConfigService.KRB5_CONF_FILE, "UTF-8");
					if (!serviceConfig.libdefaults().isEmpty()) {
						writer.println("[libdefaults]");
						Iterator<String> libdefaults = serviceConfig.libdefaults().keySet().iterator();
						while (libdefaults.hasNext()) {
							String key = (String) libdefaults.next();
							String value = serviceConfig.libdefaults().get(key);
							writer.println("    " + key + " = " + value);
						}
						writer.println();
					}
					if (!serviceConfig.realms().isEmpty()) {
						writer.println("[realms]");
						Iterator<String> realms = serviceConfig.realms().keySet().iterator();
						while (realms.hasNext()) {
							String key = (String) realms.next();
							String value = serviceConfig.realms().get(key);
							writer.println("    " + key + " = {");
							writer.println("        kdc = " + value);
							writer.println("    }");
						}
						writer.println();
					}
					if (!serviceConfig.domain_realm().isEmpty()) {
						writer.println("[domain_realm]");
						Iterator<String> domain_realm = serviceConfig.domain_realm().keySet().iterator();
						while (domain_realm.hasNext()) {
							String key = (String) domain_realm.next();
							String value = serviceConfig.domain_realm().get(key);
							writer.println("    " + key + " = " + value);
						}
						writer.println();
					}
					if (!serviceConfig.capaths().isEmpty()) {
						writer.println("[capaths]");
						Iterator<String> capaths = serviceConfig.capaths().keySet().iterator();
						while (capaths.hasNext()) {
							String key = (String) capaths.next();
							String value = serviceConfig.capaths().get(key);
							writer.println("    " + key + " = " + value);
						}
						writer.println();
					}
					writer.close();
			        System.setProperty("java.security.krb5.conf", KerberosConfigService.KRB5_CONF_FILE);
				} catch (FileNotFoundException | UnsupportedEncodingException e) {
					logger.error("Error writing to \"" + KerberosConfigService.KRB5_CONF_FILE + "\"", e);
				}
			}
        } catch (SSOException | SMSException e) {
            logger.error("Error loading service configuration...", e);
        }
	}

	/**
	 * This method will be called when the version returned by
	 * {@link #getPluginVersion()} is higher than the version already installed.
	 * This method will be called before the {@link #onStartup()} method.
	 * 
	 * No need to implement this untils there are multiple versions of your auth
	 * node.
	 *
	 * @param fromVersion The old version of the plugin that has been installed.
	 */
	@Override
	public void upgrade(String fromVersion) throws PluginException {
		logger.error("fromVersion = " + fromVersion);
		logger.error("currentVersion = " + currentVersion);
		try {
			SSOToken adminToken = AccessController.doPrivileged(AdminTokenAction.getInstance());
			ServiceManager sm = new ServiceManager(adminToken);
			if (sm.getServiceNames().contains("KerberosConfigService")) {
				logger.info("removing old KerberosConfigService version");
				sm.removeService("KerberosConfigService", fromVersion);
			}
			logger.info("Installing new KerberosConfigService service");
			pluginTools.installService(KerberosConfigService.class);
		} catch (SSOException | SMSException e) {
			throw new PluginException(e.getMessage());
		}
		pluginTools.upgradeAuthNode(KerberosNode.class);
		super.upgrade(fromVersion);
	}

    /** 
     * The plugin version. This must be in semver (semantic version) format.
     *
     * @return The version of the plugin.
     * @see <a href="https://www.osgi.org/wp-content/uploads/SemanticVersioning.pdf">Semantic Versioning</a>
     */
	@Override
	public String getPluginVersion() {
		return KerberosNodePlugin.currentVersion;
	}

    @Inject
    public void setDependencies(ServiceListeners serviceListeners, AnnotatedServiceRegistry serviceRegistry) {
        this.serviceListeners = serviceListeners;
        this.serviceRegistry = serviceRegistry;
    }
	
	
}
