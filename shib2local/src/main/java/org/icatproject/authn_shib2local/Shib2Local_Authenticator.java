package org.icatproject.authn_shib2local;

import java.io.File;
import java.io.FileInputStream;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.ejb.TransactionManagement;
import javax.ejb.TransactionManagementType;
import javax.management.AttributeNotFoundException;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceContext;
import javax.security.sasl.AuthenticationException;

import org.apache.http.HttpHost;
import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.parse.BasicParserPool;
import org.opensaml.xml.schema.XSAny;
import org.opensaml.xml.schema.XSString;

import uk.ac.diamond.shibbolethecpauthclient.ShibbolethECPAuthClient;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_shib2local.Shib2Local_Authenticator")
@TransactionManagement(TransactionManagementType.BEAN)
@Remote
public class Shib2Local_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(Shib2Local_Authenticator.class);

	@PersistenceContext(unitName = "db_shib2local")
	private EntityManager manager;

	private String serviceProviderUrl;

	private String identityProviderUrl;

	private String lookupAttribute;

	private boolean disableCertCheck;

	private HttpHost proxyConnection;

	private org.icatproject.authentication.AddressChecker addressChecker;

	private String mechanism;

	@SuppressWarnings("unused")
	@PostConstruct
	private void init() {
		File f = new File("authn_shib2local.properties");
		Properties props = null;
		try {
			props = new Properties();
			props.load(new FileInputStream(f));
		} catch (Exception e) {
			String msg = "Unable to read property file " + f.getAbsolutePath() + "  "
					+ e.getMessage();
			log.fatal(msg);
			throw new IllegalStateException(msg);

		}
		String authips = props.getProperty("ip");
		if (authips != null) {
			try {
				addressChecker = new AddressChecker(authips);
			} catch (IcatException e) {
				String msg = "Problem creating AddressChecker with information from "
						+ f.getAbsolutePath() + "  " + e.getMessage();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
		}

		// We require a Service Provider and an Identity Provider, as well as a lookup attribute
		String spURL = props.getProperty("service_provider_url");
		if (spURL == null) {
			String msg = "service_provider_url not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}
		String idpURL = props.getProperty("identity_provider_url");
		if (idpURL == null) {
			String msg = "identity_provider_url not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}
		String samlAttribute = props.getProperty("lookup_attribute");
		if (samlAttribute == null) {
			String msg = "lookup_attribute not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}

		// Proxy access is optional, but if the host is specified, the port is required
		String proxyHost = props.getProperty("proxy_host");
		if (proxyHost != null) {
			String proxyPort = props.getProperty("proxy_port");
			if (proxyPort == null) {
				String msg = "proxyHost specified, but proxyPort not defined in " + f.getAbsolutePath();
				log.fatal(msg);
				throw new IllegalStateException(msg);
			}
			else {
				// only set up a proxy connection if we have everything
				this.proxyConnection = new HttpHost(proxyHost, Integer.parseInt(proxyPort));
			}
		}
		else {
			// we clearly don't have a proxy, or we're using what's defined for the JVM
			this.proxyConnection = null;
		}

		// Disabling the certificate check is optional too, by default it is false
		String disableCertCheck = props.getProperty("disable_cert_check");
		if (disableCertCheck == null) {
			this.disableCertCheck = false;
		}
		else { 
			this.disableCertCheck = disableCertCheck.toLowerCase().equals("true");
		}

		// Note that the mechanism is optional
		this.mechanism = props.getProperty("mechanism");

		// Set up our required variables
		this.serviceProviderUrl = spURL;
		this.identityProviderUrl = idpURL;
		this.lookupAttribute = samlAttribute;

		log.debug("Initialised Shib2Local_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_shib2local does not allow log in from your IP address " + remoteAddr);
			}
		}

		String username = credentials.get("username");
		log.trace("login:" + username);

		if (username == null || username.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Username cannot be null or empty.");
		}
		String password = credentials.get("password");
		if (password == null || password.equals("")) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Password cannot be null or empty.");
		}

		log.info("Checking username/password on Shibboleth server");
		String lookupAttributeValue = null;
		try {
			// Initialise the library
			DefaultBootstrap.bootstrap();
			final BasicParserPool parserPool = new BasicParserPool();
			parserPool.setNamespaceAware(true);

			// Instantiate a copy of the client, catch any errors that occur
			ShibbolethECPAuthClient ecpClient = new ShibbolethECPAuthClient(this.proxyConnection, this.identityProviderUrl, 
					this.serviceProviderUrl, this.disableCertCheck);

			// Try to authenticate. If we get an exception here with our 'chained' get(...) calls, we have a problem anyway!
			List<Attribute> attributes = ecpClient.authenticate(username, password).getAssertions().get(0)
					.getAttributeStatements().get(0).getAttributes();

			// If there are no attributes, we can't do a lookup.
			if (attributes.isEmpty()) {
				throw new AttributeNotFoundException("The Shibboleth Identity Provider returned a SAML assertion with no attributes");
			}

			// Trawl the attributes to check if we can find ours
			boolean idFound = false;
			for (Attribute attribute : attributes) {
				if ((attribute.getName().equals(this.lookupAttribute)) ||
						(attribute.getFriendlyName().equals(this.lookupAttribute))) {
					idFound = true;
					XMLObject attributeValue = attribute.getAttributeValues().get(0);
					if (attributeValue instanceof XSString) {
						lookupAttributeValue = ((XSString) attributeValue).getValue();
					} 
					else if (attributeValue instanceof XSAny) {
						lookupAttributeValue = ((XSAny) attributeValue).getTextContent();
					}
					log.debug("Attribute: " + this.lookupAttribute + ", value: " + lookupAttributeValue);
					break;
				}
			}

			// Attribute was not found in the SAML statement
			if (!idFound) {
				final String s = "The attribute " + this.lookupAttribute + " was not returned by the Shibboleth Identity Provider";
				throw new AttributeNotFoundException(s);
			}
		} catch (final AttributeNotFoundException e) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION, 
					username + " authenticated successfully at " + this.identityProviderUrl + 
					", but the identity provider returned insufficient information. Error: " + e.toString());
		} catch (final AuthenticationException e) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Failed to authenticate " + username + " at " + this.identityProviderUrl + ". Error: " + e.toString());
		} catch (final SOAPClientException e) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"The Shibboleth service provider at " + this.serviceProviderUrl + " is not configured for ECP authentication.");
		} catch (final Exception e) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"An error occurred trying to authenticate user " + username + ". Error: " + e.toString());
		}

		// Look up the attribute's value in our database to see if we have a mapping for it
		log.debug("Entity Manager is " + manager);
		log.debug("User successfully authenticated by " + this.identityProviderUrl + ". Attempting local account lookup.");
		AccountIdMap fedId = this.manager.find(AccountIdMap.class, lookupAttributeValue);
		if (fedId == null) {
			throw new IcatException(IcatException.IcatExceptionType.SESSION,
					"Unable to find a local account for Shibboleth user " + username);
		}

		// Return a new authentication object
		log.info(username + " logged in and mapped to " + fedId.getLocalUid() + " successfully.");
		return new Authentication(fedId.getLocalUid(), mechanism);
	}
}
