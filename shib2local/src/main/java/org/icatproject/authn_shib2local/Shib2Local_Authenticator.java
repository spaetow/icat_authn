package org.icatproject.authn_shib2local;

import java.util.List;
import java.util.Map;

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
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.Response;
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

	private static final Logger logger = Logger.getLogger(Shib2Local_Authenticator.class);

	@PersistenceContext(unitName = "authn_shib2local")
	private EntityManager manager;

	private String serviceProviderUrl;

	private String identityProviderUrl;

	private String lookupAttribute;

	private boolean disableCertCheck;

	private HttpHost proxyConnection;

	private org.icatproject.authentication.AddressChecker addressChecker;

	private String mechanism;

	@PostConstruct
	private void init() {

		String propsName = "authn_shib2local.properties";
		CheckedProperties props = new CheckedProperties();
		try {
			props.loadFromFile(propsName);

			String authips = props.getProperty("ip");
			if (authips != null) {
				try {
					addressChecker = new AddressChecker(authips);
				} catch (IcatException e) {
					String msg = "Problem creating AddressChecker with information from "
							+ propsName + " " + e.getMessage();
					logger.fatal(msg);
					throw new IllegalStateException(msg);
				}
			}

			// We require a Service Provider and an Identity Provider, as well as a lookup attribute
			serviceProviderUrl = props.getURL("service_provider_url").toString();
			identityProviderUrl = props.getURL("identity_provider_url").toString();
			lookupAttribute = props.getString("lookup_attribute");

			// Optional proxy access. If host or port specified, then both required
			if (props.has("proxy_host") || props.has("proxy_port")) {
				String proxyHost = props.getString("proxy_host");
				int proxyPort = props.getPositiveInt("proxy_port");
				this.proxyConnection = new HttpHost(proxyHost, proxyPort);
			}

			// Disabling the certificate check is optional too, by default it is false
			disableCertCheck = props.getBoolean("disable_cert_check", false);

			// Optional mechanism
			mechanism = props.getProperty("mechanism");

		} catch (CheckedPropertyException e) {
			logger.fatal(e.getMessage());
			throw new IllegalStateException(e.getMessage());
		}

		logger.info("Initialised Shib2Local_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null && !addressChecker.check(remoteAddr)) {
			fail("authn_shib2local does not allow log in from your IP address: " + remoteAddr);
		}

		String username = credentials.get("username");

		if (username == null || username.equals("")) {
			fail("Username cannot be null or empty.");
		}

		String password = credentials.get("password");
		if (password == null || password.equals("")) {
			fail("Password cannot be null or empty.");
		}

		logger.debug("Checking username/password on Shibboleth server for " + username);
		String lookupAttributeValue = null;
		try {
			// Initialise the library
			DefaultBootstrap.bootstrap();
			final BasicParserPool parserPool = new BasicParserPool();
			parserPool.setNamespaceAware(true);

			// Instantiate a copy of the client, catch any errors that occur
			ShibbolethECPAuthClient ecpClient = new ShibbolethECPAuthClient(this.proxyConnection,
					this.identityProviderUrl, this.serviceProviderUrl, this.disableCertCheck);

			// Try to authenticate. If authentication failed, an AuthenticationException is thrown
			final org.opensaml.saml2.core.Response response = ecpClient.authenticate(username, password);
			
			// If we get an exception here with our 'chained' get(...) calls, we have a problem!
			List<Attribute> attributes;
			try {
				 attributes = response.getAssertions().get(0).getAttributeStatements().get(0).getAttributes();
			}
			catch (final IndexOutOfBoundsException e) {
				throw new AttributeNotFoundException("The Shibboleth Identity Provider either returned no SAML assertions or no attribute statements");
			}
			
			// If there are no attributes, we can't do a lookup.
			if (attributes.isEmpty()) {
				throw new AttributeNotFoundException(
						"The Shibboleth Identity Provider returned a SAML assertion with no attributes");
			}

			// Trawl the attributes to check if we can find ours
			boolean idFound = false;
			for (Attribute attribute : attributes) {
				if ((attribute.getName().equals(this.lookupAttribute))
						|| (attribute.getFriendlyName().equals(this.lookupAttribute))) {
					idFound = true;
					XMLObject attributeValue = attribute.getAttributeValues().get(0);
					if (attributeValue instanceof XSString) {
						lookupAttributeValue = ((XSString) attributeValue).getValue();
					} else if (attributeValue instanceof XSAny) {
						lookupAttributeValue = ((XSAny) attributeValue).getTextContent();
					}
					logger.debug(lookupAttribute + ": " + lookupAttributeValue);
					break;
				}
			}

			// Attribute was not found in the SAML statement
			if (!idFound) {
				final String s = "The attribute " + this.lookupAttribute
						+ " was not returned by the Shibboleth Identity Provider";
				throw new AttributeNotFoundException(s);
			}
		} catch (final AttributeNotFoundException e) {
			fail(username + " authenticated successfully at " + this.identityProviderUrl
					+ ", but the identity provider returned insufficient information. Error: "
					+ e.toString());
		} catch (final AuthenticationException e) {
			fail("Failed to authenticate " + username + ": " + e.toString());
		} catch (final SOAPClientException e) {
			fail("The Shibboleth service provider is not configured for ECP authentication.");
		} catch (final Exception e) {
			fail("Unexpected error occurred trying to authenticate " + username + ": "
					+ e.toString());
		}

		// Look up the attribute's value in our database to see if we have a mapping for it
		AccountIdMap account = this.manager.find(AccountIdMap.class, lookupAttributeValue);
		if (account == null) {
			fail("Unable to find a local account for Shibboleth user " + username);
		}

		// Return a new authentication object
		logger.info(username + " logged in and mapped to " + account.getLocalUid()
				+ " successfully.");
		return new Authentication(account.getLocalUid(), mechanism);
	}

	private void fail(String msg) throws IcatException {
		logger.info(msg);
		throw new IcatException(IcatException.IcatExceptionType.SESSION, msg);
	}
}
