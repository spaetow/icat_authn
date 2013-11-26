package org.icatproject.authn_shibboleth;

import java.io.File;
import java.io.FileInputStream;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;

import javax.annotation.PostConstruct;
import javax.ejb.Remote;
import javax.ejb.Stateless;
import javax.management.AttributeNotFoundException;
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

import uk.ac.diamond.ShibbolethECPAuthClient.ShibbolethECPAuthClient;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_shib2local.Shib2Local_Authenticator")
@Remote
public class Shib2Local_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(Shib2Local_Authenticator.class);
	private String serviceProviderUrl;
	private String identityProviderUrl;
	private String requiredAttribute;
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
		String reqAttribute = props.getProperty("userid_attribute");
		if (reqAttribute == null) {
			String msg = "userid_attribute not defined in " + f.getAbsolutePath();
			log.fatal(msg);
			throw new IllegalStateException(msg);
		}

		// proxy access is optional, but if the host is specified, the port is required
		String proxyHost = props.getProperty("proxy_host");
		if (spURL != null) {
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
		else
		{
			// we clearly don't have a proxy, or we're using what's defined for the JVM
			this.proxyConnection = null;
		}

		// Note that the mechanism is optional
		this.mechanism = props.getProperty("mechanism");

        this.serviceProviderUrl = spURL;
        this.identityProviderUrl = idpURL;
        this.requiredAttribute = reqAttribute;

		log.debug("Initialised Shib2Local_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null) {
			if (!addressChecker.check(remoteAddr)) {
				throw new IcatException(IcatException.IcatExceptionType.SESSION,
						"authn_shibboleth does not allow log in from your IP address " + remoteAddr);
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

        try {
            // Initialise the library
            DefaultBootstrap.bootstrap();
            final BasicParserPool parserPool = new BasicParserPool();
            parserPool.setNamespaceAware(true);

            // Instantiate a copy of the client, try to authentication, catch any errors that occur
            ShibbolethECPAuthClient seac = new ShibbolethECPAuthClient(this.proxyConnection, this.identityProviderUrl, 
            		this.serviceProviderUrl, true);

            // if we get an exception here with our 'chained' get(...) calls, we have a problem anyway!
            boolean idFound = false;
            String requiredAttributeValue;
            List<Attribute> attributes = seac.authenticate(username, password)
            								.getAssertions().get(0)
            								.getAttributeStatements().get(0)
            								.getAttributes();

            if (!attributes.isEmpty()) {
                for (Attribute attribute : attributes) {
                    if ((attribute.getName().indexOf(this.requiredAttribute) == 0) ||
                        (attribute.getFriendlyName().indexOf(this.requiredAttribute) == 0)) {
                        idFound = true;
                        XMLObject attributeValue = attribute.getAttributeValues().get(0);
                        if (attributeValue instanceof XSString) {
                        	requiredAttributeValue = ((XSString) attributeValue).getValue();
                        } else if (attributeValue instanceof XSAny) {
                        	requiredAttributeValue = ((XSAny) attributeValue).getTextContent();
                        }
                        log.debug("Attribute: " + this.requiredAttribute + ", value: " + requiredAttributeValue);
                    } // if getName()...
                } // for attribute...
            } // if not empty

            if (!idFound) {
                throw new IcatException(IcatException.IcatExceptionType.SESSION,
                        "The Shibboleth attribute " + this.requiredAttribute + " was not returned by the Shibboleth server");
            }

            // return a new authentication object
            log.info(username + " logged in successfully");
            return new Authentication(username, mechanism);

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
    }
}
