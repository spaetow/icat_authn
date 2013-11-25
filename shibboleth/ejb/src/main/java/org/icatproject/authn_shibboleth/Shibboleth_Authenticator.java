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

import org.apache.log4j.Logger;
import org.icatproject.authentication.AddressChecker;
import org.icatproject.authentication.Authentication;
import org.icatproject.authentication.Authenticator;
import org.icatproject.core.IcatException;
import org.opensaml.DefaultBootstrap;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.soap.client.SOAPClientException;
import org.opensaml.xml.parse.BasicParserPool;

import uk.ac.diamond.ShibbolethECPAuthClient.ShibbolethECPAuthClient;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_shibboleth.Shibboleth_Authenticator")
@Remote
public class Shibboleth_Authenticator implements Authenticator {

	private static final Logger log = Logger.getLogger(Shibboleth_Authenticator.class);
	private String serviceProviderUrl;
	private String identityProviderUrl;
	private org.icatproject.authentication.AddressChecker addressChecker;
	private String mechanism;

	@SuppressWarnings("unused")
	@PostConstruct
	private void init() {
		File f = new File("authn_shibboleth.properties");
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

		// Note that the mechanism is optional
		mechanism = props.getProperty("mechanism");

        this.serviceProviderUrl = spURL;
        this.identityProviderUrl = idpURL;

		log.debug("Initialised Shibboleth_Authenticator");
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

            // Instantiate a copy of the client, catch any errors that occur
            ShibbolethECPAuthClient seac = new ShibbolethECPAuthClient(this.identityProviderUrl, this.serviceProviderUrl, true);

            final Response response = seac.authenticate(username, password);

/*
            Assertion assertion = response.getAssertions().get(0);
            AttributeStatement as = assertion.getAttributeStatements().get(0);

            List<org.opensaml.saml2.core.Attribute> attributes = as.getAttributes();
            boolean idFound = false;
            if (!attributes.isEmpty()) {
                for (Attribute attribute : attributes) {
                    if ((attribute.getName().indexOf(attributeId) == 0) ||
                        (attribute.getFriendlyName().indexOf(attributeId) == 0)) {
                        idFound = true;
                        XMLObject attributeValue = attribute.getAttributeValues().get(0);
                        if (attributeValue instanceof XSString) {
                            log.debug("Attribute: " + attributeId + ", value: " + ((XSString) attributeValue).getValue());
                        } else if (attributeValue instanceof XSAny) {
                            log.debug("Attribute: " + attributeId + ", value: " + ((XSAny) attributeValue).getTextContent());
                        }
                    } // if getName()...
                } // for attribute...
            } // if not empty

            if (!idFound) {
                throw new IcatException(IcatException.IcatExceptionType.SESSION,
                        "The Shibboleth attribute " + this.requiredAttribute + " was not returned by the Shibboleth server");
            }
*/
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
