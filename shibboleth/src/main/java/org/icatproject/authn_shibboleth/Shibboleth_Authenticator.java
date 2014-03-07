package org.icatproject.authn_shibboleth;

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
import org.icatproject.utils.CheckedProperties;
import org.icatproject.utils.CheckedProperties.CheckedPropertyException;
import org.opensaml.saml2.core.Response;
import org.opensaml.ws.soap.client.SOAPClientException;

import uk.ac.diamond.shibbolethecpauthclient.ShibbolethECPAuthClient;

/* Mapped name is to avoid name clashes */
@Stateless(mappedName = "org.icatproject.authn_shibboleth.Shibboleth_Authenticator")
@Remote
public class Shibboleth_Authenticator implements Authenticator {

	private static final Logger logger = Logger.getLogger(Shibboleth_Authenticator.class);

	private String serviceProviderUrl;

	private String identityProviderUrl;

	private boolean disableCertCheck;

	private HttpHost proxyConnection;

	private org.icatproject.authentication.AddressChecker addressChecker;

	private String mechanism;

	@PostConstruct
	private void init() {

		String propsName = "authn_shibboleth.properties";
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

		logger.info("Initialised Shibboleth_Authenticator");
	}

	@Override
	public Authentication authenticate(Map<String, String> credentials, String remoteAddr)
			throws IcatException {

		if (addressChecker != null && !addressChecker.check(remoteAddr)) {
			fail("authn_shibboleth does not allow log in from your IP address: " + remoteAddr);
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
		try {
			// Instantiate a copy of the client, catch any errors that occur
			ShibbolethECPAuthClient ecpClient = new ShibbolethECPAuthClient(this.proxyConnection,
					this.identityProviderUrl, this.serviceProviderUrl, this.disableCertCheck);

			// Try to authenticate. If authentication failed, an AuthenticationException is thrown
			final Response response = ecpClient.authenticate(username, password);

		} catch (final AuthenticationException e) {
			fail("Failed to authenticate " + username + ": " + e.toString());
		} catch (final SOAPClientException e) {
			fail("The Shibboleth service provider is not configured for ECP authentication.");
		} catch (final Exception e) {
			fail("Unexpected error occurred trying to authenticate " + username + ": "
					+ e.toString());
		}
		
		// Return a new authentication object
		logger.info(username + " logged in successfully.");
		return new Authentication(username, mechanism);
	}

	private void fail(String msg) throws IcatException {
		logger.info(msg);
		throw new IcatException(IcatException.IcatExceptionType.SESSION, msg);
	}
}
