package com.czertainly.cryptosense.certificate.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;
import org.springframework.data.jpa.repository.config.EnableJpaAuditing;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

@Configuration
@EnableJpaAuditing
@PropertySource(value = ApplicationConfig.EXTERNAL_PROPERTY_SOURCE, ignoreResourceNotFound = true)
public class ApplicationConfig {

	private static final Logger logger = LoggerFactory.getLogger(ApplicationConfig.class);

	public static final String EXTERNAL_PROPERTY_SOURCE = "file:${czertainly-cryptosense-discovery.config.dir:/etc/czertainly-cryptosense-discovery}/czertainly-cryptosense-discovery.properties";

	@Bean
	public void httpsConnection() {
		TrustManager[] dummyTrustManager = new TrustManager[] { new X509TrustManager() {

			@Override
			public X509Certificate[] getAcceptedIssuers() {
				// TODO Auto-generated method stub
				return null;
			}

			@Override
			public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// TODO Auto-generated method stub

			}

			@Override
			public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {
				// TODO Auto-generated method stub

			}
		} };
		SSLContext sc;
		try {
			sc = SSLContext.getInstance("SSL");
			sc.init(null, dummyTrustManager, new java.security.SecureRandom());
			HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
		} catch (NoSuchAlgorithmException | KeyManagementException e1) {
			logger.error(e1.getMessage());
		}

		HostnameVerifier allHostsValid = new HostnameVerifier() {
			public boolean verify(String hostname, SSLSession session) {
				return true;
			}
		};

		// Install the all-trusting host verifier
		HttpsURLConnection.setDefaultHostnameVerifier(allHostsValid);
	}

}