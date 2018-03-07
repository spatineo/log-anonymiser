package com.spatineo.anonymisator;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApplicationConfiguration {
	private static Logger logger = LoggerFactory.getLogger(ApplicationConfiguration.class);
	
	@Bean
	public DnsLookup dnsLookup(@Value("${dns.disabled:#{null}}") String nodns, @Value("${dns.server:#{null}}") String dnsServer) {
		
		DnsLookup ret = new DnsLookup();
		
		if (nodns != null) {
			logger.debug("Disabling DNS lookup");
			ret.setEnabled(false);
		} else {
			logger.debug("Enabling DNS lookup");
			ret.setEnabled(true);
		}
		
		ret.setServer(dnsServer);
		
		return ret;
	}
	
}
