package com.spatineo.anonymisator;

/*-
 * #%L
 * log-anonymisator
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 Spatineo Inc
 * %%
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public
 * License along with this program.  If not, see
 * <http://www.gnu.org/licenses/gpl-3.0.html>.
 * #L%
 */

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.util.StringUtils;
import org.xbill.DNS.ExtendedResolver;
import org.xbill.DNS.Resolver;

import com.spatineo.anonymisator.dns.DisabledDnsLookupHandler;
import com.spatineo.anonymisator.dns.DnsjavaLookupHandlerImpl;
import com.spatineo.anonymisator.dns.DnsLookupHandler;

@Configuration
public class ApplicationConfiguration {
	private static Logger logger = LoggerFactory.getLogger(ApplicationConfiguration.class);
	
	private static final Map<String, String> legalParameters;
	private static final Set<String> legalParametersRequireValue;
	
	static {
		Map<String, String> tmp = new HashMap<>();
		
		tmp.put("dns.allowprivate", "Return full private DNS names (e.g. hello.local) when DNS returns them");
		tmp.put("dns.disabled", "Disable DNS lookups (enabled by default)");
		tmp.put("dns.server", "DNS server(s) to use as a comma-delimited list, for example --dns.server=8.8.8.8,8.8.4.4 for Google public DNS (use system settings by default)");
		tmp.put("dns.timeoutmillis", "DNS lookup timeout in milliseconds (default 30000)");
		tmp.put("threads", "How many concurrent threads are used in parallel (default 32)");
		tmp.put("mask.ipv4", "How many bits in IPv4 addressess to mask / anonymise (default 8)");
		tmp.put("mask.ipv6", "How many bits in IPv6 addressess to mask / anonymise (default 80)");
		tmp.put("compress.input", "Is the input file gzip compressed true/false (default autodetect)");
		tmp.put("compress.output", "Should the output file be gzip compressed true/false (default as input)");
		tmp.put("help", "Display this message");
		
		legalParameters = Collections.unmodifiableMap(tmp);
		
		legalParametersRequireValue = Collections.unmodifiableSet(
				new HashSet<>(Arrays.asList("dns.server", "mask.ipv4", "mask.ipv6","compress.input","compress.output","threads")));
	}
	
	/**
	 * Produces a human-readable usage/help message to be presented to the user.
	 *
	 * @return A human readable string containing the usage message
	 */
	public String usage() {
		StringBuffer buf = new StringBuffer();
		buf.append("Usage: java -jar log-anonymisator.jar [options] inputfile outputfile\n");
		buf.append("\tThe following options are supported:\n");
		List<String> parameters = new ArrayList<>(legalParameters.keySet());
		
		int maxLength = -1;
		for (String p : parameters) {
			if (legalParametersRequireValue.contains(p)) {
				p += "=value";
			}
			maxLength = Math.max(maxLength, p.length());
		}
		Collections.sort(parameters);
		for (String param : parameters) {
			buf.append("\t  --");
			String description = legalParameters.get(param);
			
			if (legalParametersRequireValue.contains(param)) {
				param += "=value";
			}
			buf.append(param);
			
			for (int i = -2; i < (maxLength - param.length()); i++) {
				buf.append(" ");
			}
			
			buf.append(description);
			buf.append("\n");
		}
		
		return buf.toString();
	}
	
	/**
	 * Validates given parameters
	 * 
	 * @param arg Arguments given to application
	 * @return A human-readable error message or null if arguments are valid
	 */
	public String validateParameters(ApplicationArguments arg) {
		if (arg.getNonOptionArgs().size() != 2) {
			return "You need to specify one inputfile name and one outputfile";
		}
		
		
		for (String p : arg.getOptionNames()) {
			if (!legalParameters.containsKey(p)) {
				return "Illegal parameter "+p;
			}
			
			if (legalParametersRequireValue.contains(p)) {
				List <String> values = arg.getOptionValues(p);
				if (values.size() == 0) {
					return "You need to specify a value for parameter "+p;
				}
				
				if (values.size() > 1) {
					return "Please only specify one value for parameter "+p;
				}
			}
		}
		
		return null;
	}
	
	@Bean
	public AnonymiserProcessor anonymisator(IpAddressAnonymiser ipAddressAnonymiser, AnonymiserConfiguration configuration) {
		AnonymiserProcessor ret = new AnonymiserProcessor();
		ret.setIpAddressAnonymiser(ipAddressAnonymiser);
		ret.setParallelThreads(configuration.getParallelThreads());
		ret.setTimeoutMillis(configuration.getTimeoutMillis());
		return ret;
	}
	
	@Bean
	public IpAddressAnonymiser ipAddressAnonymiser(DnsLookupHandler dnsLookupHandler, AnonymiserConfiguration configuration) {
		SpatineoLogAnalysisIpAddressAnonymiser ret = new SpatineoLogAnalysisIpAddressAnonymiser();
		ret.setIpv4BitsToAnonymize(configuration.getIpv4BitsToAnonymize());
		ret.setIpv6BitsToAnonymize(configuration.getIpv6BitsToAnonymize());
		ret.setDnsLookupHandler(dnsLookupHandler);
		ret.setAllowFullPrivateAddresses(configuration.isAllowFullPrivateAddresses());
		return ret;
	}
	
	@Bean
	public InputOutput inputOutput(
			@Value("${compress.input:#{null}}") String compressInput,
			@Value("${compress.output:#{null}}") String compressOutput) {
		InputOutput ret = new InputOutput();
		
		if (compressInput != null) {
			if ("true".equals(compressInput)) {
				ret.setCompressInput(true);
			} else if ("false".equals(compressInput)) {
				ret.setCompressInput(false);
			} else {
				throw new IllegalArgumentException("Invalid value for compress.input '"+compressInput+"'");
			}
		}
		
		if (compressOutput != null) {
			if ("true".equals(compressOutput)) {
				ret.setCompressOutput(true);
			} else if ("false".equals(compressOutput)) {
				ret.setCompressOutput(false);
			} else {
				throw new IllegalArgumentException("Invalid value for compress.output '"+compressOutput+"'");
			}
		}
		
		return ret;
	}
	
	@Bean
	public AnonymiserConfiguration dnsLookup(
			@Value("${dns.allowprivate:#{null}}") String allowFullPrivateAddresses,
			@Value("${dns.disabled:#{null}}") String nodns,
			@Value("${dns.server:#{null}}") String dnsServer,
			@Value("${dns.timeoutmillis:30000}") long timeoutMillis,
			@Value("${threads:32}") int parallelThreads,
			@Value("${mask.ipv4:8}") int ipv4mask,
			@Value("${mask.ipv6:80}") int ipv6mask)
	{
		
		AnonymiserConfiguration ret = new AnonymiserConfiguration();
		
		ret.setAllowFullPrivateAddresses(allowFullPrivateAddresses != null);
		logger.debug("Allow full private addresses = "+ret.isAllowFullPrivateAddresses());
		
		if (nodns != null) {
			logger.debug("Disabling DNS lookup");
			ret.setEnabled(false);
			
			// Set threads since this is needed for thread pool configuration
			ret.setParallelThreads(1);
			
		} else {
			logger.debug("Enabling DNS lookup");
			ret.setEnabled(true);
			// Do the rest of the configuration only when DNS lookup is enabled
		
			if (dnsServer == null) {
				logger.debug("Using default DNS server");
				ret.setServers(null);
			} else {
				List<String> tmp = new ArrayList<>();
				for (String server : StringUtils.split(dnsServer, ",")) {
				
					server = server.trim();
					if (server.length() > 0) {
						tmp.add(server);
					}
				}
				logger.debug("Using following DNS servers: "+tmp);
				ret.setServers(tmp);
			}
			
			logger.debug("Using "+timeoutMillis+"ms as DNS timeout");
			ret.setTimeoutMillis(timeoutMillis);
			 
			logger.debug("Using "+parallelThreads+" parallel DNS threads");
			ret.setParallelThreads(parallelThreads);
		}
		
		if (ipv4mask < 0 || ipv4mask > 32) {
			throw new IllegalArgumentException("Illegal IPv4 mask "+ipv4mask);
		}
		logger.debug("Anonymising IPv4 addresses by removing last "+ipv4mask+" bits");
		ret.setIpv4BitsToAnonymize(ipv4mask);
		
		
		if (ipv6mask < 0 || ipv6mask > 128) {
			throw new IllegalArgumentException("Illegal IPv6 mask "+ipv6mask);
		}
		logger.debug("Anonymising IPv6 addresses by removing last "+ipv6mask+" bits");
		ret.setIpv6BitsToAnonymize(ipv6mask);
		
		return ret;
	}

	@Bean
	public Resolver resolver(AnonymiserConfiguration configuration) throws Exception {
		Resolver resolver;
		List<String> servers = configuration.getServers();
		if (servers == null) {
			resolver = new ExtendedResolver();
		} else {
			resolver = new ExtendedResolver(servers.toArray(new String[]{}));
		}
		
		long timeout = configuration.getTimeoutMillis();
		long millis = timeout % 1000;
		long secs = (timeout - millis) / 1000l;
		resolver.setTimeout((int) secs, (int) millis);
		
		return resolver;
	}
	
	@Bean
	public DnsLookupHandler dnsLookupHandler(AnonymiserConfiguration config, Resolver resolver) {
		if (!config.isEnabled()) {
			return new DisabledDnsLookupHandler();
		}
		
		DnsjavaLookupHandlerImpl ret = new DnsjavaLookupHandlerImpl();
		ret.setAnonymiserConfiguration(config);
		ret.setResolver(resolver);
		
		return ret;
	}

}
