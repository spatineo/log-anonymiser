package com.spatineo.anonymisator;

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

import com.spatineo.anonymisator.dns.DnsLookupConfiguration;
import com.spatineo.anonymisator.dns.DnsLookupService;
import com.spatineo.anonymisator.dns.DnsjavaLookupHandlerImpl;
import com.spatineo.anonymisator.dns.DnsLookupHandler;
import com.spatineo.anonymisator.dns.ParallelDnsLookupService;

@Configuration
public class ApplicationConfiguration {
	private static Logger logger = LoggerFactory.getLogger(ApplicationConfiguration.class);
	
	private static final Map<String, String> legalParameters;
	private static final Set<String> legalParametersRequireValue;
	
	static {
		Map<String, String> tmp = new HashMap<>();
		
		tmp.put("dns.disabled", "Disable DNS lookups (enabled by default)");
		tmp.put("dns.server", "DNS server(s) to use as a comma-delimited list, for example --dns.server=8.8.8.8,4.4.4.4 for Google public DNS (use system settings by default)");
		tmp.put("dns.parallel", "How many concurrent DNS lookups may be done in parallel (default 16)");
		tmp.put("help", "Display this message");
		
		legalParameters = Collections.unmodifiableMap(tmp);
		
		legalParametersRequireValue = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("dns.server")));
	}
	
	/**
	 * Produces a human-readable usage/help message to be presented to the user.
	 * 
	 * @return
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
					return "Please only spsecify one value for parameter "+p;
				}
			}
		}
		
		return null;
	}
	
	
	@Bean
	public DnsLookupConfiguration dnsLookup(
			@Value("${dns.disabled:#{null}}") String nodns,
			@Value("${dns.server:#{null}}") String dnsServer,
			@Value("${dns.parallel:16}") int parallelThreads) {
		
		DnsLookupConfiguration ret = new DnsLookupConfiguration();
		
		if (nodns != null) {
			logger.debug("Disabling DNS lookup");
			ret.setEnabled(false);
			
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
			
			logger.debug("Using "+parallelThreads+" parallel DNS threads");
			ret.setParallelThreads(parallelThreads);
		}
		
		return ret;
	}

	
	@Bean
	public DnsLookupHandler dnsLookupHanlder(DnsLookupConfiguration config) {
		DnsjavaLookupHandlerImpl ret = new DnsjavaLookupHandlerImpl();
		ret.setDnsLookupConfiguration(config);
		return ret;
	}
	
	
	@Bean
	public DnsLookupService dnsLookupService(DnsLookupConfiguration config, DnsLookupHandler lookupHandler) {
		ParallelDnsLookupService ret = new ParallelDnsLookupService();
		ret.setParallelThreads(config.getParallelThreads());
		ret.setTimeoutMillis(30000l);
		ret.setLookupHandler(lookupHandler);
		
		return ret;
	}

}
