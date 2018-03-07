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
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Application implements ApplicationRunner
{
	private static Logger logger = LoggerFactory.getLogger(Application.class);
	
	private static final Map<String, String> legalParameters;
	private static final Set<String> legalParametersRequireValue;
	
	static {
		Map<String, String> tmp = new HashMap<>();
		
		tmp.put("dns.disabled", "Disable DNS lookups (enabled by default)");
		tmp.put("dns.server", "DNS server(s) to use as a comma-delimited list, for example --dns.server=8.8.8.8,4.4.4.4 for Google public DNS (use system settings by default)");
		tmp.put("help", "Display this message");
		
		legalParameters = Collections.unmodifiableMap(tmp);
		
		legalParametersRequireValue = Collections.unmodifiableSet(new HashSet<>(Arrays.asList("dns.server")));
	}
	
	@Autowired
	private DnsLookup dnsLookup;
	
	public static void main(String...args) {
		SpringApplication.run(Application.class, args);
	}
	
	
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
	
	@Override
	public void run(ApplicationArguments arguments) {
		/**
		 * Parameters: 
		 *  - input file
		 *  - output file
		 *  - dns lookup or no (on by default)
		 *  - dns service to use
		 *  - ipv4 bits to anonymise
		 *  - ipv6 bits to anonymise
		 */
		
		String errorMessage = validateParameters(arguments);
		if (errorMessage != null) {
			System.err.println("error: "+errorMessage);
			System.err.println(usage());
			return;
		}
		
		if (arguments.containsOption("help")) {
			System.err.println(usage());
			return;
		}
		
		
		logger.info("Non option args (n="+arguments.getNonOptionArgs().size()+")");
		for (String str : arguments.getNonOptionArgs()) {
			logger.info(" + "+str);
		}
		
		
		logger.info("Option args (n="+arguments.getOptionNames().size()+")");
		for (String str : arguments.getOptionNames()) {
			logger.info(" + "+str+"="+arguments.getOptionValues(str));
		}
		
		logger.info("DNS lookup: "+dnsLookup);
	}
}
