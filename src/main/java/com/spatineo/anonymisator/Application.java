package com.spatineo.anonymisator;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ConfigurableApplicationContext;

@SpringBootApplication
public class Application implements ApplicationRunner
{
	private static Logger logger = LoggerFactory.getLogger(Application.class);
	
	@Autowired
	private AnonymiserProcessor anonymisator;
	
	@Autowired
	private ApplicationConfiguration configuration;
	
	
	public static void main(String...args) {
		ConfigurableApplicationContext ctx = SpringApplication.run(Application.class, args);
		SpringApplication.exit(ctx);
	}
	
	@Override
	public void run(ApplicationArguments arguments) throws Exception {
		/**
		 * Parameters: 
		 *  - input file
		 *  - output file
		 *  - dns lookup or no (on by default)
		 *  - dns service to use
		 *  - ipv4 bits to anonymise
		 *  - ipv6 bits to anonymise
		 */
				
		String errorMessage = configuration.validateParameters(arguments);
		if (errorMessage != null) {
			System.err.println("error: "+errorMessage);
			System.err.println(configuration.usage());
			return;
		}
		
		if (arguments.containsOption("help")) {
			System.err.println(configuration.usage());
			return;
		}
		
		
		String inputFileName = arguments.getNonOptionArgs().get(0);
		String outputfileName = arguments.getNonOptionArgs().get(1);
		
		File inputFile = new File(inputFileName);
		if (!inputFile.exists()) {
			System.err.println(inputFileName+": does not exist");
			return;
		}
		
		if (inputFile.isDirectory()) {
			System.err.println(inputFileName+": is a directory");
			return;
		}
		
		if (!inputFile.canRead()) {
			System.err.println(inputFileName+": cannot read file");
			return;
		}
		
		/*
		File outputFile = new File(outputfileName);
		if (outputFile.exists()) {
			System.err.println(inputFileName+": exists already!");
			return;
		}
		
		if (!outputFile.canWrite()) {
			System.err.println(inputFileName+": cannot write to this file");
			return;
		}
		*/
		
		try (Reader input = new FileReader(inputFile);
				Writer output = new OutputStreamWriter(System.out)
				/*Writer output = new FileWriter(outputFile)*/) {
			anonymisator.process(input, output);
			output.flush();
		}
	
	}
}
