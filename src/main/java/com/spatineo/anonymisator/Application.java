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

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
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
		try {
			ConfigurableApplicationContext ctx = SpringApplication.run(Application.class, args);
			SpringApplication.exit(ctx);
		} catch(Exception e) {
			logger.error("Configuration error", e);
		}
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

		try {
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
			
			File outputFile = new File(outputfileName);
			if (outputFile.exists()) {
				System.err.println(outputfileName+": exists already!");
				return;
			}
			
			try (Reader input = new FileReader(inputFile); Writer output = new FileWriter(outputFile)) {
				anonymisator.process(input, output);
				output.flush();
			}
		} catch(Exception e) {
			logger.error("Application error", e);
		}
	
	}
}
