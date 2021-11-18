package com.spatineo.anonymisator;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.Reader;
import java.io.Writer;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

/*-
 * #%L
 * com.spatineo:log-anonymiser
 * $Id:$
 * $HeadURL:$
 * %%
 * Copyright (C) 2018 - 2021 Spatineo Inc
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

public class InputOutput {
	private Boolean compressInput;
	private Boolean compressOutput;
	
	// Was the last input file compressed or not
	private boolean inputCompressed;
	
	public void setCompressInput(Boolean compressInput) {
		this.compressInput = compressInput;
	}
	
	public Boolean getCompressInput() {
		return compressInput;
	}
	
	public void setCompressOutput(Boolean compressOutput) {
		this.compressOutput = compressOutput;
	}
	
	public Boolean getCompressOutput() {
		return compressOutput;
	}
	
	public Reader createInput(File filename) throws IOException {
		if (compressInput == null) {
			inputCompressed = testIfShouldCompress(filename);
		} else {
			inputCompressed = compressInput.booleanValue();
		}
		
		Reader input;
		if (inputCompressed) {
			input = new InputStreamReader(new GZIPInputStream(new FileInputStream(filename)));
		} else {
			input = new FileReader(filename);
		}
		return input;
	}
	
	private boolean testIfShouldCompress(File filename) {
		if (filename.getName().endsWith(".gz") || filename.getName().endsWith(".Z")) {
			return true;
		}
		return false;
	}

	public Writer createWriter(File filename) throws IOException {
		boolean outputCompressed;
		
		if (compressOutput == null) {
			outputCompressed = inputCompressed;
		} else {
			outputCompressed = compressOutput.booleanValue();
		}
		
		Writer output;
		if (outputCompressed) {
			output = new OutputStreamWriter(new GZIPOutputStream(new FileOutputStream(filename)));
		} else {
			output = new FileWriter(filename);
		}
		return output;
	}
	
}
