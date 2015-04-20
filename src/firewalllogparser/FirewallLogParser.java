/*
 * The MIT License
 *
 * Copyright 2015 Timothy Flynn.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

package firewalllogparser;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;

/**
 * This program parses through output files from a Cisco firewall and reports 
 * several different analytics.  It can recreate the input file, displays the 
 * count for a user provided IP addresses and ports.  Also, it can show the
 * counts by hour for certain IP addresses and ports.
 * @author Timothy Flynn
 */

public class FirewallLogParser 
{    
    /**
     * Execute the functions in the order specified by the assignment
     * @param args
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void main(String[] args) throws FileNotFoundException, IOException 
    {   
        //Read from the input file and write it to an identical output file
        //writeOutput();
        
        //Output to the console the count of all connections
        //displayCountConnections();
        
        //Output to the console the count for IP address 192.168.1.14 and output the logs
        displayCountForIP("192.168.1.14", true);
        
        //Output to the console the count for port 88 and output the logs
        //displayCountForPort("88", true);
        
        //Output to the console the count for 192.168.1.14 and port 88
        //displayCountForBoth("192.168.1.14", "88", true);
        
        //Display the counts per hour for IP address 172.20.1.5 and port 80
        //displayCountsPerHour("172.20.1.5", "80");
    }
    
    /**
     * Reads from a file stored at data/input.txt and writes
     * to a file at data/output.txt
     * 
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void writeOutput() throws FileNotFoundException, IOException
    {
        System.out.println("Write started...");
        //Create file
        File outputFile = new File("data\\output.txt");
        //Create file output stream
	FileOutputStream fos = new FileOutputStream(outputFile);
        //Create BufferedWriter
	BufferedWriter bw = new BufferedWriter(new OutputStreamWriter(fos));
        
        //Read through input file
        try(BufferedReader br = new BufferedReader(new FileReader("data\\input.txt"))) 
        {
            //Iterate through the entire file line by line
            for(String line; (line = br.readLine()) != null; ) 
            {   
                //Write current line to the BufferedWriter
                bw.write(line);
                //Start a new line
		bw.newLine();
            }
        }
        
        System.out.println("Write completed successfully!");
    }   
    
    /**
     * Counts all connections in the file and returns the number
     * 
     * @return total count of all connections in data/input.txt
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static int countConnections() throws FileNotFoundException, IOException
    {
        //Set count equal to 0
        int count = 0;
        
        try(BufferedReader br = new BufferedReader(new FileReader("data\\input.txt"))) 
        {
            //For each lin that is not null increment count
            for(String line; (line = br.readLine()) != null; ) 
            {
                count++;
            }
        }
        //Return the value of count
        return count;
    }  
    
    /**
     * Prints the total count of connections to the console
     * @throws IOException
     */
    public static void displayCountConnections() throws IOException
    {
        //Display starting dialog
        System.out.println("Starting count...");
        //Get value of countConnections()
        int count = countConnections();
        //Output to console the total number of connections
        System.out.println("Count completed successfully!\nTotal Number of Connections: " + count);
    }
    
    /**
     * Generate counts for a given IP address.  Also takes output flag which
     * determines whether or not the logs are displayed or just the counts
     * 
     * @param ipaddress
     * @param output
     * @return total number of connections for a certain IP
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static int countForIP(String ipaddress, Boolean output) throws FileNotFoundException, IOException
    {
        //Set count equal to 0
        int count = 0;
        
        try(BufferedReader br = new BufferedReader(new FileReader("data\\input.txt"))) 
        {
            //While next line is not null continue
            for(String line; (line = br.readLine()) != null; ) 
            { 
                //If IP address is in line then increment count
                if(line.contains(ipaddress))
                {
                    //If output equals true print to console
                    if(output.equals(true))
                    {
                        System.out.println(line);
                    }
                    count++; 
                }
            }
        } 
        //Return the value of count
        return count;
    }
    
    /**
     * Displays status messages and total counts for a provided IP address
     * to the console.  A boolean (output) value is excepted which if toggled true will
     * output the individual lines to the console.
     * @param ipaddress
     * @param output
     * @throws IOException
     */
    public static void displayCountForIP(String ipaddress, Boolean output) throws IOException
    {
        //Display starting dialog
        System.out.println("Starting count...");
        //Execute countForIP with given constraints
        int count = countForIP(ipaddress, output);
        //Print results
        System.out.println("\nCount for " + ipaddress + ": " + count);
    }
    
    /**
     * Calculates the total count for any port provided by the user. A boolean 
     * (output) value is excepted which if toggled true will
     * output the individual lines to the console 
     * @param port
     * @param output
     * @return
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static int countForPort(String port, Boolean output) throws FileNotFoundException, IOException
    {
        //Set the count to 0 initially
        int count = 0;
        try(BufferedReader br = new BufferedReader(new FileReader("data\\input.txt"))) 
        {
            //Iterate through while next line is not null
            for(String line; (line = br.readLine()) != null; ) 
            { 
                //If line contains the selected port then increment value of count
                if(line.contains("/" + port))
                {
                    //If output is true then display logs to console
                    if(output.equals(true))
                    {
                        System.out.println(line);
                    }
                    count++;
                }
            }
        } 
        return count;
    }
    
    /**
     * Displays the counts for a user specified port.  A boolean 
     * (output) value is excepted which if toggled true will
     * output the individual lines to the console 
     * @param port
     * @param output
     * @throws IOException
     */
    public static void displayCountForPort(String port, Boolean output) throws IOException
    {
        //Display start dialog
        System.out.println("Starting count...");
        //Call countForPort with provided constraints
        int count = countForPort(port, output);
        //Print the total counts to the console
        System.out.println("Count for port " + port+ ": " + count);
    }
    
    /**
     * Calculate the counts per hour based on IP address, port, and given
     * date.
     * @param day
     * @param ipaddress
     * @param port
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static void countsPerHour(String day, String ipaddress, String port) throws FileNotFoundException, IOException
    {
        //Set counter to 0
        int count = 0;

        try(BufferedReader br = new BufferedReader(new FileReader("data\\input.txt"))) 
        {
            //For every line that is not null keep iterating
            for(String line; (line = br.readLine()) != null; ) 
            { 
                //If line matches given contstraints then increment count
                if(line.contains(day) && line.contains(ipaddress) && line.contains(port))
                {
                    count++;
                }
            }
        }
       
        //Output the counts per hour in table format
        System.out.println(day + ":00\t| " + ipaddress + "\t| " + port + "\t| " + count);
    }
    
    /**
     * Displays the counts per the selected hours for a given IP address and
     * port.  This could be further methodized, but for the given context the
     * hard coded hours suffice.
     * @param ipaddress
     * @param port
     * @throws IOException
     */
    public static void displayCountsPerHour(String ipaddress, String port) throws IOException
    {
        //Display the table headers
        System.out.println("\nTime Stamp\t\t| IP Address\t| Port\t| Count");
        System.out.println("---------------------------------------------------------");
        //Calculate countsPerHour for 24 hours
        countsPerHour("2011-04-13 08", ipaddress, port);
        countsPerHour("2011-04-13 09", ipaddress, port);
        countsPerHour("2011-04-13 10", ipaddress, port);
        countsPerHour("2011-04-13 11", ipaddress, port);
        countsPerHour("2011-04-13 12", ipaddress, port);
        countsPerHour("2011-04-13 13", ipaddress, port);
        countsPerHour("2011-04-13 14", ipaddress, port);
        countsPerHour("2011-04-13 15", ipaddress, port);
        countsPerHour("2011-04-13 16", ipaddress, port);
        countsPerHour("2011-04-13 17", ipaddress, port);
        countsPerHour("2011-04-13 18", ipaddress, port);
        countsPerHour("2011-04-13 19", ipaddress, port);
        countsPerHour("2011-04-13 20", ipaddress, port);
        countsPerHour("2011-04-13 21", ipaddress, port);
        countsPerHour("2011-04-13 22", ipaddress, port);
        countsPerHour("2011-04-13 23", ipaddress, port);
        countsPerHour("2011-04-14 00", ipaddress, port);
        countsPerHour("2011-04-14 01", ipaddress, port);
        countsPerHour("2011-04-14 02", ipaddress, port);
        countsPerHour("2011-04-14 03", ipaddress, port);
        countsPerHour("2011-04-14 04", ipaddress, port);
        countsPerHour("2011-04-14 05", ipaddress, port);
        countsPerHour("2011-04-14 06", ipaddress, port);
        countsPerHour("2011-04-14 07", ipaddress, port);
    }
    
    /**
     * Calculate the counts based on IP address and port
     * 
     * @param ipaddress
     * @param port
     * @param output
     * @return 
     * @throws FileNotFoundException
     * @throws IOException
     */
    public static int countForBoth(String ipaddress, String port, Boolean output) throws FileNotFoundException, IOException
    {
        //Set counter to 0
        int count = 0;

        try(BufferedReader br = new BufferedReader(new FileReader("data\\input.txt"))) 
        {
            //For every line that is not null keep iterating
            for(String line; (line = br.readLine()) != null; ) 
            { 
                //If line matches given contstraints then increment count
                if(line.contains(ipaddress) && line.contains(port))
                {
                    //If output is equal to true display to console
                    if(output.equals(true))
                    {
                        System.out.println(line);
                    }
                    count++;
                }
            }
        }
        return count;
    }
    
    /**
     * Displays counts for intersection of IP address and port provided
     * @param ipaddress
     * @param port
     * @param output
     * @throws IOException
     */
    public static void displayCountForBoth (String ipaddress, String port, Boolean output) throws IOException
    {
        //Display start dialog
        System.out.println("Starting count...");
        //Call countForPort with provided constraints
        int count = countForBoth(ipaddress, port, output);
        //Print the total counts to the console
        System.out.println("Count for IP address " + ipaddress + " and port " + port + ": " + count);
    }
}