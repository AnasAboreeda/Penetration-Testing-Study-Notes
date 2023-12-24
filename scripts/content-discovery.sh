#!/bin/bash

# Input file containing subdomains (located in the current directory)
input_file="$(pwd)/subdomains-live.txt"

# Log file for recording script execution
log_file="script.log"

print_separator_2() {
    echo "--------------------------------------------------------------------------------"
}

# Function to print a separator line
print_separator() {
    echo "================================================================================="
}

# Define a function to run the commands for a single subdomain
run_commands() {
    subdomain="$1"
    # Clean the subdomain for use as a filename
    subdomain_filename=$(echo "$subdomain" | sed 's/[^A-Za-z0-9._-]/_/g')
    output_file="content-discovery_$subdomain_filename.txt"
    
    # Print separator line to visually separate logs for each subdomain
    print_separator
    
    # Log the current subdomain being processed to both stdout and the log file
    echo "Processing subdomain: $subdomain"
    echo "Processing subdomain: $subdomain" >> "$log_file"
    print_separator_2
    
    # Log the start of command execution
    echo "Running commands for $subdomain..."
    echo "Running commands for $subdomain..." >> "$log_file"
    
    # Run the commands for the current subdomain and save output to the output file
    gofinder -l "$subdomain" > "$output_file"
    echo "goFinder command completed for $subdomain..."
    echo "goFinder command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    getallurls "$subdomain" >> "$output_file"
    echo "getallurls command completed for $subdomain..."
    echo "getallurls command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    waybackurls "$subdomain" >> "$output_file"
    echo "waybackurls command completed for $subdomain..."
    echo "waybackurls command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    waybackrobots "$subdomain" >> "$output_file"
    echo "waybackrobots command completed for $subdomain..."
    echo "waybackrobots command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    ffuf -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/common.txt -u "$subdomain/FUZZ" >> "$output_file"
    echo "ffuf command completed for $subdomain..."
    echo "ffuf command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    dirb "$subdomain/" /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/common.txt >> "$output_file"
    echo "dirb command completed for $subdomain..."
    echo "dirb command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    gobuster dir --url "$subdomain/" -w /usr/share/wordlists/seclists/SecLists-master/Discovery/Web-Content/common.txt >> "$output_file"
    echo "gobuster command completed for $subdomain..."
    echo "gobuster command completed for $subdomain..." >> "$log_file"
    
    print_separator_2
    
    # Log completion of commands for the current subdomain to both stdout and the log file
    echo "Commands completed for $subdomain."
    echo "Commands completed for $subdomain." >> "$log_file"
}

# Clear the log file before starting
> "$log_file"

# Export the function so it can be used with parallel
export -f run_commands

# Limit the number of subdomains processed concurrently to 10 (-j 10)
cat "$input_file" | parallel -j 3 run_commands {}

# Print a separator line to mark the end of script execution
print_separator

# Log script completion to both stdout and the log file
echo "Script execution completed."
echo "Script execution completed." >> "$log_file"
