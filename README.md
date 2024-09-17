# i_seeyar
This tool automatically generates basic YARA rules based on the strings extracted from a binary file (e.g., malware sample or any PE file).

How to Use

Clone or Download the Script: Save the script as i_seeyar.py on your local machine.

Run the Script:

python i_seeyar.py

Input Prompts:

Enter the binary file path: Specify the file you want to analyze (e.g., malware_sample.exe).
Enter a custom name for your YARA rule: Name your YARA rule (e.g., MyCustomRule).
Enter the output YARA rule file path: Provide a name for the output file (e.g., rule.yara).
Choose a condition for the rule:
        
        Option 1: All strings must match (default).
        Option 2: Any string can match.
        Option 3: File size must match and all strings must match.
        Option 4: PE entry point and all strings must match.

View the Generated YARA Rule: The tool will generate a YARA rule and save it to the file you specified.
