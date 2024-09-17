import os
import re
import pefile


def extract_strings(file_path, min_length=5):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    
    ascii_strings = re.findall(b'[ -~]{%d,}' % min_length, data)
    unicode_strings = re.findall(b'(?:[\x20-\x7E][\x00]){%d,}' % min_length, data)

   
    decoded_ascii = [s.decode('ascii', errors='ignore') for s in ascii_strings]
    decoded_unicode = [s.decode('utf-16', errors='ignore') for s in unicode_strings]

    return decoded_ascii + decoded_unicode


def generate_yara_rule(file_path, rule_name, output_rule, condition_type):
    # Extract the strings from the binary
    strings = extract_strings(file_path)
    
    
    filtered_strings = [s for s in strings if len(s) > 4 and not is_common_string(s)]
    
    
    filtered_strings = filtered_strings[:10]

   
    yara_rule_template = f"""
rule {rule_name}
{{
    meta:
        description = "Auto-generated YARA rule for {os.path.basename(file_path)}"
        author = "YourTool"
        date = "{os.path.getmtime(file_path)}"
    
    strings:
"""
    # Add extracted strings to the rule
    for idx, s in enumerate(filtered_strings):
        yara_rule_template += f'        $string{idx} = "{s}"\n'

   
    yara_rule_template += "\n    condition:\n"
    if condition_type == "1":
        yara_rule_template += "        all of them\n"
    elif condition_type == "2":
        yara_rule_template += "        any of them\n"
    elif condition_type == "3":
        yara_rule_template += f"        filesize < {os.path.getsize(file_path)} and all of them\n"
    elif condition_type == "4":
        pe = pefile.PE(file_path)
        entry_point = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        yara_rule_template += f"        uint16(0) == 0x5A4D and pe.entry_point == {entry_point} and all of them\n"

    
    with open(output_rule, 'w') as f:
        f.write(yara_rule_template)

    print(f"YARA rule generated and saved to {output_rule}")


def is_common_string(s):
    common_strings = [
        "Microsoft", "Windows", "kernel32.dll", "user32.dll", "ntdll.dll",
        "comctl32.dll", "msvcrt.dll", "LoadLibrary", "GetProcAddress"
    ]
    return any(common_str in s for common_str in common_strings)


def analyze_pe(file_path):
    try:
        pe = pefile.PE(file_path)
        print(f"Analyzing PE file: {file_path}")
        print(f"Entry point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}")
        print(f"Number of sections: {pe.FILE_HEADER.NumberOfSections}")
        print(f"ImageBase: {hex(pe.OPTIONAL_HEADER.ImageBase)}")
    except Exception as e:
        print(f"Error analyzing PE file: {e}")


def main():
    # Path to the binary file you want to analyze
    file_path = input("Enter the path to the binary file: ")
    if not os.path.exists(file_path):
        print(f"File {file_path} not found!")
        return

    
    analyze_pe(file_path)

 
    rule_name = input("Enter a custom name for your YARA rule (e.g., MyCustomRule): ")

   
    output_rule = input("Enter the output YARA rule file path (e.g., rule.yara): ")

    # Choose condition type
    print("\nChoose a condition for the YARA rule:")
    print("1: All strings must match (default)")
    print("2: Any string can match")
    print("3: Match based on file size and all strings")
    print("4: Match based on PE entry point and all strings")
    condition_type = input("Enter the condition number (1-4): ")
    
    if condition_type not in ["1", "2", "3", "4"]:
        print("Invalid input. Defaulting to 'all strings must match'.")
        condition_type = "1"

  
    generate_yara_rule(file_path, rule_name, output_rule, condition_type)

if __name__ == "__main__":
    main()
