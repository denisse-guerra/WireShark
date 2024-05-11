"""
Denisse Guerra
May 9th, 2024

This program is intented to extract information from a whireshark packet capture in text file format and print it to the user. 
The values extracted are frame number, the source and destination addresses, and the frame type.
"""

import re

def extract_frame(packet_filename):
    """
    This function opens the packet capture text file in read mode and fragments the content of each line in a list, to get the frame number,
    the source and destination addresses, and the frame type.
    The commented sections of the function are for finding the occurences of IP Addresses
    and more below, printing the lists for troubleshooting.
    
    Parameters:
    packet_filename(str): The name of a .txt file containing network packets.
    """
    
    frame_numbers = []  # Initialize an empty list for frame numbers
    all_mac_addresses = [] #Initialize an empty list for all mac addresses
    src_mac_addresses = [] #Initialize an empty list for source addresses
    dst_mac_addresses = [] #Initialize an empty list for destination addresses
    frame_type = [] # Initialize an empty list for frame types
    
    # Open packet file in read mode
    with open(packet_filename, 'r') as file:
        
        for line in file:
            #if the word Frame is found in the line
            if "Frame" in line:
                # Extract the frame number from the line, using regular expressions (re library) to extract the number even for multiple digits
                frame_match = re.search(r"Frame (\d+):", line)
                if frame_match:
                    frame_number = frame_match.group(1) #put all frame numbers, from single and multiple digits in one same group
                    frame_numbers.append(frame_number) #append the groups of numbers to the frame_numbers list
                    
            # elif "Internet Protocol Version 4" in line:
            #     #use IPV4 as the search parameter to make sure you are working with the expected format of IP address source and destination
            #     #a continuación usa el re.search para elegir src: todos los digitos y luego otro elif de dst
            #     src_match = re.search(r"Src: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            #     dst_match = re.search(r"Dst: (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
            #     if src_match and dst_match:
            #         src_address = src_match.group(1)
            #         src_addresses.append(src_address)
            #         dst_address = dst_match.group(1)
            #         dst_addresses.append(dst_address)
            #     else:
            #         print("The source and destination address could not be found.")
                    
            # Regular expression mac_pattern to match MAC addresses
            mac_pattern = r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})"

            # Find all occurrences of the mac_pattern in the line
            mac_matches = re.findall(mac_pattern, line)

            # Separate the mac_matches into source and destination MAC addresses
            for match in mac_matches:
                if "Src:" in line:
                    all_mac_addresses.append(match)
                    src_mac_addresses = all_mac_addresses[::2]
                    dst_mac_addresses = all_mac_addresses[1::2]
                    
            # Regular expression pattern to match hexadecimal values in parentheses aka. find Frame Type
            type_pattern = r"\((0x[0-9a-fA-F]+)\)"

            # Find all occurrences of frame types in the line
            type_matches = re.findall(type_pattern, line)
            
            for match in type_matches:
                frame_type.append(match)

    #traverse all the lists and print the corresponding instances one by one
    for frame, src, dst, ftype in zip(frame_numbers, src_mac_addresses, dst_mac_addresses, frame_type):
        print(f"Frame {frame}, Src:{src}, Des:{dst}, Type:({ftype})")
        
        
    # Print the results
    # print(frame_numbers)
    # print("Source MAC addresses:", src_mac_addresses)
    # print("Destination MAC addresses:", dst_mac_addresses)
    # print("Extracted hexadecimal values:", frame_type)


def main():
    '''
    This is the main driver code that calls the functions defined above to perform the desired tasks.
    '''
    
    extract_frame("wireShark.txt")

if __name__ == '__main__':
    main()