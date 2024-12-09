import os
import hashlib


KNOWN_VIRUS_SIGNATURES = [
    "e99a18c428cb38d5f260853678922e03",   (MD5)
    "d41d8cd98f00b204e9800998ecf8427e",  (MD5)
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", # SHA256 
    "38467e46d0bdad0749518e16a19809b8ffe0386192e92e0d5aeb648a53470a79", #
    "f6c8e18c8ca4240feb9d4f6a7b7fb24b5d43917f8788563138466f538d1d0c92", #
    "
    =
]


def get_file_hash(file_path, hash_algorithm='md5'):
    hash_obj = hashlib.new(hash_algorithm)
    try:
        with open(file_path, "rb") as file:
            # Read the file in chunks to handle large files
            for chunk in iter(lambda: file.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        print(f"Error reading file {file_path}: {e}")
        return None


def scan_directory(directory_path):
    print(f"Scanning directory: {directory_path}")
    infected_files = []

    
    for root, dirs, files in os.walk(directory_path):
        for file_name in files:
            file_path = os.path.join(root, file_name)
            print(f"Scanning file: {file_path}")

            
            file_hash = get_file_hash(file_path, hash_algorithm='sha256')  # or 'md5'
            if file_hash:
                # Check if the hash matches any known virus signature
                if file_hash in KNOWN_VIRUS_SIGNATURES:
                    infected_files.append(file_path)

    return infected_files

# Main function to run the antivirus scan
def main():
    directory_to_scan = input("Enter the directory to scan: ")
    
    # Check if the provided path is valid
    if not os.path.exists(directory_to_scan):
        print(f"The directory {directory_to_scan} does not exist.")
        return

    infected_files = scan_directory(directory_to_scan)

    if infected_files:
        print("\nInfected files found:")
        for file in infected_files:
            print(f"- {file}")
        print("\nWarning: Virus signatures detected!")
    else:
        print("No infected files found.")

if __name__ == "__main__":
    main()
