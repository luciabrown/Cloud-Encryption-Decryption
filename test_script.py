import secure, os, json
print(" ---------------- TEST CASE 1: ALICE & BOB CAN USE THE FUNCTIONALITY INITIALLY ---------------- ")
print("Generating certificates for Alice and Bob...")
secure.generate_user_cert("Alice")
secure.generate_user_cert("Bob")

# Verify certificate generation
for user in ["Alice", "Bob"]:
    if not os.path.exists(f"{user}_public.pem"):
        print(f"Error: {user}_public.pem not found!")
    else:
        print(f"{user}'s certificate ({user}_public.pem) generated successfully.\n")

# Ensure private keys exist before proceeding
for user in ["Alice", "Bob"]:
    if not os.path.exists(f"{user}_private.pem"):
        print(f"Error: {user}_private.pem not found! Decryption may fail.\n")

secure.add_user_to_group("Alice", "Alice_public.pem")
secure.add_user_to_group("Bob", "Bob_public.pem")

# Define user keys (public keys for encryption)
user_keys = {"Alice": "Alice_public.pem", "Bob": "Bob_public.pem"}
print(f"User keys for encryption: {user_keys}")

print("Encrypting file sample.txt using the public keys of Alice and Bob...")
secure.encrypt_file("sample.txt", user_keys)

# Ensure the key file is created before uploading
if os.path.exists("sample.txt.key"):
    print("Encrypted key file (sample.txt.key) found, uploading...")
    secure.upload_to_cloud("sample.txt.key")
else:
    print("Error: sample.txt.key not found! Ensure encryption was successful.")

# Upload encrypted file
secure.upload_to_cloud("sample.txt.enc")

# Check if key file exists before proceeding with decryption
if os.path.exists("sample.txt.key"):
    with open("sample.txt.key", "r", encoding="utf-8") as f:
        encrypted_keys = json.load(f)

# Decrypt file for Alice using Alice's private key
if "Alice" in encrypted_keys:
    print("Decrypting the encrypted file for Alice using Alice's private key...")
    secure.decrypt_file("sample.txt.enc", "Alice_private.pem", "Alice")
else:
    print("Error: Encrypted key for Alice not found.")
# Decrypt file for Bob using Bob's private key
if "Bob" in encrypted_keys:
    print("Decrypting the encrypted file for Bob using Bob's private key...")
    secure.decrypt_file("sample.txt.enc", "Bob_private.pem", "Bob")
else:
    print("Error: Encrypted key for Bob not found.")
    
# Test Case 2: Adding Charlie to the user group after initial setup
print(" ---------------- TEST CASE 2: ADDING CHARLIE TO THE USER GROUP AFTER INITIAL SETUP ---------------- ")
print("Generating certificate for Charlie...")
secure.generate_user_cert("Charlie")
print("Adding Charlie to the user group...")
secure.add_user_to_group("Charlie", "Charlie_public.pem")

# Re-encrypt the file so Charlie gets the AES key
print("Re-encrypting file sample.txt with updated user list (Alice, Bob, Charlie)...")
user_keys = {"Alice": "Alice_public.pem", "Bob": "Bob_public.pem", "Charlie": "Charlie_public.pem"}
secure.encrypt_file("sample.txt", user_keys)

# Upload the updated key file
if os.path.exists("sample.txt.key"):
    print("Updated encrypted key file (sample.txt.key) found, uploading...")
    secure.upload_to_cloud("sample.txt.key")
else:
    print("Error: Updated sample.txt.key not found! Ensure re-encryption was successful.")

# Verify if Charlie can now decrypt the file
print("Decrypting the encrypted file for Charlie using Charlie's private key...")
secure.decrypt_file("sample.txt.enc", "Charlie_private.pem", "Charlie")


# Test Case 3: Removing Bob from the user group and ensuring he can no longer decrypt
print(" ---------------- TEST CASE 3: REMOVING BOB FROM THE USER GROUP AND ENSURING HE CAN NO LONGER DECRYPT ---------------- ")

print("Removing Bob from the user group...")
secure.remove_user_from_group("Bob")

# Verify that Bob cannot decrypt the file anymore
print("Attempting to decrypt the encrypted file for Bob using Bob's private key...")
try:
    secure.decrypt_file("sample.txt.enc", "Bob_private.pem", "Bob")
except Exception as e:
    print(f"Bob correctly failed to decrypt the file. Error: {e}")
