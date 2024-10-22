def hash_api(api_name):

    hash_value = 0x69 #can be changed

    for i, char in enumerate(api_name, 1):
        c = ord(char)
        c_hex = f"0x{c:x}"         
        hash_value += (hash_value * 0xac88d37f0 + c) & 0xffffff #0xac88d37f0 is arbitrary and can be changed
        hash_hex = f"0x{hash_value:x}"


    final_hash = f"0x00{hash_value:x}"
    print(f"{api_name}\t {final_hash}")
    return final_hash


if __name__ == "__main__":
    api = input("Enter the name of the api function to hash:")
    hash_api(api)
