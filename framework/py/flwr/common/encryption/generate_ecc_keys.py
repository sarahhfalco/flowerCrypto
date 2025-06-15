from ecies.utils import generate_key
import os

def save_keys(folder="keys"):
    os.makedirs(folder, exist_ok=True)
    privkey = generate_key()

    with open(f"{folder}/private_key.hex", "w") as f:
        f.write(privkey.to_hex())

    with open(f"{folder}/public_key.hex", "w") as f:
        f.write(privkey.public_key.format(True).hex())

    print("ECC keys generated and saved.")

if __name__ == "__main__":
    save_keys()
