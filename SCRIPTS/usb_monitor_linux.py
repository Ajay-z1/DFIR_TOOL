import os
import hashlib
import subprocess


def check_iocs(hashes, ioc_file="iocs_file"):
    """
    Compare calculated hashes with known IOCs
    """
    matches = set()

    if not os.path.exists(ioc_file):
        return matches

    with open(ioc_file, "r") as f:
        iocs = {line.strip() for line in f}

    for h in hashes:
        if h in iocs:
            matches.add(h)

    return matches


def calculate_hash(filepath, hash_func=hashlib.sha256):

    hash_obj = hash_func()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                hash_obj.update(chunk)
    except Exception:
        return None

    return hash_obj.hexdigest()



def traverse(mount_point):

    hashes = set()

    for root, _, files in os.walk(mount_point):
        for file in files:
            path = os.path.join(root, file)
            h = calculate_hash(path)
            if h:
                hashes.add(h)

    return hashes



def differ_check(hashes, usb_id, hash_path):
    
    # Check if current hashes differ from stored hashes

    stored_file = os.path.join(hash_path, usb_id)

    if not os.path.exists(stored_file):
        return True

    with open(stored_file, "r") as f:
        stored_hashes = {line.strip() for line in f}

    return hashes != stored_hashes



def check_for_familiarity(usb_id, familiar_file, hash_path, mount_point):
    # Check whether USB is new or modified and scan for IOCs
    familiar = set()

    if os.path.exists(familiar_file):
        with open(familiar_file, "r") as f:
            familiar = {line.strip() for line in f}

    hashes = traverse(mount_point)

    # New USB
    if usb_id not in familiar:
        with open(familiar_file, "a") as f:
            f.write(usb_id + "\n")

        with open(os.path.join(hash_path, usb_id), "w") as f:
            for h in hashes:
                f.write(h + "\n")

        return check_iocs(hashes)

    # Known USB – check for modifications
    if differ_check(hashes, usb_id, hash_path):
        with open(os.path.join(hash_path, usb_id), "w") as f:
            for h in hashes:
                f.write(h + "\n")

        return check_iocs(hashes)

    return set()


def main():
    result = subprocess.run(
        ["lsblk", "-S", "-o", "NAME,TRAN,SERIAL,VENDOR,MODEL,MOUNTPOINT"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL
    )

    output = result.stdout.decode("utf-8").strip().split("\n")[1:]

    familiar_file = "path/" #to create already traversed usbs
    hash_dir = "/path/hash" #to save hases of files gone through

    os.makedirs(hash_dir, exist_ok=True)

    for line in output:
        if "usb" not in line:
            continue

        parts = line.split()
        if len(parts) < 6:
            continue

        name, tran, serial, vendor, model, mount_point = parts[:6]

        if not mount_point.startswith("/"):
            print(f"USB {name} not mounted")
            continue

        usb_id = vendor + model + serial

        matches = check_for_familiarity(
            usb_id,
            familiar_file,
            hash_dir,
            mount_point
        )

        if matches:
            print(f"[!] USB {name} ({usb_id}) is COMPROMISED")
        else:
            print(f"[+] USB {name} ({usb_id}) is clean")


if __name__ == "__main__":
    main()
