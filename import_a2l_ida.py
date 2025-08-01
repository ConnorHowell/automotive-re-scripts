import idc
import ida_kernwin
import ida_funcs
import ida_bytes

def ask_file():
    # Asks the user for a file
    path = ida_kernwin.ask_file(0, "*.a2l", "Select A2L file")
    if not path:
        raise RuntimeError("No file selected.")
    return path

def read_file(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return f.read()

def main():
    fpath = ask_file()
    a2l_file = read_file(fpath)

    # Get all characteristics
    characteristics = a2l_file.split("/begin CHARACTERISTIC")
    characteristics.pop(0)
    print("Found: %d characteristic(s)" % len(characteristics))

    measurements = a2l_file.split("/begin MEASUREMENT")
    measurements.pop(0)
    print("Found: %d measurement(s)" % len(measurements))

    axis_pts = a2l_file.split("/begin AXIS_PTS")
    axis_pts.pop(0)
    print("Found: %d axis_pts" % len(axis_pts))

    # Setup empty array for symbols and their corresponding address
    symbols = []

    # Process characteristics
    for c in characteristics:
        namefound = 0
        addrfound = 0
        name = ""
        addr = ""
        for l in c.split("\n"):
            l = l.strip()
            if len(l) > 0:
                if namefound == 0:
                    name = l.split(' "')[0]
                    namefound = 1
                elif (
                    l.startswith("VALUE ")
                    or l.startswith("CURVE ")
                    or l.startswith("ASCII ")
                    or l.startswith("MAP ")
                ):
                    addr = l.split(" ")[1]
                    addrfound = 1
                    break
                elif l.startswith("0x") and len(l) > 4:
                    addr = l
                    addrfound = 1
                    break
        if addrfound != 1:
            print("ERROR in characteristics")
        else:
            symbols.append((name, addr))

    # Process measurements
    for m in measurements:
        namefound = 0
        addrfound = 0
        name = ""
        addr = ""
        for l in m.split("\n"):
            l = l.strip()
            if len(l) > 0:
                if namefound == 0:
                    name = l.split(' "')[0]
                    namefound = 1
                elif l.startswith("ECU_ADDRESS"):
                    addr = l[12:].strip()
                    addrfound = 1
                    break
        if addrfound != 1:
            print("ERROR in measurements")
        else:
            symbols.append((name, addr))

    # Process axis_pts
    for a in axis_pts:
        namefound = 0
        addrfound = 0
        name = ""
        addr = ""
        for l in a.split("\n"):
            l = l.strip()
            if len(l) > 0:
                if namefound == 0:
                    name = l.split(' "')[0]
                    namefound = 1
                elif l.startswith("0x"):
                    addr = l
                    addrfound = 1
                    break
        if addrfound != 1:
            print("ERROR in axis_pts")
        else:
            symbols.append((name, addr))

    # Now apply labels
    for symbol in symbols:
        name = symbol[0]
        address_str = symbol[1].replace(";", "").strip()
        try:
            address = int(address_str, 16)
        except Exception:
            print("Could not parse address for {}: {}".format(name, address_str))
            continue

        # Check if there is already a function at this address, otherwise just create a label
        if ida_funcs.get_func(address):
            old_name = idc.get_func_name(address)
            idc.set_name(address, name, idc.SN_NOWARN)
            print("Renamed function {} to {} at address 0x{:X}".format(old_name, name, address))
        else:
            # Create a label at the address
            idc.set_name(address, name, idc.SN_NOWARN)
            print("Created label {} at address 0x{:X}".format(name, address))

if __name__ == '__main__':
    main()
