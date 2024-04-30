from ghidra.program.model.symbol.SourceType import *
import string

functionManager = currentProgram.getFunctionManager()

f = askFile("Choose an A2L file", "Import A2L file")

a2l_file = file(f.absolutePath).read()

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
        if (len(l) > 0):
            if (namefound == 0):
                name = l.split(' "')[0]
                namefound = 1
            elif (l.startswith("ECU_ADDRESS")):
                addr = l[12:]
                addrfound = 1
                break
    if (addrfound != 1):
        print("ERROR")
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
        print("ERROR")
    else:
        symbols.append((name, addr))


for symbol in symbols:
    name = symbol[0]
    address = toAddr(long(symbol[1], 16))

    try:
        function_or_label = symbol[1]
    except IndexError:
        function_or_label = "l"

    if function_or_label == "f":
        func = functionManager.getFunctionAt(address)

        if func is not None:
            old_name = func.getName()
            func.setName(name, USER_DEFINED)
            print("Renamed function {} to {} at address {}".format(old_name, name, address))
        else:
            func = createFunction(address, name)
            print("Created function {} at address {}".format(name, address))

    else:
        print("Created label {} at address {}".format(name, address))
        createLabel(address, name, False)
