import frida
import sys

currfile = None

def on_message(message, data):
	global currfile

	if message["type"] != "send":
		return

	data = message["payload"]

	if data.startswith("BEGIN"):
		filename = "/".join(data[5:].split("/")[-2:])

        basedir = filename.split("/")[0]
		if not os.path.exists(basedir):
			os.mkdir(basedir)
		
		currfile = open(filename, "wb")
	elif data == "DONE":
		print("[PyI] dumped file %s." % currfile.name)
		currfile.close()
	else:
		currfile.write(bytes(x % 256 for x in data))

def call(expand):
    return f"""
    indentation_level += 1;
    var ret = {expand};
    indentation_level -= 1;
    """

def basefun(fun):
    f"""
    function (...args) {{
        print(`Calling: {fun}(${{[...args].join(", ")}})`);
        
        var fun = this.{fun};
        {call("fun(...args)")}
            
        print("{fun} -> " + ret);
            
        return ret;
    }}
    """

def hookall(classpath, fun):
    return f"""
    Java.use("{classpath}").{fun}.overloads.forEach(overload => {{
        overload.implementation = {basefun(fun)}
    }});
    """

def dump_file(filename):
	return f"""
	try {{
		var File = Java.use("java.io.File");
		var FileInputStream = Java.use("java.io.FileInputStream").$new({filename});
		
		var buffer = Java.array('byte', new Array(1024 * 1024 * 64).fill(0));
		var readfile = File.$new({filename});
		var reader = FileInputStream.$new(readfile);

		send("BEGIN " + {varname});

		var lenread = 0;

		while (true) {{
			var nr = reader.read(buffer);
			if (nr == 0)
				break;
			
			send(buffer);

			lenread += nr;

			if (lenread >= readfile.length())
				break;
		}}
	}} catch (ex) {{
		print(ex);
	}}

    send("DONE");
	"""

dump_foo_file = f"""
    // overloading a overloaded function with signature: `anything bar(string a, int b)`
    Java.use("com.foobar.Foo").bar.overload("java.lang.string", "int").implementation = function (filename, length) {{
        {dump_file("filename")}

        ({basefun(fun)})(filename, length);
    }}
"""

script = """
let indentation_level = 0;

let print = function (msg) {
	var indent = "\t".repeat(indentation_level);
	console.log(indent + msg);
}

setTimeout(function () {
	Java.perform(function () {
        """ + dump_foo_file
        """
    });
}, 0);
"""

device = frida.get_usb_device()

pid = device.spawn(["com.foobar"])

session = device.attach(pid)

script = session.create_script(script)

device.resume(pid)
script.load()

sys.stdin.read()
