import frida
import sys

def call(expand):
    return f"""
    indentation_level += 1;
    var ret = {expand};
    indentation_level -= 1;
    """

def hookall(classpath, fun):
    return f"""
    Java.use("{classpath}").{fun}.overloads.forEach(overload => {{
        overload.implementation = function (...args) {{
            print(`Calling: {fun}(${{[...args].join(", ")}})`);
            
            var fun = this.{fun};
            {call("fun(...args)")}
            
            print("{fun} -> " + ret);
            
            return ret;
        }}
    }});
    """

# who called?
def stacktrace():
	return f"""
	{call('Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Exception").$new())')}
	"""

change_telemetry = f"""
    var TelephonyManager = Java.use("android.telephony.TelephonyManager");

    // make mcc = 0000000000000000
	TelephonyManager.getDeviceId.overload().implementation = function () {{
        {stacktrace()}

		return "0000000000000000";
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
        """ + change_telemetry
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
