import frida
import sys

def hookall(classpath, fun):
    return f"""
    Java.use("{classpath}").{fun}.overloads.forEach(overload => {{
        overload.implementation = function (...args) {{
            console.log(`{fun}(${{[...args].join(", ")}})`);
            var ret = this.{fun}(...args);
            console.log(ret);
            return ret;
        }}
    }});
    """

script = """
setTimeout(function () {
	Java.perform(function () {
        """ + hookall("com.foobar.Foo", "bar")
            + hookall("com.foobar.Foo", "kar")
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
