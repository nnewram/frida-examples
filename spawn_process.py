import frida
import sys

device = frida.get_usb_device()

pid = device.spawn(["com.foobar"])

session = device.attach(pid)

with open("script.js") as s:
    script = session.create_script(s.read())

device.resume(pid)
script.load()
sys.stdin.read()
