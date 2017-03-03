
import os
import threading
from opentimestamps.calendar import RemoteCalendar


def call(rcal, val):
    rcal.submit(val)


cal = RemoteCalendar("https://eth.ots.eternitywall.com")
urandom = os.urandom(32)
print(bytes.hex(urandom))
urandom2 = os.urandom(32)
print(bytes.hex(urandom2))

t = threading.Thread(target=call, args=(cal, urandom))
t2 = threading.Thread(target=call, args=(cal, urandom2))
t.start()
t2.start()


