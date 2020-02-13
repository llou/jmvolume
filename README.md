# jmvolume

This is a Python module that wraps standard Linux cryptografic tools to create
and manage encrypted volumes and their keys. Using cryptsetup can be a tedious
job as the commands are intrincate and you have to do it with a lot of care of
doing it the right way because one mistake can result in the loss o secrecy or
worst with the irrevocable loss of information.

This code is supoused to be run with root privileges and to manage sensitive
data, this is why I tried to keep it as symple as posible, so any experienced
admin can check what it does in a few minutes.

This project is in its alpha stage so use it with care.
