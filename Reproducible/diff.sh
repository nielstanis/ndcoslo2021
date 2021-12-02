#!/bin/bash
rm t1 t2
dotnet build app
dotnet build app2
strings app/bin/Debug/net6.0/app.dll > t1 
strings app2/bin/Debug/net6.0/app.dll > t2 
code --diff t1 t2
