#!/bin/bash
rm t1 t2
dotnet build app -c Release
dotnet build app2 -c Release
strings app/bin/Release/net6.0/app.dll > t1 
strings app2/bin/Release/net6.0/app.dll > t2 
code --diff t1 t2
