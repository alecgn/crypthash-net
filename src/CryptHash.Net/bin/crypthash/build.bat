dotnet publish -c Release -r win-x64 /p:PublishSingleFile=true /p:PublishTrimmed=true -o D:\dotnet-publish\crypthash-net\win-x64
dotnet publish -c Release -r win-x86 /p:PublishSingleFile=true /p:PublishTrimmed=true -o D:\dotnet-publish\crypthash-net\win-x86
dotnet publish -c Release -r win-arm /p:PublishSingleFile=true /p:PublishTrimmed=true -o D:\dotnet-publish\crypthash-net\win-arm
dotnet publish -c Release -r linux-x64 /p:PublishSingleFile=true /p:PublishTrimmed=true -o D:\dotnet-publish\crypthash-net\linux-x64
dotnet publish -c Release -r linux-arm /p:PublishSingleFile=true /p:PublishTrimmed=true -o D:\dotnet-publish\crypthash-net\linux-arm
dotnet publish -c Release -r osx-x64 /p:PublishSingleFile=true /p:PublishTrimmed=true -o D:\dotnet-publish\crypthash-net\osx-x64