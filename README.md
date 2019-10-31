# CryptHash.NET 
[![Build status (crypthash-net)](https://travis-ci.org/alecgn/crypthash-net.svg?branch=master)](https://travis-ci.org/alecgn/crypthash-net) [![Nuget version (CryptHash.Net)](https://img.shields.io/nuget/v/CryptHash.Net)](https://nuget.org/packages/CryptHash.Net) [![Nuget downloads (CryptHash.Net)](https://img.shields.io/nuget/dt/CryptHash.Net)](https://nuget.org/packages/CryptHash.Net) [![Tests status (crypthash-net)](https://img.shields.io/appveyor/tests/alecgn/crypthash-net)](https://ci.appveyor.com/project/alecgn/crypthash-net)

### A .NET multi-target Library and .NET Core Console Application utility for encryption/decryption and hashing.

The .NET Core console utility is designed to run in Windows, Linux and Mac, for text and files symmetric authenticated encryption/decryption, and text/files hashing. File checksum functionality is also available, you can verify the integrity of downloaded files from the internet with the source supplied hash.

The multi-target libray can be used in projects with any .NET implementation like **.NET Framework**, **.NET Core**, **Mono**, **Xamarin**, etc. Verify the .NET Standard compatibility table here: https://github.com/dotnet/standard/blob/master/docs/versions.md

Currently symmetric encryption algorithms are:  
* **AES 128 bits** in **CBC Mode** with **HMACSHA256 Authentication** and **Salt**, using the **Encrypt-then-MAC (EtM)** strategy.  
* **AES 192 bits** in **CBC Mode** with **HMACSHA384 Authentication** and **Salt**, using the **Encrypt-then-MAC (EtM)** strategy.
* **AES 256 bits** in **CBC Mode** with **HMACSHA384 Authentication** and **Salt**, using the **Encrypt-then-MAC (EtM)** strategy.
* **AES 256 bits** in **CBC Mode** with **HMACSHA512 Authentication** and **Salt**, using the **Encrypt-then-MAC (EtM)** strategy.
* **AES 256 bits** in **GCM Mode** with **Authentication** and **Associated Data** (**AEAD**).

Currently supported hash algorithms are:  
* **MD5**  
* **SHA1**  
* **SHA256**  
* **SHA384**  
* **SHA512**  
* **BCrypt**  
* **Argon2id**

Other encryption/hashing algorithms will be implemented in the future.

NuGet package: https://www.nuget.org/packages/CryptHash.Net

Compiled console utility and library binaries (self-contained / no framework dependent) for Windows (x86/x64/ARM), Linux (x64/ARM -> Raspberry Pi) and Mac (x64): https://github.com/alecgn/crypthash-net/releases/tag/v3.1.0.  When running on Linux or Mac, don't forget to navigate to the program's folder and "**chmod +x crypthash**".  
Additionally in the above release link there're a Windows x64 and a Linux x64 versions native compiled using CoreRT, wich runs much faster than the other versions.

**WARNING:** PER SEMANTIC VERSIONING, THE ABOVE RELEASE (3.x.x) IS NOT COMPATIBLE WITH PREVIOUS RELEASES (1.x.x and 2.x.x), AND AS SUCH MIGHT NOT PROPERLY DECRYPT DATA YOU ENCRYPTED WITH PREVIOUS VERSIONS.
From this version (3.x.x) onwards, any new implementations will be planned so as to maintain compatibility and stability. There should be no more breaking-changes, as the project's architecture and design are already well defined. If there is a need to make a breaking-change going forward then a method for properly decryting data you encryted with version 3.x.x will be provided.

Publish it yourself using the following dotnet client command-line:

>**dotnet publish -c Release -r \<RID\> /p:PublishSingleFile=true /p:PublishTrimmed=true**
--------------------------------------------------
**WINDOWS RIDs**

**Portable**
- win-x86
- win-x64

**Windows 7 / Windows Server 2008 R2**
- win7-x64
- win7-x86

**Windows 8 / Windows Server 2012**
- win8-x64
- win8-x86
- win8-arm

**Windows 8.1 / Windows Server 2012 R2**
- win81-x64
- win81-x86
- win81-arm

**Windows 10 / Windows Server 2016**
- win10-x64
- win10-x86
- win10-arm
- win10-arm64

--------------------------------------------------

**LINUX RIDs**

**ARM / Raspberry Pi (Raspbian)**
- linux-arm

**Portable**
- linux-x64

**CentOS**
- centos-x64
- centos.7-x64

**Debian**
- debian-x64
- debian.8-x64

**Fedora**
- fedora-x64
- fedora.24-x64
- fedora.25-x64 (.NET Core 2.0 or later versions)
- fedora.26-x64 (.NET Core 2.0 or later versions)

**Gentoo (.NET Core 2.0 or later versions)**
- gentoo-x64

**openSUSE**
- opensuse-x64
- opensuse.42.1-x64

**Oracle Linux**
- ol-x64
- ol.7-x64
- ol.7.0-x64
- ol.7.1-x64
- ol.7.2-x64

**Red Hat Enterprise Linux**
- rhel-x64
- rhel.6-x64 (.NET Core 2.0 or later versions)
- rhel.7-x64
- rhel.7.1-x64
- rhel.7.2-x64
- rhel.7.3-x64 (.NET Core 2.0 or later versions)
- rhel.7.4-x64 (.NET Core 2.0 or later versions)

**Tizen (.NET Core 2.0 or later versions)**
- tizen

**Ubuntu**
- ubuntu-x64
- ubuntu.14.04-x64
- ubuntu.14.10-x64
- ubuntu.15.04-x64
- ubuntu.15.10-x64
- ubuntu.16.04-x64
- ubuntu.16.10-x64

**Ubuntu derivatives**
- linuxmint.17-x64
- linuxmint.17.1-x64
- linuxmint.17.2-x64
- linuxmint.17.3-x64
- linuxmint.18-x64
- linuxmint.18.1-x64 (.NET Core 2.0 or later versions)

--------------------------------------------------

**macOS RIDs**

**macOS RIDs use the older "OSX" branding.**
- osx-x64 (.NET Core 2.0 or later versions, minimum version is osx.10.12-x64)
- osx.10.10-x64
- osx.10.11-x64
- osx.10.12-x64 (.NET Core 1.1 or later versions)
- osx.10.13-x64

--------------------------------------------------

**Complete RID LIST**
(https://docs.microsoft.com/en-us/dotnet/core/rid-catalog)
