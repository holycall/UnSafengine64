# UnSafengine64
Unpack Safengine 2.3.x ~ 2.4.0 protected executables. 

## Prerequisite
[Intel Pin 3.18 (Windows MSVC)](https://software.intel.com/content/www/us/en/develop/articles/pin-a-dynamic-binary-instrumentation-tool.html).

Extract Pin 3.18 into "C:\pin". 

## Build
Requires Visual Studio 2019 or higher. 
Build two projects. 
A pintool dll file and a CUI executable will be copied into "C:\pintool". 

## Usage 
The following command will unpack a safengine protected executable. 
```
UnSafengine64.exe -deob .\mb64_se.exe
```
