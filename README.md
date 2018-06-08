# mountRarMp4

## Feature
Mount rar file to view mp4
even if some  *.part.rar is missing  or download incomplete

## RAR format
* file format : RAR4 or RAR5
* Compression : Store Only
* Encryption : NO Encryption  
or  
RAR4 encryption without "Encrypt file names"  
(rar will appear  instead of mp4 ,  Open it with WinRAR and Extract with "keep broken extracted files" option)

## Environment
* Windows
* File System of System Drive(usually is C ) is NTFS
* PowerShell 5.0
* [Pismo File Mount Audit Package](http://pismotec.com/download/)  installed
* pfmclr_190.dll  and  pfmshim16_190.dll  
get correct version from [Pismo File Mount Developer Kit](http://pismotec.com/download/)  
for example :  
pfmkit-190.zip\clr\pfmclr_190.dll  
pfmkit-190.zip\clr\win-x64\pfmshim16_190.dll
* mountRarMp4.ps1
* rar files  
for mp4 meta data , at least need **first part rar** and **last part rar**

## Usage
* **put these files in the same folder**
* right click on mountRarMp4.ps1  ->  Run  with PowerShell
* if ps1  dll  rar  are not in the same folder  
try commandline  
mountRarMp4.ps1  -DllDir  *$Dlldir*  -rarDir  *$rarDir*

* only these extension name will appear  
mp4  avi  mpg mkv  jpg  
for more extension name , you can edit  mountRarMp4.ps1  
$Mp4ext = '\.(mp4|avi|mpg|mkv|jpg)$'
