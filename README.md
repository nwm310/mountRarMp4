# mountRarMp4

## Feature
Mount rar file to view mp4
even if some  *.part.rar is missing  or download incomplete

## RAR format
* file format : RAR4 or RAR5
* Compression : Store Only
* Encryption : NO Encryption  
or  
encryption without "Encrypt file names"  
(Instead of mp4 , rar will appear.  Open it with WinRAR and Extract with "keep broken extracted files" option)

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
**right click on these two dlls -> property -> unblock**
* mountRarMp4.ps1
* rar files  
for mp4 meta data , at least need **first part rar** and **last part rar**
IF **first part rar** is missing and **last part rar**(contins moov) exist , it will try to rebuild mp4 header

## Usage
* **put these files in the same folder**
* right click on mountRarMp4.ps1  ->  Run  with PowerShell
* if ps1  dll  rar  are not in the same folder  
try commandline  
.\mountRarMp4.ps1  -DllDir  *$Dlldir*  -rarDir  *$rarDir*

***
# mountRarMp4

## 功能
掛載RAR、看裡面的Mp4  
就算缺少分割檔或下載不完全，也可以看

## RAR格式(需符合以下條件)
* RAR版本 : RAR4 或 RAR5
* 壓縮方式 : 僅儲存
* 加密方式 : 沒有加密  
or  
一般加密(沒有檔名加密)  
掛載的結果會是RAR檔。  
用WinRAR打開它、解壓縮。「保留毀損的檔案」的選項要打勾

## 環境
* Windows
* Windows所在的磁碟機(通常是 C )的檔案系統 是 NTFS
* PowerShell 5.0
* 安裝[Pismo File Mount Audit Package](http://pismotec.com/download/)
* pfmclr_190.dll  和  pfmshim16_190.dll  
從[Pismo File Mount Developer Kit](http://pismotec.com/download/)取得正確的版本  
例如:  
pfmkit-190.zip\clr\pfmclr_190.dll  
pfmkit-190.zip\clr\win-x64\pfmshim16_190.dll  
**分別在這兩個dll 按右鍵 → 內容 → 解除封鎖**
* mountRarMp4.ps1
* rar檔  
Mp4檔頭、檔尾有重要資訊 , 至少要有 **第一檔** 和 **最後一檔**
如果沒有**第一檔** 而**最後一檔**存在(內含moov資訊)，會試著去重建檔頭

## 使用方法
* **把上述這些檔案放到同一個資料夾**
* mountRarMp4.ps1 -> 右鍵 ->  用 PowerShell 執行
* 如果 ps1  dll  rar  不在同一個資料夾  
可用命令行  
.\mountRarMp4.ps1  -DllDir  *$Dlldir*  -rarDir  *$rarDir*

