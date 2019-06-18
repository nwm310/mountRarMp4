param($DllDir ='.', $rarDir = '.')
#==================Edit Area================
$driveLetter = 'Z'
$MoutName = "thanks for sharing"

#============Check PS 5.0  and DLLs==============
if ($host.Version.Major -lt 5){echo 'NEED PowerShell 5.0';pause;exit}

cd -literal $PSScriptRoot

cd -literal $DllDir
$dllfiles = @(gi pfmclr_[0-9][0-9][0-9].dll , pfmshim16_[0-9][0-9][0-9].dll )

if ( $dllfiles.length -ne 2 ){
    echo 'Need  DLLs or too many DLLs' ;pause;exit
}else{
    Add-Type  -Path  $dllfiles[0]
}

if ( ! ('pfm' -as [type])){
    echo "Dlls are not loaded"
    echo 'right click on these two dlls -> property -> unblock'
    pause;exit
}

$pfmApi = $null
$err = [Pfm]::ApiFactory( [ref] $pfmApi)
if($err -ne 0){echo '"Pismo File Mount Audit Package" was not installed';pause;exit}



#===============Finding RAR Files==================
#Finding  Multi Volume RAR
cd -literal $rarDir
$RarGroup = dir *.part*.rar | sort |?{$_.name -match '(.*)\.part(\d+)\.rar$' } | 
            group -prop {$matches[1] + '/' + $matches[2].length}


#IF not find Multi Volume RAR , then find single RAR
#Only first set of Multi Volume RAR  or first single RAR will be process
if ( $RarGroup -ne $null ) { 
    $Rar = $RarGroup[0].group
}else{
    $Rar = ( dir *.rar  -file  -ex *.part*.rar )[0]
}

#IF RAR not found
if ( $Rar -eq $null ) {echo 'RAR not found' ;pause;exit}


#====================Functions=====================
function getVint( [ref]$bPos ){
    $bPosOld = $bPos.Value

    while ( $buffer[$bPos.Value++] -band 0x80 ) {}

    if ( ($bPos.Value - $bPosOld) -gt 9 ){throw 'Vint : too many bytes'}  # 7 * 9 = 63

    $data = $n = 0

    while ( $bPosOld -lt $bPos.Value ) {
        [uint64]$d = $buffer[$bPosOld++] -band 0x7F
        $data +=  $d -shl  (7 * $n++)
    }
    return $data
}

function getVint2 ( $n ){
    [byte[]]$databyte = @()
    while ($n){
        $a = $n -band 0x7F
        $n = $n -shr 7
        if ( $n ){ $a += 0x80 }
        $databyte += $a
    }
    return $databyte
}

function RarName4($buffer,$namePos,$nameSize){
    $nameEnd = $namePos + $nameSize

    #search zero between usual and encoded Unicode name
    for ($i = $namePos ; $i -lt $nameEnd ; $i++){
        if ($buffer[$i] -eq 0 ) {break}
    }

    #only ansi name
    if ($i -eq $nameEnd ){
        return [System.Text.Encoding]::Default.GetString($buffer,$namePos,$nameSize)
    }

    #===============get unicode name===============
    $nameAnsiEnd = $i
    $i++
    $j = $namePos

    #HighByte of two bytes of Unicode
    $HighByte = $buffer[$i++]
    [byte]$FlagBits = [byte]$Flags = 0
    $Mp4FullName=$null

    :out
    While ($i -lt $nameEnd){
        #every 4 times , $FlagBit become 0 , read a byte into $Flags
        #There are 4 flags(2bit)  in  $Flags
        if ($FlagBits -eq 0){
            $Flags = $buffer[$i++]
            $FlagBits = 8
        }

        switch ($Flags -shr 6){
            0{#ascii stored in encoded area
                if ($i -ge $nameEnd){break out}
                $Mp4FullName += [System.Text.Encoding]::Default.GetString($buffer[$i++])
                $j++
            }

            1{# one byte of unicode in encoded area
                if ($i -ge $nameEnd){break out}
                $Mp4FullName += [System.Text.Encoding]::Unicode.GetString(@($buffer[$i++],$HighByte))
                $j++
            }

            2{# two bytes of unicode in encoded area
                if ($i+1 -ge $nameEnd){break out}
                $Mp4FullName += [System.Text.Encoding]::Unicode.GetString(@($buffer[$i],$buffer[$i+1]))
                $i += 2
                $j++
            }

            3{#ascii stored in ansi area
                if ($i -ge $nameEnd){break out}
                
                #length of ascii to be read
                $L = $buffer[$i++]
                if ( ($L -band 0x80) -ne 0){
                    if ($i -ge $nameEnd){break out}
                    $Correction = $buffer[$i++]

                    for ($L = ($L -band 0x7F)+2 ;$L -gt 0 -and $j -lt $nameAnsiEnd ; $L-- ,$j++){
                        $Mp4FullName += [System.Text.Encoding]::Unicode.GetString(
                            @( (($buffer[$j] + $Correction) -band 0xFF) , $HighByte )
                        )
                    }
                }else{
                    for ($L += 2 ;$L -gt 0 -and $j -lt $nameAnsiEnd ; $L-- ,$j++){
                        $Mp4FullName += [System.Text.Encoding]::Default.GetString($buffer[$j])
                    }

                }
            }
        }#end of switch
        $Flags = $Flags -shl 2
        $FlagBits -=2

    }#end of while

    return $Mp4FullName
}

$getHeader4 = {
    param($fs , $buffer , $bufferPos)

    $HeadTypeName = $HeadEncrypt = $HeadEnd = $PackSize = $Mp4Size =
    $Mp4FullName = $PackType = $FileEncrypt = $FullPack = $Compression = $null

    $n = $fs.read($buffer , $bufferPos , 7)
    if ( $n -lt 7 ) { throw 'filesize is too small'  }

    $HeadType = $buffer[$bufferPos + 2]
    $HeadFlag = [BitConverter]::ToUInt16($buffer , $bufferPos + 3 )
    $HeadSize = [BitConverter]::ToUInt16($buffer , $bufferPos + 5 )

    if ($HeadSize -eq 0 ){throw 'header error'}

    $n = $HeadSize - 7
    if ( $n -gt 0 ) {
        $n1 = $fs.read($buffer , $bufferPos + 7 , $n )
        if ( $n1 -lt $n ) { throw 'filesize is too small' }
    }

    $HeadEnd = $bufferPos + $HeadSize

    #=============after reading  header into buffer===============
    switch ($HeadType){
        0x73{
            $HeadTypeName = 'Main'

            if (  $HeadFlag -band 0x80 ){ 
                $HeadEncrypt = $true
            }else{
                $HeadEncrypt = $false
            }
        }

        0x74{
            $HeadTypeName = 'File'
            
            $PackSize = [BitConverter]::ToUInt32($buffer, $bufferPos + 7 )
            $Mp4Size  = [BitConverter]::ToUInt32($buffer, $bufferPos + 11 )


            #if file size too big 
            if  ( $HeadFlag -band 0x100 ){
                $HighSize = [BitConverter]::ToUInt32($buffer, $bufferPos + 32 )
                $PackSize += ([uint64]$HighSize -shl 32 )

                $HighSize = [BitConverter]::ToUInt32($buffer, $bufferPos + 36 )
                $Mp4Size += ([uint64]$HighSize -shl 32 )

                $namePos = $bufferPos + 40
            }else{
                $namePos = $bufferPos + 32
            }

            #get file name
            $nameSize = [BitConverter]::ToUInt16($buffer , $bufferPos + 26 )
            $Mp4FullName = RarName4  $buffer  $namePos  $nameSize
            
            #normal pack ? first pack  ?  middle pack ? last pack ?
            $PackType = $HeadFlag -band 3

            $FullPack = $Mp4Size
            if ($HeadFlag -band 4){
                $FileEncrypt = $true
                $FullPack += 16 - ($Mp4Size % 16)
            }

            if ( $buffer[$bufferPos + 25] -ne 0x30) { $Compression = $true ;break }

            #================edit header in buffer if file is encrypted==============
            #normal pack or first pack ,  if encrypted
            if ( ($PackType -eq 0 -or $PackType -eq 2) -and $FileEncrypt ) {

                #only get 11101110 ; some bit clear ;
                # clear Volume attribute and New volume naming scheme ('volname.partN.rar')
                $buffer[10] = $buffer[10] -band 0xEE

                #only get 11111110 ; some bit clear ; clear First volume 
                $buffer[11] = $buffer[11] -band 0xFE

                #only get 11111101 ; some bit clear ; clear continued in next volume
                #edit headflag
                $buffer[$bufferPos + 3] = $buffer[$bufferPos + 3] -band 0xFD

                $fpbyte = [BitConverter]::GetBytes([uint64]$FullPack)

                #edit PackSize
                [array]::copy($fpbyte,0,$buffer, $bufferPos + 7 , 4 )
                if  ( $HeadFlag -band 0x100 ){
                    #edit HighSize
                    [array]::copy($fpbyte,4,$buffer, $bufferPos + 32 , 4 )
                }                
            }#end of if

        }#end of 0x74

        default{
            #other block
            if ($HeadFlag -band 0x8000){ 
                $n = [BitConverter]::ToUInt32($buffer, $bufferPos + 7)
                if ( ($fs.Position + $n ) -gt $fs.length ){throw 'file size too small'}

                $fs.Position += $n
            }

        }#end of default
    }#end of switch
    return $HeadTypeName , $HeadEncrypt , $HeadEnd , $PackSize , $Mp4Size ,
    $Mp4FullName , $PackType , $FileEncrypt , $FullPack , $Compression
}

$getHeader5 = {
    param($fs , $buffer , $bufferPos)

    $HeadTypeName = $HeadEncrypt = $HeadEnd = $PackSize = $Mp4Size =
    $Mp4FullName = $PackType = $FileEncrypt = $FullPack = $Compression = $null

    $bPos = $bufferPos

    #Read CRC
    $n = $fs.read($buffer , $bPos , 4)
    if ( $n -lt 4 ) { throw 'file size too small' }

    $bPos += 4
    $HeadSizePos  = $bPos

    #Read HeadSize
    $n = $fs.read($buffer , $HeadSizePos  , 3)
    if ( $n -lt 3 ) { throw 'file size too small' }

    $HeadSize = getVint ([ref]$bPos)
    if ($HeadSize -eq 0 ){throw 'header error'}
    $HeadSizePosEnd  = $bPos
    

    $fs.position -=  3 - ( $HeadSizePosEnd - $HeadSizePos )

    #Read Header into buffer
    $n = $fs.read($buffer , $HeadSizePosEnd , $HeadSize)
    if ( $n -lt $HeadSize ) { throw 'file size too small' }
    $HeadEnd = $HeadSizePosEnd + $HeadSize

    #=============after reading  header into buffer===============
    #Read HeadType  HeadFlag
    $HeadType = getVint ([ref]$bPos)

    $HeadFlag = getVint ([ref]$bPos)

    switch -w ($HeadType){
        #assume that data area is not exist
        1{	$HeadTypeName = 'Main' }

        [23]{	# File header or Service header
            #Extra area size
            if ( $HeadFlag -band 1 ) {getVint ([ref]$bPos) > $null 
                                $extraSizeEnd = $bPos
            }

            #Data area size
            $PackSize = 0
            if ( $HeadFlag -band 2 ) {
                $PackSize = getVint ([ref]$bPos)
            }

            if ( $_ -eq 2 ) {
                $HeadTypeName = 'File'
            }else{
                #service header
                if ( ($fs.Position + $PackSize ) -gt $fs.length ){throw 'file size too small'}
                $fs.Position += $PackSize
                break
            }
            $packSizeEnd = $bPos

            #File flags
            $FileFlags = getVint ([ref]$bPos)

            #Unpacked size
            $Mp4Size  = getVint ([ref]$bPos)

            #Attributes
            getVint ([ref]$bPos) > $null

            #mtime
            if ($FileFlags -band 2) {$bPos +=4}

            #Data CRC32
            if ($FileFlags -band 4) {$bPos +=4}

            #Compression information
            if (  (getVint ([ref]$bPos)) -band 0x0380){ $Compression = $true }

            #Host OS
            getVint ([ref]$bPos) > $null

            #file name length
            $nameSize = getVint ([ref]$bPos)

            #get file name
            $Mp4FullName=[System.Text.Encoding]::UTF8.GetString($buffer,$bPos,$nameSize)
            $bPos += $nameSize

            #normal pack ? first pack  ?  middle pack ? last pack ?
            $PackType = ($HeadFlag -shr 3) -band 3

            $FullPack = $Mp4Size

            #encrypt ?  read extra area
            $FileEncrypt = $false
            while ( $bPos -lt $HeadEnd ){
                $recordSize = getVint ([ref]$bPos)
                if ( $bPos -ge $HeadEnd ){break}
                                
                $recordEnd = $bPos + $recordSize
            
                #record type
                if ( ( getVint ([ref]$bPos) ) -eq 1 ){
                    $FileEncrypt = $true
                    $FullPack += 16 - ($Mp4Size % 16)
                    break
                }else{
                    $bPos = $recordEnd
                }
            }#end of while
            #================edit header in buffer if file is encrypted============
            #normal pack or first pack ,  if encrypted
            if ( ($PackType -eq 0 -or $PackType -eq 2) -and $FileEncrypt ) {
                                                    #size , type , flags , Archive flags
                [byte[]]$editBuffer = $buffer[0..11] + 3,1,0,0  +
                                    $buffer[$bufferPos .. ($bufferPos+3) ]
                
                #type,flags,extraSize
                [byte[]]$data1 = $buffer[$HeadSizePosEnd .. ($extraSizeEnd -1)  ]
                $data1[1] = 3  #flags
                $data1 += getVint2 $FullPack  #data size
                $data1 += $buffer[$packSizeEnd .. ($HeadEnd -1) ] # after data size

                $editBuffer += (getVint2 $data1.Length) + $data1
                $HeadEnd = $editBuffer.Length

                [array]::copy($editBuffer , 0 , $buffer , 0 , $HeadEnd )
            }#end of if

        }#end of [23]

        4{	$HeadEncrypt = $true }

    }# end of switch
    return $HeadTypeName , $HeadEncrypt , $HeadEnd , $PackSize , $Mp4Size ,
    $Mp4FullName , $PackType , $FileEncrypt , $FullPack , $Compression
}
#-----------------------------------------------------
$nextRarN = $null
$Mp4Info = @()
$Mp4InfoALL = @()
$Mp4NameList = @()

$buffer = new-object byte[](20kb)

$Rar | %{
    trap{ $fs.close() ; return }	
    
    $fs = $_.OpenRead()
    
    #=============check RAR signature============
    $n = $fs.read($buffer , 0 , 8)
    if ( $n -lt 8 ) {throw "$_ file is too small"}

    if ( [BitConverter]::ToString($buffer,0,7) -eq '52-61-72-21-1A-07-00' ){
        # RAR4
        $fs.Position = 7
        $rarVer = 4   ;  $bufferPos = 7
        $getHeader = $getHeader4
        
    } elseif ( [BitConverter]::ToString($buffer,0,8) -eq '52-61-72-21-1A-07-01-00' ){
        # RAR5
        $rarVer = 5   ;  $bufferPos = 8
        $getHeader = $getHeader5

    } else {
        $fs.close(); echo "$_ is not RAR";return
    }
    
    #=============read main header===============
    $result = & $getHeader $fs  $buffer  $bufferPos
    #$HeadTypeName , $HeadEncrypt , $HeadEnd , $PackSize , $Mp4Size ,
    #$Mp4FullName , $PackType , $FileEncrypt , $FullPack , $Compression
    
    $HeadTypeName , $HeadEncrypt , $bufferPos = $result[0..2]

    if ($HeadEncrypt){ $fs.close();echo " can't process files which `"Encrypt file names`"";pause;exit }
    
    if ($HeadTypeName -ne 'Main') {$fs.close(); echo "$_ header error";return}

    #==============read file header==============
    while ($fs.Position -lt $fs.length ){
        $result = & $getHeader $fs  $buffer  $bufferPos

        $HeadTypeName , $HeadEncrypt , $HeadEnd , $PackSize , $Mp4Size ,
        $Mp4FullName , $PackType , $FileEncrypt , $FullPack , $Compression = $result[0..9]

        if ( $HeadTypeName -ne 'File' ) { continue }

        $a = $_

        #=============previous pack and current pack are parts of the same file ? ==============
        switch -w  ( $PackType ) {
                #previous pack does not exist
               *{ if ( $nextRarN -eq $null ) {break} }

               #middle pack or last pack 
               #previous pack and current pack are  parts of the same file
            [13]{ if ( $Mp4FullName_now -eq $Mp4FullName -and
                   $Mp4Size_now -eq $Mp4Size) {break}
            }

            *{#previous pack and current pack are not  parts of the same file
                if ( $Mp4Info[0] -ne $null ){
                    echo "$Mp4FullName_now`nincomplete"
                    $Mp4Info[0].Mp4Size = $Mp4offset
                    $Mp4NameList += $Mp4Name
                    $Mp4InfoALL+= ,$Mp4Info
                }else{
                    $Mp4Info | %{
                        if ( $_.fs -ne $null ){ $_.fs.close() }
                    }
                }
                
                $Mp4Info =  @()
                $nextRarN = $null
            }
        }#end of switch
        #=====================process current pack=====================================
        switch -w  ( $PackType ) {
            {$nextRarN  -eq $null }{
                #skip files which are compressed
                if ( $compression ) { echo "$Mp4FullName`ncan't process compressed file";break}
                
                #skip filesize -eq 0   or folder
                if ( $Mp4Size -eq 0 ){break }

                
                if ( $_ -like '[13]' ) {
                    if ( $Mp4FullName -notmatch '\.mp4$' -or $FileEncrypt ) { break }
                    $Mp4Info += $null,$null
                }

                $Mp4offset = 0
                if ($_ -eq 1 ){ $Mp4offset = $FullPack - $PackSize }
                if ($_ -eq 3 ){ $midPackSize = $PackSize }

                #check duplicate names
                $Mp4Name = split-path  $Mp4FullName  -leaf
                
                if ( $FileEncrypt ){ $Mp4Name += '.rar' }
                                                
                $n = 1
                $Mp4BaseName = [IO.Path]::GetFileNameWithoutExtension($Mp4Name)
                $Mp4ExtName = [IO.Path]::GetExtension($Mp4Name)
                while ($Mp4NameList -contains $Mp4Name){
                    $Mp4Name = $Mp4BaseName + '-' + $n + $Mp4ExtName
                    $n++
                }

                # if encrypt , add RAR signature and main header to Mp4info
                if ( $_ -like '[02]' -and $FileEncrypt ){

                    $Mp4Info += @{fs = new-object IO.MemoryStream
                        Mp4offset = $Mp4offset	; length = $HeadEnd ; RARoffset = 0
                        Mp4Name = $Mp4Name ; Mp4Size = $HeadEnd + $FullPack}

                    $Mp4Info[0].fs.write($buffer , 0 , $HeadEnd)

                    $Mp4offset += $HeadEnd

                    echo 'Use WinRAR to Open and Extract with "keep broken extracted files" option'
                }
                #======================================================================
                $nEmpty = 0
                #file is incomplete ?
                if (  ($fs.Position + $PackSize) -gt $fs.length  ) {
                    $nEmpty = $fs.Position + $PackSize - $fs.length
                }

                $Mp4Info += @{fs = $a.OpenRead() ; Mp4offset = $Mp4offset
                    RARoffset = $fs.Position ; length = $PackSize - $nEmpty
                    Mp4Name = $Mp4Name ; Mp4Size = $FullPack}

                $Mp4offset += $PackSize - $nEmpty

                #=========================================================
                if ( $_ -like '[23]' ) { # first pack or middle pack
                    #next RAR file number
                    $nextRarN = 1 + $( $a.basename -replace '.*part','' )
                    $Mp4FullName_now = $Mp4FullName
                    $Mp4Size_now = $Mp4Size
                    break
                } 
            } # end of $nextRarN  -eq $null

            { $nextRarN  -ne $null }{
                [int]$nPart = $a.basename -replace '.*part',''

                # missing *.part.rar  or previous pack is not complete
                if ( $nPart -gt $nextRarN  -or  $nEmpty -gt 0 ){
                    if ($_ -eq 3){ # middle pack						
                        $nEmpty = $PackSize * ( $nPart - $nextRarN ) +  $nEmpty
                        $Mp4Info += @{fs = $null ; Mp4offset = $Mp4offset;length = $nEmpty}
                        $Mp4offset += $nEmpty
                    }else{ # last pack
                        if ( $Mp4Info[0] -ne $null ){
                            $nEmpty = $Mp4Info[0].Mp4Size -$PackSize - $Mp4offset
                            $Mp4Info += @{fs = $null ; Mp4offset = $Mp4offset;length = $nEmpty}
                            $Mp4offset = $Mp4Info[0].Mp4Size - $PackSize
                        }else{
                            $nEmpty = $midPackSize * ( $nPart - $nextRarN ) +  $nEmpty
                            $Mp4Info += @{fs = $null ; Mp4offset = $Mp4offset;length = $nEmpty}
                            $Mp4offset = $FullPack - $PackSize
                        }
                        
                    }
                }

                if ( $_ -eq 1 -and $Mp4Info[0] -eq $null ) { $Mp4offset = $FullPack - $PackSize }
                $nEmpty = 0
                #file is incomplete ?
                if (  ($fs.Position + $PackSize) -gt $fs.length  ) {
                    $nEmpty = $fs.Position + $PackSize - $fs.length
                }

                $Mp4Info += @{fs = $a.OpenRead() ; Mp4offset = $Mp4offset
                    RARoffset = $fs.Position ; length = $PackSize - $nEmpty}

                $Mp4offset += $PackSize - $nEmpty
                    
                #middle pack
                if ($_ -eq 3){ $nextRarN = $nPart + 1 ; break }
            } #end of $nextRarN  -ne $null 

            [01]{
                if ($Mp4Info[0] -eq $null ){
                    write-host searching moov
                    $time1=get-date
                    # find moov
                    $searchSize = 20MB
                    if ( $FullPack -lt $searchSize ){ $searchSize = $FullPack }

                    $buffer2 = new-object byte[]( $searchSize )
                    $buffer2End = $searchSize - $nEmpty ; $i = $Mp4Info.length -1
                    while( $buffer2End -gt 0 ){
                        if ( $Mp4Info[$i].fs -eq $null ) { break }

                        $L = 0
                        if ( $Mp4Info[$i].length -gt $buffer2End ){
                            $L = $Mp4Info[$i].length - $buffer2End
                        }
                        $Mp4Info[$i].fs.position = $Mp4Info[$i].RARoffset + $L
                        $buffer2End -= $Mp4Info[$i].length - $L
                        [void]$Mp4Info[$i].fs.read( $buffer2 , $buffer2End  ,$Mp4Info[$i].length - $L )
                        $i--
                    }
                    
                    $buffer2start = $buffer2End
                    #search range : $buffer2start  to ($searchSize - $nEmpty)
                    [byte[]]$pattern = 0x6D ,0x6F ,0x6F ,0x76 ,0 ,0 ,0 ,0x6C ,0x6D ,0x76 ,0x68 ,0x64
                    
                    if ( $buffer2start -lt 0 -or
                    $searchSize - $nEmpty - $buffer2start -lt $pattern.length ){
                        $moovPos = -1
                    }else{
                        [byte[]]$B = @(12) * 256
                        ($pattern.Length - 1) .. 1 | %{ $B[ $pattern[$_] ] = $_ }
                        [byte[]]$G = 1,8 + @(12) * 10

                        $buffer2Pos = $searchSize - $nEmpty  - $pattern.length

                        while ( $buffer2Pos -ge $buffer2start ){
                            for ($i = 0 ; $i -lt $pattern.length -and $pattern[$i] -eq $buffer2[$buffer2Pos + $i] ; $i++){}
                        
                            if ($i -eq $pattern.length){
                                break
                            }else{
                                if ( $i -eq 0 ){
                                    $buffer2Pos -= $B[  $buffer2[$buffer2Pos] ]
                                }else{
                                    $buffer2Pos -= $G[ $i ]
                                }
                            }
                        }#end of while 
                        
                        if ($buffer2Pos -lt $buffer2start ){
                            $moovPos = -1 ; write-host moov not found
                        }else{
                            $moovPos = $FullPack - $searchSize + $buffer2Pos - 4
                            write-host moov found
                        }
                        $buffer2 = $null
                        $time2=get-date
                        write-host ($time2-$time1)
                    }# end of if
                    #========================after searching========================

                    if ( $moovPos -eq -1 ) { # moov not find
                        $Mp4Info | %{
                            if ( $_.fs -ne $null ){ $_.fs.close() }
                        }
                        $Mp4Info =  @()
                        $nextRarN = $null
                        break
                    }else{ #moov found
                        [byte[]]$ftypData = 0,0,0,0x20,0x66,0x74,0x79,0x70,0x69,0x73,0x6F,0x6D,0,0,
                                            2,0,0x69,0x73,0x6F,0x6D,0x69,
                                            0x73,0x6F,0x32,0x61,0x76,0x63,0x31,0x6D,0x70,0x34,0x31
                        $mdatSize = $moovPos - $ftypData.Length
                        if ( $mdatSize -lt 4GB ){
                            $arr = [BitConverter]::GetBytes([uint32]$mdatSize)
                            [array]::Reverse($arr)
                            [byte[]]$mdatHead = $arr + 0x6D,0x64,0x61,0x74
                        }else{
                            $arr = [BitConverter]::GetBytes([uint64]$mdatSize)
                            [array]::Reverse($arr)
                            [byte[]]$mdatHead = 0,0,0,1 + 0x6D,0x64,0x61,0x74 + $arr
                        }
                        
                        $L = $ftypData.Length + $mdatHead.length
                        $Mp4Info[0] = @{fs = new-object IO.MemoryStream
                            Mp4offset = 0 ; length = $L ; RARoffset = 0
                            Mp4Name = $Mp4Name ; Mp4Size = $FullPack}

                        $Mp4Info[0].fs.write($ftypData , 0 , $ftypData.Length)
                        $Mp4Info[0].fs.write($mdatHead , 0 , $mdatHead.Length)
                        
                        $Mp4Info[1] = @{fs = $null ; Mp4offset = $L ; length = $null }
    
                        if ( $Mp4Info.Length -gt 3 ){
                            $L = $FullPack - $PackSize - ( $Mp4Info[-2].Mp4offset + $Mp4Info[-2].length )
                            2 .. ($Mp4Info.Length - 2) | %{ $Mp4Info[$_].Mp4offset += $L }
                        }
                        $Mp4Info[1].length = $Mp4Info[2].Mp4offset - $Mp4Info[1].Mp4offset
                    }#end of moov found
                }# end of if $mp4Info[0]
                
                if ( $nEmpty -gt 0 ) {
                    echo "$Mp4FullName`nincomplete"
                    $Mp4Info[0].Mp4Size = $Mp4offset
                }

                $Mp4NameList += $Mp4Name
                $Mp4InfoALL+= ,$Mp4Info
                $Mp4Info = @()
                $nextRarN = $null
            }#end of [01]
        }# end of switch
        #========Is this block  the last block need to be processed in this file ? =========
        switch -w  ( $PackType ) {
            #First pack  or Middle pack
            #After this block , no content in this  file need to be processed
            [23]{ $fs.close() ; return }

            [01]{ # normal pack  or last pack
                if (  ($fs.Position + $PackSize) -gt $fs.length  ) {
                    $fs.close() ; return
                }else{
                    $fs.Position += $PackSize
                }
            }
        } # end of switch
    } # end of while
$fs.close()  ; $buffer = $null
}
if ( $nextRarN -ne $null ) {
    if ( $Mp4Info[0] -ne $null ){
        echo "$Mp4FullName_now`nincomplete"
        $Mp4Info[0].Mp4Size = $Mp4offset
        $Mp4NameList += $Mp4Name
        $Mp4InfoALL+= ,$Mp4Info
    }else{
        $Mp4Info | %{
            if ( $_.fs -ne $null ){ $_.fs.close() }
        }
    }
    $Mp4Info =  @()
    $nextRarN = $null
}
if ( $Mp4InfoALL.length -eq 0) {echo 'mp4 not found';pause;exit}
#====================================================================================
$RarVolumeType=@'
#Learn from   Pismo File Mount Development Kit   samples\hellofs_cs\hellofs.cs
class RarVolume: Pfm+FormatterDispatch{
    $openRoot
    $openMp4s
    $Mp4InfoAll
RarVolume(){
    $this.openRoot = new-object Pfm+OpenAttribs -prop @{
                openSequence = 1 ; accessLevel = [Pfm]::accessLevelReadData;
                attribs = new-object Pfm+Attribs -prop @{fileType = [Pfm]::fileTypeFolder ; fileId = 2 }}


}

[void] Dispose(){}

[void] Open( [Pfm+MarshallerOpenOp]$op){
    $perr = 0
    $existed = $false
    $parentFileId = 0
    $endName = $null
    $openAttribs =  new-object Pfm+OpenAttribs
    if ($op.NameParts().Length -eq 0){
        if ($this.openRoot.openId -eq 0) {$this.openRoot.openId = $op.NewExistingOpenId() }
        $existed = $true
        $openAttribs = $this.openRoot

    }elseif($op.NameParts().Length -eq 1){
            for ($i=0; $i -lt $this.Mp4InfoAll.length;$i++){
                if($op.NameParts()[0].ToLowerInvariant() -eq $this.Mp4InfoAll[$i][0].Mp4Name.ToLowerInvariant()){
                    if ($this.openMp4s[$i].openId -eq 0) {$this.openMp4s[$i].openId = $op.NewExistingOpenId() }
                    $existed = $true
                    $endName = $this.Mp4InfoAll[$i][0].Mp4Name
                    $openAttribs = $this.openMp4s[$i]
                    break
                }
            }
            if ($i -eq $this.Mp4InfoAll.length){$perr = [Pfm]::errorNotFound}

    }else{  $perr = [Pfm]::errorParentNotFound }

    if($perr -eq [Pfm]::errorNotFound -and $op.CreateFileType() -ne 0)
    {	$perr = [Pfm]::errorAccessDenied          }

    $op.Complete( $perr, $existed, $openAttribs, $parentFileId, $endName, 0, $null, 0, $null)
}

[void] Replace( [Pfm+MarshallerReplaceOp]$op){
    $op.Complete( [Pfm]::errorAccessDenied, $null, $null)
}

[void] Move( [Pfm+MarshallerMoveOp] $op){
    $op.Complete( [Pfm]::errorAccessDenied, $false, $null, 0, $null, 0, $null, 0, $null)
}

[void] MoveReplace( [Pfm+MarshallerMoveReplaceOp] $op){
    $op.Complete( [Pfm]::errorAccessDenied)
}

[void] Delete( [Pfm+MarshallerDeleteOp] $op){
    $op.Complete( [Pfm]::errorAccessDenied)
}

[void] Close( [Pfm+MarshallerCloseOp] $op){
    $op.Complete( [Pfm]::errorSuccess)
}

[void] FlushFile( [Pfm+MarshallerFlushFileOp] $op){
    $perr = 0
    $openAttribs = new-object Pfm+OpenAttribs
    if ( $op.FileFlags() -ne [Pfm]::fileFlagsInvalid -or
             $op.Color() -ne [Pfm]::colorInvalid -or
             $op.CreateTime() -ne [Pfm]::timeInvalid -or
             $op.WriteTime() -ne [Pfm]::timeInvalid){

        $perr = [Pfm]::errorAccessDenied

    }elseif ($op.OpenId() -eq $this.openRoot.openId){

        $openAttribs = $this.openRoot

    }else{ for ($i=0; $i -lt $this.openMp4s.length;$i++){
            if ($op.OpenId() -eq $this.openMp4s[$i].openId){
                $openAttribs = $this.openMp4s[$i]
            }
        }
        if ($i -eq $this.openMp4s.length){$perr = [Pfm]::errorNotFound}
    }

    $op.Complete( $perr, $openAttribs, $null)
}

[void] List( [Pfm+MarshallerListOp] $op){
    $perr = 0
    if ($op.OpenId() -ne $this.openRoot.openId){
        $perr = [Pfm]::errorAccessDenied
    }else{
        for ($i=0; $i -lt $this.openMp4s.length;$i++){
            $op.Add( $this.openMp4s[$i].attribs, $this.Mp4InfoAll[$i][0].Mp4Name)
        }
    }

    $op.Complete( $perr, $true)
}

[void] ListEnd( [Pfm+MarshallerListEndOp] $op){
    $op.Complete( [Pfm]::errorSuccess)
}

[void] Read( [Pfm+MarshallerReadOp] $op){
    $data = $op.Data()
    $perr = 0
    $actualSize = 0

    for ($i=0; $i -lt $this.openMp4s.length;$i++){
        if ($op.OpenId() -eq $this.openMp4s[$i].openId){break}
    }

    if ($i -eq $this.openMp4s.length){
        $perr = [Pfm]::errorAccessDenied
    }else{
        $actualSize = $op.RequestedSize()
        $aFileSize = $this.openMp4s[$i].attribs.fileSize
        if ($op.FileOffset() -ge $aFileSize){
            $actualSize = 0
        }elseif ( (  $op.FileOffset() + $op.RequestedSize()) -gt $aFileSize){
            $actualSize = $aFileSize - $op.FileOffset()
        }

        if ($actualSize -ne 0){
            $aMp4Info = $this.Mp4InfoAll[$i]
            for ( $j = 1 ; $j -lt $aMp4Info.length ; $j++ ){
                if ($op.FileOffset()  -lt $aMp4Info[$j].Mp4offset ){break}
            }					
            $j--

            
            if ($aMp4Info[$j].fs -ne $null ){
                $aMp4Info[$j].fs.Position = 
                    $aMp4Info[$j].RARoffset + ( $op.FileOffset() - $aMp4Info[$j].Mp4offset )
            }

            $aaa = $aMp4Info[$j].length - ( $op.FileOffset() - $aMp4Info[$j].Mp4offset)

            $offset = 0
            $actualSize1 = $actualSize
            while ($actualSize1 -gt 0){
                if ($actualSize1 -gt $aaa ){
                    if ($aMp4Info[$j].fs -ne $null ){
                        $aMp4Info[$j].fs.read($data , $offset , $aaa)
                    }else{
                        [array]::Clear( $data , $offset , $aaa)
                    }
                    $actualSize1 -= $aaa
                    $offset += $aaa

                    $j++
                    if ($aMp4Info[$j].fs -ne $null ){
                        $aMp4Info[$j].fs.Position = $aMp4Info[$j].RARoffset
                    }
                    $aaa = $aMp4Info[$j].length
                }else{
                    if ($aMp4Info[$j].fs -ne $null ){
                        $aMp4Info[$j].fs.read($data , $offset , $actualSize1)
                    }else{
                        [array]::Clear( $data , $offset , $actualSize1)
                    }
                    $actualSize1 = 0
                }
            }

        }
    }

    $op.Complete( $perr, $actualSize)
}

[void] Write( [Pfm+MarshallerWriteOp] $op){
    $op.Complete( [Pfm]::errorAccessDenied, 0)
}

[void] SetSize( [Pfm+MarshallerSetSizeOp] $op){
    $op.Complete( [Pfm]::errorAccessDenied)
}

[void] Capacity( [Pfm+MarshallerCapacityOp] $op){
    $op.Complete( [Pfm]::errorSuccess, 10TB, 9TB)
}

[void] FlushMedia( [Pfm+MarshallerFlushMediaOp] $op){
    $op.Complete( [Pfm]::errorSuccess, -1)
}

[void] Control( [Pfm+MarshallerControlOp] $op){
    $op.Complete( [Pfm]::errorInvalid, 0)
}

[void] MediaInfo( [Pfm+MarshallerMediaInfoOp] $op){
    $mediaInfo = new-object Pfm+MediaInfo
    $op.Complete( [Pfm]::errorSuccess, $mediaInfo, "RarMp4")
}

[void] Access( [Pfm+MarshallerAccessOp] $op){
    $perr = 0
    $openAttribs =  new-object Pfm+OpenAttribs

    if ($op.OpenId() -eq $this.openRoot.openId){
        $openAttribs = $this.openRoot

    }else{ 
        for ($i=0; $i -lt $this.openMp4s.length;$i++){
            if ($op.OpenId() -eq $this.openMp4s[$i].openId){
                $openAttribs = $this.openMp4s[$i]
            }
        }
        if ($i -eq $this.openMp4s.length){$perr = [Pfm]::errorNotFound}
    }


    $op.Complete( $perr, $openAttribs, $null)
}

[void] ReadXattr( [Pfm+MarshallerReadXattrOp] $op){
    $op.Complete( [Pfm]::errorNotFound, 0, 0)
}

[void] WriteXattr( [Pfm+MarshallerWriteXattrOp] $op){
    $op.Complete( [Pfm]::errorAccessDenied, 0)
}


}

'@

Invoke-Expression $RarVolumeType
#==========================Start to Mount==========================================
$mcp = new-object Pfm+MountCreateParams -prop @{
    mountFlags = 0x30001
    driveLetter = $driveLetter
    mountSourceName = $MoutName  }


$openMp4s=@()
for ($i ,$j = 0,3; $i -lt $Mp4InfoAll.length;$i++,$j++){
    $openMp4s += 	new-object Pfm+OpenAttribs -prop @{
            openSequence = 1 ; accessLevel = [Pfm]::accessLevelReadData;
            attribs = new-object Pfm+Attribs -prop @{fileType = [Pfm]::fileTypeFile ; 
            fileId = $j;fileSize=$Mp4InfoAll[$i][0].Mp4Size}
            }
}


$msp = new-object Pfm+MarshallerServeParams  -prop @{
    volumeFlags = 1
    dispatch = new-object RarVolume  -prop @{Mp4InfoAll= $Mp4InfoALL ; openMp4s = $openMp4s}
    formatterName = "RarMp4Fs"  }


$n1 = $n2 = -1
$err = [Pfm]::SystemCreatePipe( [ref] $n1, [ref]$n2 )
$msp.toFormatterRead = $n1
$mcp.toFormatterWrite = $n2
      

$n1 = $n2 = -1
$err = [Pfm]::SystemCreatePipe( [ref] $n1, [ref]$n2 )
$mcp.fromFormatterRead = $n1
$msp.fromFormatterWrite = $n2        



$pfmApi = $null 
$err = [Pfm]::ApiFactory( [ref] $pfmApi)
if($err -ne 0){  Write-Host "ERROR: $err Unable to open PFM API.`n" ; pause ; exit }

$mount = $null
$err = $pfmApi.MountCreate( $mcp, [ref] $mount)
if ($err -ne 0){ Write-Host "ERROR: $err Unable to create mount.`n"  }


[Pfm]::SystemCloseFd( $mcp.toFormatterWrite)
[Pfm]::SystemCloseFd( $mcp.fromFormatterRead)



$marshaller = $null
$err = [Pfm]::MarshallerFactory( [ref]$marshaller )
if($err -ne 0){  Write-Host "ERROR: $err Unable to create marshaller.`n" ; pause ; exit }

$marshaller.ServeDispatch( $msp)


[Pfm]::SystemCloseFd( $msp.toFormatterRead)
[Pfm]::SystemCloseFd( $msp.fromFormatterWrite)


$pfmApi.Dispose()
$mount.Dispose()
$marshaller.Dispose()
