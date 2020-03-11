#rar 5 enc ref
#==================Edit Area================
$driveLetter = 'Z'
$MoutName = "thanks for sharing"
$autoOpen = $true

#search other source if some part content missing
$searchOtherSrc = $false

$dllDir = '.'
$rarDir = '.'
#Check PS 5.0
if ($host.Version.Major -lt 5){Write-Host 'NEED PowerShell 5.0';pause;exit}

if ($MyInvocation.Line -match '^if\(\(Get-ExecutionPolicy'){ cd -literal $PSScriptRoot }
#====================Functions=====================
function checkPfm($dllDir){
    pushd -literal $dllDir
    $dllFles = @(gi pfmclr_[0-9][0-9][0-9].dll , pfmshim16_[0-9][0-9][0-9].dll )

    if ($dllFles.count -ne 2){
        popd
        pushd -literal $script:rarDir
        $dllFles = @(gi pfmclr_[0-9][0-9][0-9].dll , pfmshim16_[0-9][0-9][0-9].dll )
    }

    if ($dllFles.count -ne 2){
        Write-Host 'Need  DLLs or too many DLLs'; pause; exit
    }else{
        Add-Type  -Path  $dllFles[0]
    }

    if ( ! ('pfm' -as [type])){
        Write-Host 'Dlls are not loaded'; pause; exit
    }

    $pfmApi = $null
    $err = [Pfm]::ApiFactory( [ref] $pfmApi)
    if($err -ne 0){Write-Host '"Pismo File Mount Audit Package" was not installed'; pause; exit}
    popd
}
function findRar($rarPath){
    $rarName = $null

    if ($rarPath -ne $null) {
        if (Test-Path -literal $rarPath -PathType Leaf){
            $rarDir = Split-Path $rarPath
            $rarName = Split-Path $rarPath -Leaf
        }elseif(Test-Path -literal $rarPath -PathType Container){
            $rarDir = $rarPath
        }else{
            Write-Host "$rarPath  is not exist"
            $rarDir = '.'
        }
    }
    $script:rarDir = $rarDir
    pushd -literal $rarDir
    
    $RarGroup = dir *.rar | sort | ?{$_.name -match '(.*?)(\.part\d+)?\.rar$' } |
            group -prop {$matches[1] + '/' + $matches[2].length}
    
    $rarFiles = $null
    [System.Collections.ArrayList]$otherGroup = @()
    
    for ($i = 0; $i -lt $RarGroup.count; $i++){
        if ($RarGroup[$i].Group.name -contains $rarName){
            $rarFiles = $RarGroup[$i].group
        }else{
            [void]$otherGroup.add($RarGroup[$i].group)
        }
    }

    if ($null -eq $rarFiles -and $otherGroup.count -ne 0){
        $rarFiles = $otherGroup[0]
        $otherGroup.RemoveAt(0)
    }
    popd

    return $rarFiles, $otherGroup
}
function getVint([ref]$bPos){
    $bPosOld = $bPos.Value
    
    while ($buffer[$bPos.Value++] -band 0x80) {}

    if ( ($bPos.Value - $bPosOld) -gt 9 ){throw 'Vint : too many bytes'}  # 7 * 9 = 63

    $data = $n = 0

    while ($bPosOld -lt $bPos.Value){
        [uint64]$d = $buffer[$bPosOld++] -band 0x7F
        $data +=  $d -shl  (7 * $n++)
    }
    return $data
}

function RarName4($buffer, $namePos, $nameSize){
    $nameEnd = $namePos + $nameSize

    #search zero between usual and encoded Unicode name
    for ($i = $namePos ; $i -lt $nameEnd ; $i++){
        if ($buffer[$i] -eq 0) {break}
    }

    #only ansi name
    if ($i -eq $nameEnd){
        return [System.Text.Encoding]::ASCII.GetString($buffer,$namePos,$nameSize)
    }

    #===============get unicode name===============
    $nameAnsiEnd = $i
    $i++
    $j = $namePos

    #HighByte of two bytes of Unicode
    $HighByte = $buffer[$i++]
    [byte]$FlagBits = [byte]$Flags = 0
    $Mp4FullName = $null

    :out
    While ($i -lt $nameEnd){
        #after 4 times , $FlagBit become to 0 , read a byte into $Flags
        #There are 4 flags(per flag 2bit)  in  $Flags
        if ($FlagBits -eq 0){
            $Flags = $buffer[$i++]
            $FlagBits = 8
        }

        switch ($Flags -shr 6){
            0{#ascii stored in encoded area
                if ($i -ge $nameEnd){break out}
                $Mp4FullName += [System.Text.Encoding]::ASCII.GetString($buffer[$i++])
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
                        $Mp4FullName += [System.Text.Encoding]::ASCII.GetString($buffer[$j])
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
    param($fs, $buffer, $fs0 = $null)

    $HeadTypeName = $HeadEncrypt = $rar5E = $salt = $PackType = $PackOffset =
    $PackSize = $Mp4FullName = $Mp4Size = $FileEncrypt = $Compression  = $false


    $n = $fs.read($buffer, 0, 7)
    if ( $n -lt 7 ) {throw 'file size is too small'}

    $HeadType = $buffer[2]
    $HeadFlag = [BitConverter]::ToUInt16($buffer ,3)
    $HeadSize = [BitConverter]::ToUInt16($buffer ,5)

    $n = $HeadSize - 7
    $n1 = $fs.read($buffer, 7, $n)

    if ($n1 -lt $n) {throw 'file size is too small'}

    #rar header is encrypted
    if ($fs0 -ne $null){
        $PackOffset = $fs0.position
    }else{
        $PackOffset = $fs.position
    }
    #=============after reading  header into buffer===============
    switch ($HeadType){
        0x73{
            $HeadTypeName = 'Main'
            if ($HeadFlag -band 0x80){
                $HeadEncrypt = $true

                #read salt after this header
                $salt = new-object byte[] 8
                $n = $fs.read($salt, 0, 8)
                if ($n -lt 8) {throw 'file size too small'}

                # no need
                $PackOffset += 8
            }
            if ($HeadFlag -band 0x2){
                write-host $HeadSize;pause

            }
        }

        0x74{
            $HeadTypeName = 'File'
            
            $PackSize = [BitConverter]::ToUInt32($buffer, 7)
            $Mp4Size  = [BitConverter]::ToUInt32($buffer, 11)

            #if file size too big 
            if ($HeadFlag -band 0x100){
                $HighSize = [BitConverter]::ToUInt32($buffer, 32)
                $PackSize += ([uint64]$HighSize -shl 32)

                $HighSize = [BitConverter]::ToUInt32($buffer, 36)
                $Mp4Size += ([uint64]$HighSize -shl 32)

                $namePos = 40
            }else{
                $namePos = 32
            }

            #get file name
            $nameSize = [BitConverter]::ToUInt16($buffer, 26)
            $Mp4FullName = RarName4  $buffer  $namePos  $nameSize
            
            #normal pack ? first pack  ?  middle pack ? last pack ?
            $PackType = $HeadFlag -band 3

            if ($HeadFlag -band 4){
                $FileEncrypt = $true
                $saltPos = $namePos + $nameSize
                $salt = new-object byte[] 8
                [array]::copy($buffer, $saltPos, $salt, 0, 8)
            }

            if ($buffer[25] -ne 0x30) {$Compression = $true}
        }#end of 0x74

        default{            
            #other block
            if ($HeadFlag -band 0x8000){ 
                $PackSize = [BitConverter]::ToUInt32($buffer, 7)
            }
        }#end of default
    }#end of switch

    return $HeadTypeName, $HeadEncrypt, $rar5E, $salt, $PackType, $PackOffset,
    $PackSize, $Mp4FullName, $Mp4Size, $FileEncrypt, $Compression
}

$getHeader5 = {
    param($fs, $buffer, $fs0 = $null)

    $HeadTypeName = $HeadEncrypt = $rar5E = $salt = $PackType = $PackOffset =
    $PackSize = $Mp4FullName = $Mp4Size = $FileEncrypt = $Compression  = $false

    #Read CRC
    $n = $fs.read($buffer, 0, 4)
    if ($n -lt 4) {throw 'file size too small'}

    #Read HeadSize
    $n = $fs.read($buffer, 0, 3)
    if ($n -lt 3) {throw 'file size too small'}

    $bPos = 0
    $HeadSize = getVint ([ref]$bPos)
    $n1 = $n - $bPos
    #[array]::Copy($buffer, $bPos, $buffer, 0, $n1)
    for ($i = 0; $i -lt $n1; $i++){
        $buffer[$i] = $buffer[$bPos+$i]
    }
    #Read Header into buffer
    $n = $fs.read($buffer, $n1, $HeadSize - $n1)
    if ($n -lt $HeadSize - $n1) {throw 'file size too small'}
    $bPos = 0

    #rar header is encrypted
    if ($fs0 -ne $null){
        $PackOffset = $fs0.position
    }else{
        $PackOffset = $fs.position
    }

    #=============after reading  header into buffer===============
    #Read HeadType  HeadFlag
    $HeadType = getVint ([ref]$bPos)

    $HeadFlag = getVint ([ref]$bPos)

    switch -w ($HeadType){
        #assume that data area is not exist in main block
        1{$HeadTypeName = 'Main'}

        [23]{# File header or Service header
            #Extra area size
            if ($HeadFlag -band 1) {
                getVint ([ref]$bPos) > $null 
            }

            #Data area size
            $PackSize = 0
            if ($HeadFlag -band 2) {
                $PackSize = getVint ([ref]$bPos)
            }

            if ($_ -eq 2) {
                $HeadTypeName = 'File'
            }else{#service header
                $HeadTypeName = 'Service'
            }

            #File flags
            $FileFlags = getVint ([ref]$bPos)

            #Unpacked size
            $Mp4Size = getVint ([ref]$bPos)

            #Attributes
            getVint ([ref]$bPos) > $null

            #mtime
            if ($FileFlags -band 2) {$bPos +=4}

            #Data CRC32
            if ($FileFlags -band 4) {$bPos +=4}

            #Compression information
            if (  (getVint ([ref]$bPos)) -band 0x0380) {$Compression = $true}

            #Host OS
            getVint ([ref]$bPos) > $null

            #file name length
            $nameSize = getVint ([ref]$bPos)

            #get file name
            $Mp4FullName=[System.Text.Encoding]::UTF8.GetString($buffer,$bPos,$nameSize)
            $bPos += $nameSize

            #normal pack ? first pack  ?  middle pack ? last pack ?
            $PackType = ($HeadFlag -shr 3) -band 3

            #encrypt ?  read extra area
            while ($bPos -lt $HeadSize){
                $recordSize = getVint ([ref]$bPos)
                $recordEnd = $bPos + $recordSize

                if ($recordEnd -gt $HeadSize){break}
                                
                #record type
                if ( ( getVint ([ref]$bPos) ) -eq 1 ){
                    $FileEncrypt = $true
                    $rar5E = @{}
                    
                    #Encryption version
                    getVint ([ref]$bPos) > $null

                    #Encryption flags
                    $eFlag = getVint ([ref]$bPos)

                    #KDF count
                    $rar5E.KDFcount = $buffer[$bPos++]

                    #salt
                    $salt = new-object byte[] 16
                    [array]::Copy($buffer, $bPos, $salt, 0, 16)
                    $bPos += 16
                    
                    #iv
                    $rar5E.iv = new-object byte[] 16
                    [array]::Copy($buffer, $bPos, $rar5E.iv, 0, 16)
                    $bPos += 16

                    #Check value
                    if ($eFlag -band 1){
                        $rar5E.checkValue = new-object byte[] 12
                        [array]::Copy($buffer, $bPos, $rar5E.checkValue, 0, 12)
                        $bPos += 12
                    }

                    $bPos = $recordEnd
                    break
                }else{
                    $bPos = $recordEnd
                }
            }#end of while
        }#end of [23]

        4{# Archive encryption header
            $HeadTypeName = 'Encryption'
            $HeadEncrypt = $true
            $rar5E = @{}

            #Encryption version
            getVint ([ref]$bPos) > $null

            #Encryption flags
            $eFlag = getVint ([ref]$bPos)

            #KDF count
            $rar5E.KDFcount = $buffer[$bPos++]

            #salt
            $salt = new-object byte[] 16
            [array]::Copy($buffer, $bPos, $salt, 0, 16)
            $bPos += 16

            #Check value
            if ($eFlag -band 1){
                $rar5E.checkValue = new-object byte[] 12
                [array]::Copy($buffer, $bPos, $rar5E.checkValue, 0, 12)
                $bPos += 12
            }

        }
        5{# End of archive header
        }
        default{
            write-host "unknown header type : $HeadType"
        }
    }# end of switch

    return $HeadTypeName, $HeadEncrypt, $rar5E, $salt, $PackType, $PackOffset,
    $PackSize, $Mp4FullName, $Mp4Size, $FileEncrypt, $Compression
}

$SHA1SPdef =  @'
// modify version of  SHA1CryptoServiceProvider.cs 
// for calculation of  rar3 key iv
//
// original version from
// https://github.com/mono/mono/blob/master/mcs/class/corlib/System.Security.Cryptography/SHA1CryptoServiceProvider.cs
// Authors:
//	Matthew S. Ford (Matthew.S.Ford@Rose-Hulman.Edu)
//	Sebastien Pouliot (sebastien@ximian.com)
//
// Copyright 2001 by Matthew S. Ford.
// Copyright (C) 2004, 2005, 2008 Novell, Inc (http://www.novell.com)



using System.Runtime.InteropServices;

namespace SHA1SP {

	public class SHA1SP {
	
		private const int BLOCK_SIZE_BYTES =  64;
		private uint[] _H;  // these are my chaining variables
		private ulong count;
		private byte[] _ProcessingBuffer;   // Used to start data when passed less than a block worth.
		private int _ProcessingBufferCount; // Counts how much data we have stored that still needs processed.
		private uint[] buff;

		public SHA1SP () 
		{
			_H = new uint[5];
			_ProcessingBuffer = new byte[BLOCK_SIZE_BYTES];
			buff = new uint[80];
			
			Initialize();
        }
        ~SHA1SP () 
        {

        }

		public void HashCore (byte[] rgb, int ibStart, int cbSize) 
		{
			int i;
            bool secondBlock = false;
			if (_ProcessingBufferCount != 0) {
				if (cbSize < (BLOCK_SIZE_BYTES - _ProcessingBufferCount)) {
					System.Buffer.BlockCopy (rgb, ibStart, _ProcessingBuffer, _ProcessingBufferCount, cbSize);
					_ProcessingBufferCount += cbSize;
					return;
				}
				else {
					i = (BLOCK_SIZE_BYTES - _ProcessingBufferCount);
					System.Buffer.BlockCopy (rgb, ibStart, _ProcessingBuffer, _ProcessingBufferCount, i);
					ProcessBlock (_ProcessingBuffer, 0);
					_ProcessingBufferCount = 0;
					ibStart += i;
                    cbSize -= i;
                    secondBlock = true;
				}
			}


			for (i = 0; i < cbSize - cbSize % BLOCK_SIZE_BYTES; i += BLOCK_SIZE_BYTES) {
                ProcessBlock (rgb, (uint)(ibStart + i));

                if (secondBlock){
                    for (int j=0; j<16; j++) {
                        System.Array.Copy(  System.BitConverter.GetBytes(this.buff[j+64]) , 
                          0, rgb, ibStart + i + j*4 , 4);
                    }
                }

                secondBlock = true;
			}

			if (cbSize % BLOCK_SIZE_BYTES != 0) {
				System.Buffer.BlockCopy (rgb, cbSize - cbSize % BLOCK_SIZE_BYTES + ibStart, _ProcessingBuffer, 0, cbSize % BLOCK_SIZE_BYTES);
				_ProcessingBufferCount = cbSize % BLOCK_SIZE_BYTES;
			}
		}

		public byte[] HashFinal () 
		{
			byte[] hash = new byte[20];

			ProcessFinalBlock (_ProcessingBuffer, 0, _ProcessingBufferCount);

			for (int i=0; i<5; i++) {
				for (int j=0; j<4; j++) {
					hash [i*4+j] = (byte)(_H[i] >> (8*(3-j)));
				}
			}

			return hash;
		}

		public byte[] HashForIV () 
		{
            uint[] Hcopy = new uint[5];
            for (int i=0; i<5; i++) {
                Hcopy[i] = this._H[i];
            }
            ulong countCopy = this.count;

			byte[] hash = new byte[20];

			ProcessFinalBlock (_ProcessingBuffer, 0, _ProcessingBufferCount);

			for (int i=0; i<5; i++) {
				for (int j=0; j<4; j++) {
					hash [i*4+j] = (byte)(_H[i] >> (8*(3-j)));
				}
            }
            for (int i=0; i<5; i++) {
                this._H[i] = Hcopy[i];
            }
            this.count = countCopy;

			return hash;
		}



        public void Initialize () 
		{
			count = 0;
			_ProcessingBufferCount = 0;

			_H[0] = 0x67452301;
			_H[1] = 0xefcdab89;
			_H[2] = 0x98badcfe;
			_H[3] = 0x10325476;
			_H[4] = 0xC3D2E1F0;
		}

		private void ProcessBlock(byte[] inputBuffer, uint inputOffset) 
		{
			uint a, b, c, d, e;

			count += BLOCK_SIZE_BYTES;

			// abc removal would not work on the fields
			uint[] _H = this._H;
			uint[] buff = this.buff;
			InitialiseBuff(buff, inputBuffer, inputOffset);
			FillBuff(buff);

			a = _H[0];
			b = _H[1];
			c = _H[2];
			d = _H[3];
			e = _H[4];

			// This function was unrolled because it seems to be doubling our performance with current compiler/VM.
			// Possibly roll up if this changes.

			// ---- Round 1 --------
			int i=0;
			while (i < 20)
			{
				e += ((a << 5) | (a >> 27)) + (((c ^ d) & b) ^ d) + 0x5A827999 + buff[i];
				b = (b << 30) | (b >> 2);

				d += ((e << 5) | (e >> 27)) + (((b ^ c) & a) ^ c) + 0x5A827999 + buff[i+1];
				a = (a << 30) | (a >> 2);

				c += ((d << 5) | (d >> 27)) + (((a ^ b) & e) ^ b) + 0x5A827999 + buff[i+2];
				e = (e << 30) | (e >> 2);

				b += ((c << 5) | (c >> 27)) + (((e ^ a) & d) ^ a) + 0x5A827999 + buff[i+3];
				d = (d << 30) | (d >> 2);

				a += ((b << 5) | (b >> 27)) + (((d ^ e) & c) ^ e) + 0x5A827999 + buff[i+4];
				c = (c << 30) | (c >> 2);
				i += 5;
			}

			// ---- Round 2 --------
			while (i < 40)
			{
				e += ((a << 5) | (a >> 27)) + (b ^ c ^ d) + 0x6ED9EBA1 + buff[i];
				b = (b << 30) | (b >> 2);

				d += ((e << 5) | (e >> 27)) + (a ^ b ^ c) + 0x6ED9EBA1 + buff[i + 1];
				a = (a << 30) | (a >> 2);

				c += ((d << 5) | (d >> 27)) + (e ^ a ^ b) + 0x6ED9EBA1 + buff[i + 2];
				e = (e << 30) | (e >> 2);

				b += ((c << 5) | (c >> 27)) + (d ^ e ^ a) + 0x6ED9EBA1 + buff[i + 3];
				d = (d << 30) | (d >> 2);

				a += ((b << 5) | (b >> 27)) + (c ^ d ^ e) + 0x6ED9EBA1 + buff[i + 4];
				c = (c << 30) | (c >> 2);
				i += 5;
			}
		   
			// ---- Round 3 --------
			while (i < 60)
			{
				e += ((a << 5) | (a >> 27)) + ((b & c) | (b & d) | (c & d)) + 0x8F1BBCDC + buff[i];
				b = (b << 30) | (b >> 2);

				d += ((e << 5) | (e >> 27)) + ((a & b) | (a & c) | (b & c)) + 0x8F1BBCDC + buff[i + 1];
				a = (a << 30) | (a >> 2);

				c += ((d << 5) | (d >> 27)) + ((e & a) | (e & b) | (a & b)) + 0x8F1BBCDC + buff[i + 2];
				e = (e << 30) | (e >> 2);

				b += ((c << 5) | (c >> 27)) + ((d & e) | (d & a) | (e & a)) + 0x8F1BBCDC + buff[i + 3];
				d = (d << 30) | (d >> 2);

				a += ((b << 5) | (b >> 27)) + ((c & d) | (c & e) | (d & e)) + 0x8F1BBCDC + buff[i + 4];
				c = (c << 30) | (c >> 2);
				i += 5;
			}

			// ---- Round 4 --------
			while (i < 80)
			{
				e += ((a << 5) | (a >> 27)) + (b ^ c ^ d) + 0xCA62C1D6 + buff[i];
				b = (b << 30) | (b >> 2);

				d += ((e << 5) | (e >> 27)) + (a ^ b ^ c) + 0xCA62C1D6 + buff[i + 1];
				a = (a << 30) | (a >> 2);

				c += ((d << 5) | (d >> 27)) + (e ^ a ^ b) + 0xCA62C1D6 + buff[i + 2];
				e = (e << 30) | (e >> 2);

				b += ((c << 5) | (c >> 27)) + (d ^ e ^ a) + 0xCA62C1D6 + buff[i + 3];
				d = (d << 30) | (d >> 2);

				a += ((b << 5) | (b >> 27)) + (c ^ d ^ e) + 0xCA62C1D6 + buff[i + 4];
				c = (c << 30) | (c >> 2);
				i += 5;
			}

			_H[0] += a;
			_H[1] += b;
			_H[2] += c;
			_H[3] += d;
			_H[4] += e;
		}

		private static void InitialiseBuff(uint[] buff, byte[] input, uint inputOffset)
		{
			buff[0] = (uint)((input[inputOffset + 0] << 24) | (input[inputOffset + 1] << 16) | (input[inputOffset + 2] << 8) | (input[inputOffset + 3]));
			buff[1] = (uint)((input[inputOffset + 4] << 24) | (input[inputOffset + 5] << 16) | (input[inputOffset + 6] << 8) | (input[inputOffset + 7]));
			buff[2] = (uint)((input[inputOffset + 8] << 24) | (input[inputOffset + 9] << 16) | (input[inputOffset + 10] << 8) | (input[inputOffset + 11]));
			buff[3] = (uint)((input[inputOffset + 12] << 24) | (input[inputOffset + 13] << 16) | (input[inputOffset + 14] << 8) | (input[inputOffset + 15]));
			buff[4] = (uint)((input[inputOffset + 16] << 24) | (input[inputOffset + 17] << 16) | (input[inputOffset + 18] << 8) | (input[inputOffset + 19]));
			buff[5] = (uint)((input[inputOffset + 20] << 24) | (input[inputOffset + 21] << 16) | (input[inputOffset + 22] << 8) | (input[inputOffset + 23]));
			buff[6] = (uint)((input[inputOffset + 24] << 24) | (input[inputOffset + 25] << 16) | (input[inputOffset + 26] << 8) | (input[inputOffset + 27]));
			buff[7] = (uint)((input[inputOffset + 28] << 24) | (input[inputOffset + 29] << 16) | (input[inputOffset + 30] << 8) | (input[inputOffset + 31]));
			buff[8] = (uint)((input[inputOffset + 32] << 24) | (input[inputOffset + 33] << 16) | (input[inputOffset + 34] << 8) | (input[inputOffset + 35]));
			buff[9] = (uint)((input[inputOffset + 36] << 24) | (input[inputOffset + 37] << 16) | (input[inputOffset + 38] << 8) | (input[inputOffset + 39]));
			buff[10] = (uint)((input[inputOffset + 40] << 24) | (input[inputOffset + 41] << 16) | (input[inputOffset + 42] << 8) | (input[inputOffset + 43]));
			buff[11] = (uint)((input[inputOffset + 44] << 24) | (input[inputOffset + 45] << 16) | (input[inputOffset + 46] << 8) | (input[inputOffset + 47]));
			buff[12] = (uint)((input[inputOffset + 48] << 24) | (input[inputOffset + 49] << 16) | (input[inputOffset + 50] << 8) | (input[inputOffset + 51]));
			buff[13] = (uint)((input[inputOffset + 52] << 24) | (input[inputOffset + 53] << 16) | (input[inputOffset + 54] << 8) | (input[inputOffset + 55]));
			buff[14] = (uint)((input[inputOffset + 56] << 24) | (input[inputOffset + 57] << 16) | (input[inputOffset + 58] << 8) | (input[inputOffset + 59]));
			buff[15] = (uint)((input[inputOffset + 60] << 24) | (input[inputOffset + 61] << 16) | (input[inputOffset + 62] << 8) | (input[inputOffset + 63]));
		}

		private static void FillBuff(uint[] buff)
		{
			uint val;
			for (int i = 16; i < 80; i += 8)
			{
				val = buff[i - 3] ^ buff[i - 8] ^ buff[i - 14] ^ buff[i - 16];
				buff[i] = (val << 1) | (val >> 31);

				val = buff[i - 2] ^ buff[i - 7] ^ buff[i - 13] ^ buff[i - 15];
				buff[i + 1] = (val << 1) | (val >> 31);

				val = buff[i - 1] ^ buff[i - 6] ^ buff[i - 12] ^ buff[i - 14];
				buff[i + 2] = (val << 1) | (val >> 31);

				val = buff[i + 0] ^ buff[i - 5] ^ buff[i - 11] ^ buff[i - 13];
				buff[i + 3] = (val << 1) | (val >> 31);

				val = buff[i + 1] ^ buff[i - 4] ^ buff[i - 10] ^ buff[i - 12];
				buff[i + 4] = (val << 1) | (val >> 31);

				val = buff[i + 2] ^ buff[i - 3] ^ buff[i - 9] ^ buff[i - 11];
				buff[i + 5] = (val << 1) | (val >> 31);

				val = buff[i + 3] ^ buff[i - 2] ^ buff[i - 8] ^ buff[i - 10];
				buff[i + 6] = (val << 1) | (val >> 31);

				val = buff[i + 4] ^ buff[i - 1] ^ buff[i - 7] ^ buff[i - 9];
				buff[i + 7] = (val << 1) | (val >> 31);
			}
		}
	
		private void ProcessFinalBlock (byte[] inputBuffer, int inputOffset, int inputCount) 
		{
			ulong total = count + (ulong)inputCount;
			int paddingSize = (56 - (int)(total % BLOCK_SIZE_BYTES));

			if (paddingSize < 1)
				paddingSize += BLOCK_SIZE_BYTES;

			int length = inputCount+paddingSize+8;
			byte[] fooBuffer = (length == 64) ? _ProcessingBuffer : new byte[length];

			for (int i=0; i<inputCount; i++) {
				fooBuffer[i] = inputBuffer[i+inputOffset];
			}

			fooBuffer[inputCount] = 0x80;
			for (int i=inputCount+1; i<inputCount+paddingSize; i++) {
				fooBuffer[i] = 0x00;
			}

			// I deal in bytes. The algorithm deals in bits.
			ulong size = total << 3;
			AddLength (size, fooBuffer, inputCount+paddingSize);
			ProcessBlock (fooBuffer, 0);

			if (length == 128)
				ProcessBlock (fooBuffer, 64);
		}

		internal void AddLength (ulong length, byte[] buffer, int position)
		{
			buffer [position++] = (byte)(length >> 56);
			buffer [position++] = (byte)(length >> 48);
			buffer [position++] = (byte)(length >> 40);
			buffer [position++] = (byte)(length >> 32);
			buffer [position++] = (byte)(length >> 24);
			buffer [position++] = (byte)(length >> 16);
			buffer [position++] = (byte)(length >>  8);
			buffer [position]   = (byte)(length);
		}
	}
}
'@

function getAESKeyIV ($h, $salt, $rar5E = $null){
    if ($h.aesAll -ne $null){return $h.aesAll.key, $h.aesAll.iv}
    if ($h.aesKeyIV.count -eq 2){ return $h.aesKeyIV }

    if ($script:pass -eq $null){
        $script:pass = read-host 'password ?'
    }

    if ($h.rarVer -eq 4){
        $seed = [System.Text.Encoding]::Unicode.GetBytes($script:pass) + $salt
        $seedNew = New-Object byte[] $seed.length
        [array]::Copy($seed, 0, $seedNew, 0, $seed.length)
    
        $iv = @()
        if ( ! ('SHA1SP.SHA1SP' -as [type])){Add-Type -TypeDef $script:SHA1SPdef }
        $sha1 = new-object SHA1SP.SHA1SP
    
        for($i = 0; $i -lt 16; $i++){
            for($j = 0; $j -lt 0x4000; $j++){
                $count = [System.BitConverter]::GetBytes($i*0x4000 + $j)
                $sha1.HashCore($seedNew, 0, $seedNew.length) > $null
                #$sha1.HashCore($seed, 0, $seed.length) > $null
                $sha1.HashCore($count, 0, 3) >$null
                if ($j -eq 0){
                    $hash = $sha1.HashForIV()
                    $iv += $hash[19]
                }
            }
        }
        $hash = $sha1.HashFinal()
        $key = $hash[3..0] + $hash[7..4] + $hash[11..8] + $hash[15..12]

    }else{# rar 5
        $pass = [System.Text.Encoding]::UTF8.GetBytes($script:pass)
        $h256 =  new-object System.Security.Cryptography.HMACSHA256
        $h256.Key = $pass

        $u = $h256.ComputeHash($salt + (0,0,0,1))
        
        $key = $u
      
        $count = 1 -shl $rar5E.KDFcount
        for ($i = 1; $i -lt $count; $i++){
            $u = $h256.ComputeHash($u)
            for ($j = 0; $j -lt $key.count; $j++){
                $key[$j] = $key[$j] -bxor $u[$j]
            }
        }

        $v2 = New-Object byte[] 32
        [array]::Copy($key, 0, $v2, 0, 32)
        for ($i = 0 ; $i -lt 32; $i++){
            $u = $h256.ComputeHash($u)
            for ($j = 0; $j -lt $v2.count; $j++){
                $v2[$j] = $v2[$j] -bxor $u[$j]
            }
        }

        if ($null -ne $rar5E.checkValue){
            $check8 = new-object byte[] 8

            for ($i = 0; $i -lt 32; $i++){
                $check8[$i % 8] = $check8[$i % 8] -bxor $v2[$i]
            }

            if ("$check8" -eq $rar5E.checkValue[0..7]){
                Write-Host 'password ok'
            }else{
                Write-Host 'password error';pause;exit
            }
        }
        if ($null -ne $rar5E.iv){
            $iv = $rar5E.iv
        }else{
            $iv = $null
        }
    }
    
    return $key,$iv
}

function adjustRange($Mp4Info){
    if ($Mp4Info[0].fs -eq $null -and  $null -eq $Mp4Info[0].buffer ){return}
    if ($Mp4Info.count -lt 2){return}

    ($Mp4Info.Count - 1) .. 1 | %{
        $current = $Mp4Info[$_]
        $prev = $Mp4Info[$_ - 1]
        $n = $current.Mp4offset % 16

        if ($current.fs -eq $null){
            if ($prev.fs -ne $null -and $n){
                $current.Mp4offset -= $n
                $current.length += $n
                $prev.length -= $n
            }

        }else{ # $current.fs -ne $null
            if ($prev.fs -ne $null){
                if ($n){
                    $blockIV = New-Object byte[] 16
                    $blockEncrypted = New-Object byte[] 16
                    $blockOut = New-Object byte[] 16

                    # $pre.length should greater than 31 .   no check here
                    $prev.fs.position = $prev.FSoffset + $prev.Length - ($n + 16)
                    [void]$prev.fs.read($blockIV, 0, 16)
                    [void]$prev.fs.read($blockEncrypted, 0, $n)
                    
                    $current.fs.position = $current.FSoffset
                    [void]$current.fs.read($blockEncrypted, $n, 16 - $n)

                    $current.aes.IV = $blockIV

                    [void]$current.aes.CreateDecryptor().TransformBlock($blockEncrypted, 0, 16, $blockOut, 0)

                    $current.aes.IV = $blockEncrypted
                    $current.Mp4offset += 16 - $n
                    $current.FSoffset += 16 - $n
                    $current.length -= 16 - $n

                    $prev.length -= $n
                    
                    $Mp4Info.insert($_ , @{fs = $null; buffer = $blockOut ;
                        length = 16 ; Mp4offset = $current.Mp4offset - 16
                    })

                }else{ # $n -eq 0
                    $blockIV = New-Object byte[] 16
                    $prev.fs.position = $prev.FSoffset + $prev.Length - 16
                    [void]$prev.fs.read($blockIV, 0, 16)

                    $current.aes.IV = $blockIV
                }
            }else{# $prev.fs -eq $null
                $blockIV = New-Object byte[] 16
                if ($n){
                    $current.fs.position = $current.FSoffset + (16 - $n)
                    [void]$current.fs.read($blockIV, 0, 16)

                    $current.Mp4offset += 32 - $n
                    $current.FSoffset += 32 - $n
                    $current.length -= 32 - $n

                    $prev.length += 32 - $n
                }else{# $n -eq 0
                    $current.fs.position = $current.FSoffset
                    [void]$current.fs.read($blockIV, 0, 16)

                    $current.Mp4offset += 16
                    $current.FSoffset += 16
                    $current.length -= 16

                    $prev.length += 16
                }

                $current.aes.IV = $blockIV  
            }# end of $prev -eq $null
        }# end of $current -eq $null
    }# end of foreach
}

function beforeFileHeader($getHeader, $h, $fs, $buffer, $file){
    $result = & $getHeader $fs  $buffer
    #$HeadTypeName, $HeadEncrypt, $rar5E, $salt, $PackType, $PackOffset,
    #$PackSize, $Mp4FullName, $Mp4Size, $FileEncrypt, $Compression

    $HeadTypeName, $HeadEncrypt, $rar5E, $salt = $result[0..3]

    #rar v4
    if ($h.rarVer -eq 4 -and $HeadTypeName -ne 'Main') {throw "$file : Main header error"}

    if ($h.rarVer -eq 5){
        if ($HeadTypeName -eq 'Main'){
            return $HeadEncrypt
        }elseif($HeadTypeName -ne 'Encryption'){
            throw "$file : Main header error"
        }
    }

    if ($HeadEncrypt){
        $key , $iv = getAESKeyIV $h $salt $rar5E

        $h.aesAll = new-object System.Security.Cryptography.AesCryptoServiceProvider
        $h.aesAll.Key = $key

        # Padding  none
        $h.aesAll.Padding = 1

        if ($h.rarVer -eq 4){
            $h.aesAll.IV = $iv
        }else{# rar 5

            $iv = new-object byte[] 16
            $n = $fs.read($iv, 0, 16)
            if ($n -lt 16) {throw 'file size too small'}
    
            $h.aesAll.iv = $iv

            $cs = new-object System.Security.Cryptography.CryptoStream (
                $fs, $h.aesAll.CreateDecryptor(), 0
            )
    
            $result = & $getHeader $cs  $buffer  $fs
    
            if ($result[0] -ne 'Main'){throw "$file : Main header error"}
    
            $cs = $null

        }
    }


    return $HeadEncrypt
}

function parseFileHeader($getHeader, $h, $fs, $buffer, $file, $HeadEncrypt){

    if ($HeadEncrypt){
        if ($h.rarVer -eq 5){
            $iv = new-object byte[] 16
            $n = $fs.read($iv, 0, 16)
            if ($n -lt 16) {throw 'file size too small'}
    
            $h.aesAll.iv = $iv
        }

        $cs = new-object System.Security.Cryptography.CryptoStream (
            $fs, $h.aesAll.CreateDecryptor(), 0
        )

        $result = & $getHeader $cs  $buffer  $fs
        $cs = $null
    }else{
        $result = & $getHeader $fs  $buffer
    }

    $HeadTypeName, $HeadEncrypt, $rar5E, $salt, $PackType, $PackOffset,
    $PackSize, $Mp4FullName, $Mp4Size, $FileEncrypt, $Compression = $result[0..10]

    if ($HeadTypeName -ne 'File') {
        if ($HeadTypeName -eq 'Service' -and $Mp4FullName -ceq 'CMT'){

            $fs.position = $PackOffset
            if ($buffer.length -lt $PackSize){
                write-host 'comment size is too large'
            }else{
                $n = $fs.read($buffer, 0, $PackSize)
                if ($n -lt $PackSize){
                    write-host 'file is too small'
                }else{
                    if ($null -ne $h.aesAll){
                        $h.aesAll.iv = $rar5E.iv
                        $d1 = $h.aesAll.CreateDecryptor()
                        [void]$d1.TransformBlock($buffer, 0, $PackSize, $buffer, 0)
                        $d1.Dispose()
                        
                        for ($n = 0; $n -lt $PackSize; $n++){
                            if ($buffer[$n] -eq 0){break}
                        }
                    }
                    $h.comment = [System.Text.Encoding]::UTF8.GetString($buffer[0..($n-1)])
                    Write-Host $h.comment
                    pause
                }
            }
            
        }

        return 9, $PackOffset, $PackSize
    }

    #=== previous pack and current pack are parts of the same file ? ===
    $Mp4Info = $h.Mp4Info

    if ($h.nextPartN -ne $null){
        $SameFile = $false

            #middle pack or last pack 
        if ($PackType -eq 3 -or $PackType -eq 1){
            if ($h.Mp4FullName_now -eq $Mp4FullName -and $h.Mp4Size_now -eq $Mp4Size){
                $SameFile = $true
            }
        }

        if ( ! $SameFile){ mp4Ending  $h }
    }# end of if $h.nextPartN -ne $null

    #============= process current pack ======================
    if ($compression) {
        Write-Host "$Mp4FullName :`n can't process compressed file"
        return $PackType, $PackOffset, $PackSize
    }
    #skip filesize -eq 0   or folder
    if($Mp4Size -eq 0){ return $PackType, $PackOffset, $PackSize }

    # mp4size not matched when search other source 
    if ($script:h0 -ne $null -and $script:h0.Mp4Size_now -ne $Mp4Size){
        return $PackType, $PackOffset, $PackSize
    }

    if ($h.nextPartN -eq $null){ # first time meet
        $h.Mp4Info = [System.Collections.ArrayList]@()
        
        $h.Mp4FullName_now = $h.Mp4Size_now = $h.FullPack = $h.midPackSize =
        $h.nEmpty = $h.aesKeyIV = $h.FileEncrypt = $null 

        $Mp4Info = $h.Mp4Info

        if ($PackType -eq 1 -or $PackType -eq 3) {# first pack missing                
            [void]$Mp4Info.add($null)
        }

        #check duplicate names
        $Mp4Name = split-path  $Mp4FullName  -leaf
                            
        $n = 1
        $Mp4BaseName = [IO.Path]::GetFileNameWithoutExtension($Mp4Name)
        $Mp4ExtName = [IO.Path]::GetExtension($Mp4Name)
        #if ($Mp4ExtName -notIn $script:videoExtName){return $PackType, $PackOffset, $PackSize}
        while ($script:Mp4NameList -contains $Mp4Name){
            $Mp4Name = $Mp4BaseName + '-' + $n + $Mp4ExtName
            $n++
        }

        $Mp4offset = 0

        $h.FullPack = $Mp4Size
        if ($FileEncrypt){
            $h.FileEncrypt = $true
            if ($Mp4Size % 16) {$h.FullPack += 16 - ($Mp4Size % 16)}
            
            if ($h.rarVer -eq 4){
                $h.aesKeyIV =  getAESKeyIV  $h  $salt
            }else{#rar 5
                $h.aesKeyIV =  getAESKeyIV  $h  $salt $rar5E
                $h.aesKeyIV[1] = $rar5E.iv
            }
        }

        $h.Mp4FullName_now = $Mp4FullName
        $h.Mp4Size_now = $Mp4Size
        
    }else{# meet again
        $Mp4Info = $h.Mp4Info
        $Mp4offset = $Mp4Info[-1].Mp4offset + $Mp4Info[-1].length

        [int]$partN = $file.basename -replace '.*part',''

        # missing *.part.rar  or previous pack is not complete
        if ($partN -gt $h.nextPartN  -or  $h.nEmpty -gt 0){
            if ($PackType -eq 3){ # middle pack
                $nEmpty = $PackSize * ($partN - $h.nextPartN) + $h.nEmpty
                [void]$Mp4Info.add(  @{fs = $null; Mp4offset = $Mp4offset; length = $nEmpty}  )
                $Mp4offset += $nEmpty
            }else{ # last pack
                if ($Mp4Info[0] -eq $null){ # $Mp4offset is fake
                    $nEmpty = $h.midPackSize * ($partN - $h.nextPartN) + $h.nEmpty
                
                }else{# $Mp4offset is true
                    $nEmpty = $h.FullPack -$PackSize - $Mp4offset
                }
                [void]$Mp4Info.add(  @{fs = $null; Mp4offset = $Mp4offset; length = $nEmpty} )
                $Mp4offset = $h.FullPack - $PackSize
            }
        }
    }
   
    #file is incomplete ?
    if ($PackOffset + $PackSize -gt $fs.length) {
        $h.nEmpty = $PackOffset + $PackSize - $fs.length
    }
    
    [void]$Mp4Info.add( @{Mp4offset = $Mp4offset
        FSoffset = $PackOffset ; length = $PackSize - $h.nEmpty}  )
    
    if ($PackType -eq 0){
        if ($h.fsForType0 -ne $null){
            $Mp4Info[-1].fs = $h.fsForType0
        }else{
            $h.fsForType0 = $file.OpenRead()
            $Mp4Info[-1].fs = $h.fsForType0
        }
    }else{
        $Mp4Info[-1].fs = $file.OpenRead()
    }
    
    if ($h.nextPartN -eq $null){
        $Mp4Info[-1].Mp4Name = $Mp4Name
        $Mp4Info[-1].Mp4Size = $Mp4Size
    }
    
    if ($FileEncrypt){
        $Mp4Info[-1].aes = new-object System.Security.Cryptography.AesCryptoServiceProvider
        $Mp4Info[-1].aes.Key = $h.aesKeyIV[0]
        $Mp4Info[-1].aes.IV = $h.aesKeyIV[1]
        
        # Padding  none
        $Mp4Info[-1].aes.Padding = 1
    }
    
    if ($PackType -eq 3) {$h.midPackSize = $PackSize}

    if ( $PackType -eq 2 -or $PackType -eq 3 ) { # first pack or middle pack
        #next RAR part number
        $h.nextPartN = 1 + $( $file.basename -replace '.*part','' )

    }elseif ($PackType -eq 1){
        if ($Mp4Info[0] -eq $null){
            # correct Mp4offset
            $Mp4Info[-1].Mp4offset = $h.FullPack - $PackSize
            if ($Mp4Info.count -gt 2){
                $L = $Mp4Info[-1].Mp4offset - ($Mp4Info[-2].Mp4offset + $Mp4Info[-2].length)
                1 .. ($Mp4Info.count - 2) | %{ $Mp4Info[$_].Mp4offset += $L }
            }
            $Mp4Info[0] = @{fs = $null; Mp4offset = 0; length = $Mp4Info[1].Mp4offset
                Mp4Name = $Mp4Info[1].Mp4Name; Mp4Size = $Mp4Info[1].Mp4Size}
        }
        if ($h.nEmpty){
            $Mp4offset = $Mp4Info[-1].Mp4offset + $Mp4Info[-1].length
            [void]$Mp4Info.add( @{fs = $null; Mp4offset = $Mp4offset; length = $h.nEmpty}  )
        }

        if ($FileEncrypt){ adjustRange $Mp4Info }

        $h.nextPartN = -1
    }elseif($PackType -eq 0){
        $h.nextPartN = -1
    }

    return $PackType, $PackOffset, $PackSize
}

function rebuildMp4($Mp4Info){
    # mp4 only
    [byte[]]$pattern = (,0 * 11) + 1 + (,0 *15) + 1 + (,0 * 14) + 64 + (,0 * 29)

    
    [byte[]]$Bc = @(72) * 256
    $Bc[0] = 1; $Bc[1] = 11; $Bc[64] = 42
    
    [byte[]]$Gs = 1,10,9,8,7,6,5,4,3,2,1,12,72,72,72,72,72,72,
    72,72,72,72,72,72,72,72,16,72,72,72,61,72,72,72,72,72,72,
    72,72,72,72,72,72,72,72,61,72,72,72,72,72,72,72,72,72,72,
    72,72,72,72,72,61,72,72,72,72,72,72,72,72,72,72
    

    [uint32]$searchSize = 20MB
    write-host searching moov
    $time1 = get-date
    $bufferPos = BmBackward $Mp4Info  -1  -1  $pattern  $searchSize  $Bc  $Gs

    $time2=get-date
    write-host ($time2-$time1)
    #========================after searching========================
    if ($bufferPos -eq -1) {
        write-host moov not found
        return  $false
    }else{ #moov found
        write-host moov found
        $moovPos = $Mp4Info[0].Mp4Size - $searchSize + $bufferPos - 42


        [byte[]]$ftypData = 0,0,0,0x20,0x66,0x74,0x79,0x70,0x69,0x73,0x6F,0x6D,0,0,
                            2,0,0x69,0x73,0x6F,0x6D,0x69,
                            0x73,0x6F,0x32,0x61,0x76,0x63,0x31,0x6D,0x70,0x34,0x31
        $mdatSize = $moovPos - 32
        if ( $mdatSize -lt 4GB ){
            $arr = [BitConverter]::GetBytes([uint32]$mdatSize)
            [array]::Reverse($arr)
            [byte[]]$mdatHead = $arr + 0x6D,0x64,0x61,0x74
        }else{
            $arr = [BitConverter]::GetBytes([uint64]$mdatSize)
            [array]::Reverse($arr)
            [byte[]]$mdatHead = 0,0,0,1 + 0x6D,0x64,0x61,0x74 + $arr
        }
        [byte[]]$buffer = $ftypData + $mdatHead
        
        $Mp4Info[0].buffer = $buffer
        $Mp4Info[0].length = $buffer.Length
        
        $Mp4Info.insert(1, @{fs = $null; Mp4offset = $buffer.Length})

        $Mp4Info[1].length = $Mp4Info[2].Mp4offset - $Mp4Info[1].Mp4offset

        return $true
    }#end of moov found
}

function readBackward($Mp4Info, [int32]$i, [int32]$offset, [uint32]$readSize, $buffer){

    $partLen = $offset + 1
    $partPos = 0
    if ($readSize -lt $partLen){
        $partPos = $partLen - $readSize
        $partLen = $readSize
    }

    $bufferPos = $readSize - $partLen

    $readSize1 = $readSize
    while($readSize1 -gt 0){
        if ($Mp4Info[$i].fs -ne $null){
            if ($Mp4Info[$i].aes -eq $null){
                $Mp4Info[$i].fs.position = $Mp4Info[$i].FSoffset + $partPos
                [void]$Mp4Info[$i].fs.read($buffer, $bufferPos, $partLen)
            }else{
                DecryptToBuffer  $Mp4Info  $i $partPos  $buffer  $bufferPos  $partLen
            }

        }elseif ($null -ne $Mp4Info[$i].buffer ){
            [array]::Copy($Mp4Info[$i].buffer, $partPos, $buffer, $bufferPos, $partLen)
        }

        $readSize1 -= $partLen

        $i--
        if ($i -lt 0){ break }
        if ($Mp4Info[$i].fs -eq $null -and  $null -eq $Mp4Info[$i].buffer) {break}

        $partLen = $Mp4Info[$i].length
        $partPos = 0
        if ($readSize1 -lt $partLen){
            $partPos = $partLen - $readSize1
            $partLen = $readSize1
        }
    
        $bufferPos = $readSize1 - $partLen
    }#end of while
    return $bufferPos
}
function BmBackward{
    param($Mp4Info, [int32]$i, [int32]$offset,
        $pattern,  [uint32]$searchSize = 20MB, $Bc = $null, $Gs = $null
    )

    if ($i -lt 0){ $i = $Mp4Info.count + $i }

    if ($Mp4Info[$i].fs -eq $null -and  $null -eq $Mp4Info[$i].buffer){
        return -1
    }
    
    if ($offset -lt 0){ $offset = $Mp4Info[$i].length + $offset}
    if ( $Mp4Info[$i].Mp4offset + $offset + 1 -gt $Mp4Info[0].Mp4Size){
        $offset = $Mp4Info[0].Mp4Size - $Mp4Info[$i].Mp4offset - 1
    }
    

    $buffer = new-object byte[]($searchSize)

    $rangeStart = readBackward $Mp4Info  $i  $offset  $searchSize  $buffer
    $rangeEnd = $searchSize
    
    if ($rangeEnd - $rangeStart -lt $pattern.length){
        write-host moov not found
        $buffer = $null
        return -1  # moovPos
    }
    #==================================
    if ($null -eq $Bc -or $null -eq $Gs){
        $Bc = @( $pattern.Length ) * 256

        for ( $i = $pattern.Length - 1 ; $i -ge 1  ; $i-- ){
            [int]$badChar = $pattern[$i]
            $Bc[ $badChar ] =  $i
        }

        #=====
        $Gs = @( $pattern.Length ) * $pattern.Length
        $good = 0
        $defaultMove = $pattern.Length

        for($test = $pattern.Length - 1; $test -ge 1; $test--){
            $g = $good
            $t = $test

            for ( ; $t -le $pattern.Length - 1 ; $g++,$t++){
                if ($pattern[$g] -ne $pattern[$t]) {break}
            }

            if ($t -eq $test){
                $Gs[$pattern.Length - $t ] = $defaultMove
            }elseif($t -eq $pattern.Length){
                $Gs[$g] = $test - $good

                $defaultMove = $test - $good
            }else{
                $Gs[$g] = $test - $good
            }
        }

        $Gs[0] = 1
    }
    #==================================

    $bufferPos = $rangeEnd - $pattern.length

    while ($bufferPos -ge $rangeStart){
        for ($i = 0; $i -lt $pattern.length -and $pattern[$i] -eq $buffer[$bufferPos + $i]; $i++){}
    
        if ($i -eq $pattern.length){
            break
        }else{
            if ($Bc[  $buffer[$bufferPos+$i] ] - $i -gt $Gs[$i]){
                $bufferPos -= $Bc[  $buffer[$bufferPos+$i] ] - $i
            }else{
                $bufferPos -= $Gs[$i]
            }
        }
    }#end of while 
    $buffer = $null

    if ($bufferPos -lt $rangeStart){
        return -1
    }else{
        return  $bufferPos
    }
}

function readForward($Mp4Info, [int32]$i, [int32]$offset, [uint32]$readSize, $buffer){
    $partLen = $Mp4Info[$i].length - $offset
    $partPos = $offset
    if ($readSize -lt $partLen){ $partLen = $readSize }

    $bufferPos = 0

    $readSize1 = $readSize
    while($readSize1 -gt 0){
        if ($Mp4Info[$i].fs -ne $null){
            if ($Mp4Info[$i].aes -eq $null){
                $Mp4Info[$i].fs.position = $Mp4Info[$i].FSoffset + $partPos
                [void]$Mp4Info[$i].fs.read($buffer, $bufferPos, $partLen)
            }else{
                DecryptToBuffer  $Mp4Info  $i $partPos  $buffer  $bufferPos  $partLen
            }

        }elseif ($null -ne $Mp4Info[$i].buffer){
            [array]::Copy($Mp4Info[$i].buffer, $partPos, $buffer, $bufferPos, $partLen)
        }

        $readSize1 -= $partLen
        $bufferPos += $partLen

        $i++
        if ($i -eq $Mp4Info.count){ break }
        if ($Mp4Info[$i].fs -eq $null -and $null -eq $Mp4Info[$i].buffer) {break}

        $partLen = $Mp4Info[$i].length
        if ($i -eq $Mp4Info.count - 1){
            if ($Mp4Info[-1].Mp4offset + $Mp4Info[-1].length -gt  $Mp4Info[0].Mp4Size){
                $partLen = $Mp4Info[0].Mp4Size - $Mp4Info[-1].Mp4offset
            }
        }
        $partPos = 0
        if ($readSize1 -lt $partLen){ $partLen = $readSize1 }
    
    }#end of while
    return $bufferPos
}
function BmForward{
    param($Mp4Info, [int32]$i, [int32]$offset,
        $pattern,  [uint32]$searchSize = 20MB, $Bc = $null, $Gs = $null
    )

    if ($i -lt 0){ $i = $Mp4Info.count + $i }

    if ($Mp4Info[$i].fs -eq $null -and $null -eq $Mp4Info[$i].buffer){
        return -1
    }
    
    if ($offset -lt 0){ $offset = $Mp4Info[$i].length + $offset}
    

    $buffer = new-object byte[]($searchSize)

    $rangeStart = 0
    $rangeEnd = readForward $Mp4Info  $i  $offset  $searchSize  $buffer
    
    if ($rangeEnd - $rangeStart -lt $pattern.length){
        write-host moov not found
        $buffer = $null
        return -1  # moovPos
    }
    #==================================
    if ($null -eq $Bc -or $null -eq $Gs){
        $Bc = @( $pattern.Length ) * 256

        for ( $i = 0 ; $i -le $pattern.Length - 2  ; $i++ ){
            [int]$badChar = $pattern[$i]
            $Bc[ $badChar ] = $pattern.Length - 1 - $i
        }

        #=====
        $Gs = @( $pattern.Length ) * $pattern.Length
        $good = $pattern.Length - 1
        $defaultMove = $pattern.Length
        
        for($test = 0; $test -le $pattern.Length - 2; $test++){
            $g = $good
            $t = $test
        
            for ( ; $t -ge 0 ; $g--,$t--){
                if ($pattern[$g] -ne $pattern[$t]) {break}
            }
        
            if ($t -eq $test){
                $Gs[$good - $test -1 ] = $defaultMove
            }elseif($t -eq -1){
                $Gs[$g] = $good - $test
        
                $defaultMove = $good - $test
            }else{
                $Gs[$g] = $good - $test
            }
        }
        
        $Gs[$pattern.Length - 1] = 1
    }
    #==================================

    $bufferPos = 0

    while ($bufferPos -lt $rangeEnd - $pattern.Length + 1){
        for ($i = $pattern.Length - 1; $i -ge 0 -and $pattern[$i] -eq $buffer[$bufferPos + $i]; $i--){}
    
        if ($i -eq -1){
            break
        }else{
            $badChar = $buffer[$bufferPos + $i]
            $B_move = $Bc[ $badChar ] - ($pattern.Length -1 - $i)

            if ($B_move -gt $Gs[$i]){
                $bufferPos += $B_move
            }else{
                $bufferPos += $Gs[$i]
            }
        }
    }#end of while 
    $buffer = $null

    if ($bufferPos -ge $rangeEnd - $pattern.Length + 1){
        return -1
    }else{
        return  $bufferPos
    }
}

function DecryptToBuffer($Mp4Info, $i, $partPos, $buffer, $bufferPos, $Len){    
    $n = $partPos % 16

    if ($partPos -ge 16){
        $Mp4Info[$i].fs.Position = $Mp4Info[$i].FSoffset + $partPos - $n - 16
        $blockIV = New-Object byte[] 16
        [void]$Mp4Info[$i].fs.read($blockIV, 0, 16)

        $cs = new-object System.Security.Cryptography.CryptoStream (
            $Mp4Info[$i].fs,
            $Mp4Info[$i].aes.CreateDecryptor($Mp4Info[$i].aes.key, $blockIV),
            0
            )
        $blockIV = $null

    }else{
        $Mp4Info[$i].fs.Position = $Mp4Info[$i].FSoffset
        $cs = new-object System.Security.Cryptography.CryptoStream (
            $Mp4Info[$i].fs, $Mp4Info[$i].aes.CreateDecryptor(), 0
            )
    }

    $blockSkip = new-object byte[] 16
    [void]$cs.read($blockSkip, 0, $n)

    [void]$cs.read($buffer, $bufferPos, $Len)
    $cs = $null
    $blockSkip = $null
}


function overlap($a, $b, $aIsSure, $midPackSize){
    $searchLen0 = 0
    $sInfo0 = $null
    $sIndex0 = $null
    $sPos0 = $null
    $sDirection0 = $null
    $pattern0 = $null
        
        $j = 1
    for ($i = 1; $i -lt $a.count; $i++){
        if ($a[$i].fs -ne $null -or $null -ne $a[$i].buffer){
            for (; $j -lt $b.count; $j++){
                if ($a[$i].Mp4offset -lt $b[$j].Mp4offset ){
                    break
                }
            }
            $j--
           
            if ($b[$j].fs -ne $null -or $null -ne $b[$j].buffer){

                $bPartPos = $a[$i].Mp4offset - $b[$j].Mp4offset

                $aLen = $a[$i].length
                for ($i2 = $i+1; $i2 -lt $a.count; $i2++){
                    if ($a[$i2].fs -ne $null -or $null -ne $a[$i2].buffer){ $aLen += $a[$i2].length}else{break}
                }
                $bLen = $b[$j].length - $bPartPos
                for ($j2 = $j+1; $j2 -lt $b.count; $j2++){
                    if ($b[$j2].fs -ne $null -or $null -ne $b[$j2].buffer){$ $bLen += $b[$j2].length}else{break}
                }

                if ($aLen -gt 16 -and $bLen -gt 16){
                    $sameByteLen = 16
                }elseif ($aLen -gt $bLen){
                    $sameByteLen = $bLen
                }else{
                    $sameByteLen = $aLen
                }

                $aLenB = $sameByteLen
                for($i2 = $i-1; $i2 -ge 0; $i2--){
                    if ($a[$i2].fs -ne $null -or $null -ne $a[$i2].buffer){$aLenB += $a[$i2].length}else{break}
                }

                $bLenB = $bPartPos + $sameByteLen
                for($j2 = $j-1; $j2 -ge 0; $j2--){
                    if ($b[$j2].fs -ne $null -or $null -ne $b[$j2].buffer){$bLenB += $b[$j2].length}else{break}
                }
                <#
                write-host "`$aLen $aLen"
                write-host "`$aLenB $aLenB"
                write-host "`$bLen $bLen"
                write-host "`$bLenB $bLenB"
                #>
                #=============================

                
                [byte[]]$sameByteA = New-Object byte[] $sameByteLen
                readForward $a  $i  0  $sameByteLen  $sameByteA > $null

                [byte[]]$sameByteB = New-Object byte[] $sameByteLen
                readForward $b  $j  $bPartPos  $sameByteLen  $sameByteB > $null

                if ("$sameByteA" -eq "$sameByteB"){return 0}

                if ($aIsSure){
                    if ($aLenB -gt $bLen){
                        $searchLen = $aLenB
                        $sInfo = $a
                        $sIndex = $i
                        $sPos = $sameByteLen - 1
                        $sDirection = 'left'
                        $pattern = $sameByteB
                    }else{
                        $searchLen = $bLen
                        $sInfo = $b
                        $sIndex = $j
                        $sPos = $bPartPos
                        $sDirection = 'right'
                        $pattern = $sameByteA
                    }
                }else{
                    if ($aLen -gt $bLenB){
                        $searchLen = $aLen
                        $sInfo = $a
                        $sIndex = $i
                        $sPos = 0
                        $sDirection = 'right'
                        $pattern = $sameByteB
                    }else{
                        $searchLen = $bLenB
                        $sInfo = $b
                        $sIndex = $j
                        $sPos = $bPartPos + $sameByteLen - 1
                        $sDirection = 'left'
                        $pattern = $sameByteA
                    }
                }

                if ($searchLen -gt $searchLen0){
                    $searchLen0 = $searchLen
                    $sInfo0 = $sInfo
                    $sIndex0 = $sIndex
                    $sPos0 = $sPos
                    $sDirection0 = $sDirection
                    $pattern0 = $pattern
                }
                if ($searchLen0 -gt $midPackSize){break}
            }# end of if
            
        }# end of if $a[$i].fs -ne $null
    }#end of for

    if ($sDirection0 -eq 'right'){
        $r = BmForward  $sInfo0  $sIndex0  $sPos0  $pattern0  $searchLen0
        if ($r -ge $searchLen0){return -1}
    }else{
        $r = BmBackward  $sInfo0  $sIndex0  $sPos0  $pattern0  $searchLen0
        if ($r -lt 0){return -1}
        $r = $searchLen0 - $pattern0.length - $r
    }

    return $r
}
function addPartFromOther($h){
    # need to search other source ?
    if ($script:h0 -eq $null){
        $Mp4Info = $h.Mp4Info
        $needSearch = $false

        for($i = 0; $i -lt $Mp4Info.count; $i++){
            if ($Mp4Info[$i].fs -eq $null -and $null -eq $Mp4Info[$i].buffer){ $needSearch = $true; break }
        }
        if ( ! $needSearch){
            if ($Mp4Info[-1].Mp4offset + $Mp4Info[-1].length -lt $h.FullPack){
                $needSearch = $true
            }
        }
        #================
        if ($needSearch){
            $script:h0 = $h
        
            for ($i = 0; $i -lt $script:otherGroup.count; $i++){
                parseRARs  $script:otherGroup[$i]  $script:buffer
            }
            $script:h0 = $null
            return
        }
    
    }else{ # $script:h0 -ne $null     (add from other source)
        if ($script:h0.Mp4Info[0] -eq $null -and $h.Mp4Info[0] -eq $null){return}
        if ($script:h0.Mp4Info[0] -ne $null -and $h.Mp4Info[0] -ne $null){
            if ($script:h0.Mp4Info[0].otherSrcList.count -eq 0){
                $script:h0.Mp4Info[0].otherSrcList = @()
            }
            $script:h0.Mp4Info[0].otherSrcList += ,$h.Mp4Info
            $h.nextPartN = $null
            return         
        }

        $unSureIsH0 = $false
        if ($script:h0.Mp4Info[0] -eq $null){
            if ($script:h0.FileEncrypt){return}
            $unSure = $script:h0.Mp4Info
            $rarVer = $script:h0.rarVer
            $midPackSize = $script:h0.midPackSize
            $unSureIsH0 = $true

            $sure = $h.Mp4Info
        }else{
            if ($h.FileEncrypt){return}
            $unSure = $h.Mp4Info
            $rarVer = $h.rarVer
            $midPackSize = $h.midPackSize

            $sure = $script:h0.Mp4Info
        }

        # $unSure guess Mp4offset
        $BaseName = [IO.Path]::GetFileNameWithoutExtension($unSure[1].fs.name)
        $shiftSize = $midPackSize * ( -1 + $( $BaseName -replace '.*part','' ))
        if ($rarVer -eq 5){ $shiftSize += 1 }
            
        for ($i = 1; $i -lt $unSure.count; $i++){
            $unSure[$i].Mp4offset += $shiftSize
        }
        $unSure[0] = @{ fs = $null; length = $shiftSize; Mp4offset = 0 
                Mp4Name = $unSure[1].Mp4Name; Mp4Size = $unSure[1].Mp4Size}

        
        $Mp4offset = $unSure[-1].Mp4offset + $unSure[-1].length
        $nEmpty = $unSure[0].Mp4Size - $Mp4offset 
        if ($nEmpty){
            [void]$unSure.add( @{fs = $null; Mp4offset = $Mp4offset; length = $nEmpty}  )
        }
        

        $r = overlap  $unSure $sure $false $midPackSize
        if ($r -lt 0){ $r = overlap  $sure $unSure $true $midPackSize }

        if ($r -lt 0){
            $h.Mp4Info | %{
                if ($_.fs -ne $null) {$_.fs.close()}
            }
            $h.nextPartN = $null

            if ($unSureIsH0){
                for ($i = 1; $i -lt $unSure.count; $i++){
                    $unSure[$i].Mp4offset -= $shiftSize
                }
                $unSure[0] = $null
                if ($unSure[-1].fs -eq $null){
                    $unSure.RemoveAt($unSure.count - 1)
                }
            }
            return
        }

        if ($r -gt 0){
            for ($i = 1; $i -lt $unSure.count; $i++){
                $unSure[$i].Mp4offset -= $r
            }
            $unSure[0].length = $shiftSize - $r
            $unSure[-1].length += $r

            if ($unSure[1].aes -ne $null){
                adjustRange  $unSure
            }
        }
        # if ($r -eq 0) no need edit

        if ($script:h0.Mp4Info[0].otherSrcList.count -eq 0){
            $script:h0.Mp4Info[0].otherSrcList = @()
        }

        $script:h0.Mp4Info[0].otherSrcList += ,$h.Mp4Info
        $h.nextPartN = $null
    }

}
function mp4Ending($h){
    if ($h.nextPartN -eq $null){return}

    $Mp4Info = $h.Mp4Info

    if ($Mp4Info[0] -ne $null){
        if ($Mp4Info[-1].Mp4offset + $Mp4Info[-1].length -lt $Mp4Info[0].Mp4Size){
            $Mp4offset = $Mp4Info[-1].Mp4offset + $Mp4Info[-1].length
            $nEmpty = $Mp4Info[0].Mp4Size - $Mp4offset
            [void]$Mp4Info.add( @{fs = $null; Mp4offset = $Mp4offset; length = $nEmpty}  )

            if ($h.FileEncrypt){ adjustRange $Mp4Info }
        }
    }

    if ($script:searchOtherSrc){
        addPartFromOther $h
        if ($script:h0 -ne $null){ return }
    }

    #=========================================
    
    if ($Mp4Info[0].fs -eq $null -and $null -eq $Mp4Info[0].otherSrcList){
        $r = $false
        if ($h.Mp4FullName_now -match '\.mp4$'){
            
            $r = rebuildMp4 $Mp4Info
        }
        if ( !$r ){ #rebuild fail
            $Mp4Info | %{
                if ($_.fs -ne $null) {$_.fs.close()}
            }
            $h.nextPartN = $null
            return
        }

    }
    
    $script:Mp4NameList += $Mp4Info[0].Mp4Name
    $script:Mp4InfoList += ,$Mp4Info

    $h.nextPartN = $null
}

function parseRARs($rarFiles, $buffer){
    if ($null -eq $rarFiles){return}
    
    $h = @{
        Mp4Info = $null; nextPartN = $null
        Mp4FullName_now = $null; Mp4Size_now = $null
        FullPack = $null; midPackSize = $null; nEmpty = $null
        aesKeyIV = $null; FileEncrypt = $null
        aesAll = $null
        rarVer = $null; fsForType0 = $null
    }

    $rarFiles | %{
        trap{$fs.close(); return}
        
        $fs = $_.OpenRead()
        #=============check RAR signature============
        $n = $fs.read($buffer , 0 , 8)
        if ($n -lt 8) {throw "$_ file is too small"}
    
        if ( [BitConverter]::ToString($buffer,0,7) -eq '52-61-72-21-1A-07-00'){
            # RAR4
            $fs.Position = 7
            $h.rarVer = 4
            $getHeader = $script:getHeader4
            
        }elseif ( [BitConverter]::ToString($buffer,0,8) -eq '52-61-72-21-1A-07-01-00'){
            # RAR5
            $h.rarVer = 5
            $getHeader = $script:getHeader5
        } else {
            $fs.close(); Write-Host "$_ is not RAR";return
        }

        #=============read main header===============
        $HeadEncrypt = beforeFileHeader $getHeader $h  $fs  $buffer  $_
        $h.fsForType0 = $null
        while ($fs.Position -lt $fs.length ){
            #==============read file header==============
            $PackType, $PackOffset, $PackSize =  parseFileHeader $getHeader $h $fs  $buffer  $_  $HeadEncrypt
            
            if ($PackType -eq 1 -or $PackType -eq 0){
                if ($h.nextPartN){mp4Ending  $h}
            }

            #===Is this block  the last block need to be processed in this file ? ===
            switch -w  ($PackType) {
                #First pack  or Middle pack
                #After this block , no content in this  file need to be processed
                [23]{ $fs.close(); return }
    
                [019]{ # normal pack  or last pack or $HeadTypeName -ne 'File'
                    if ($PackOffset + $PackSize -gt $fs.length) {
                        $fs.close(); return
                    }else{
                        $fs.Position = $PackOffset + $PackSize
                    }
                }
            } # end of switch
        }#end of while
    
        $fs.close()
    }
    
    if ($h.nextPartN -ne $null) {mp4Ending $h}
}

$RarVolumeType=@'
#Learn from   Pismo File Mount Development Kit   samples\hellofs_cs\hellofs.cs
class RarVolume: Pfm+FormatterDispatch{
    $openRoot
    $openMp4s
    $Mp4InfoList
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
            for ($i=0; $i -lt $this.Mp4InfoList.count; $i++){
                if($op.NameParts()[0].ToLowerInvariant() -eq $this.Mp4InfoList[$i][0].Mp4Name.ToLowerInvariant()){
                    if ($this.openMp4s[$i].openId -eq 0) {$this.openMp4s[$i].openId = $op.NewExistingOpenId() }
                    $existed = $true
                    $endName = $this.Mp4InfoList[$i][0].Mp4Name
                    $openAttribs = $this.openMp4s[$i]
                    break
                }
            }
            if ($i -eq $this.Mp4InfoList.count){$perr = [Pfm]::errorNotFound}

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

    }else{ for ($i=0; $i -lt $this.openMp4s.count;$i++){
            if ($op.OpenId() -eq $this.openMp4s[$i].openId){
                $openAttribs = $this.openMp4s[$i]
            }
        }
        if ($i -eq $this.openMp4s.count){$perr = [Pfm]::errorNotFound}
    }

    $op.Complete( $perr, $openAttribs, $null)
}

[void] List( [Pfm+MarshallerListOp] $op){
    $perr = 0
    if ($op.OpenId() -ne $this.openRoot.openId){
        $perr = [Pfm]::errorAccessDenied
    }else{
        for ($i=0; $i -lt $this.openMp4s.count;$i++){
            $op.Add( $this.openMp4s[$i].attribs, $this.Mp4InfoList[$i][0].Mp4Name)
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

    for ($i=0; $i -lt $this.openMp4s.count;$i++){
        if ($op.OpenId() -eq $this.openMp4s[$i].openId){break}
    }

    if ($i -eq $this.openMp4s.count){
        $perr = [Pfm]::errorAccessDenied
    }else{
        $actualSize = $op.RequestedSize()
        $aFileSize = $this.openMp4s[$i].attribs.fileSize
        $currentMp4offset = $op.FileOffset()

        if ($currentMp4offset -ge $aFileSize){
            $actualSize = 0
        }elseif ( (  $currentMp4offset + $op.RequestedSize()) -gt $aFileSize){
            $actualSize = $aFileSize - $currentMp4offset
        }

        if ($actualSize -ne 0){
            $this.read2($data, 0, $currentMp4offset, $actualSize, $this.Mp4InfoList[$i])
        }
    }

    $op.Complete($perr, $actualSize)
}

[void]Read2($data, $dataPos, $currentMp4offset, $actualSize, $aMp4Info){ 
    for ( $j = 1 ; $j -lt $aMp4Info.count ; $j++ ){
        if ($currentMp4offset  -lt $aMp4Info[$j].Mp4offset ){break}
    }					
    $j--

    $actualSize1 = $actualSize

    while ($actualSize1 -gt 0){
        $partPos = $currentMp4offset - $aMp4Info[$j].Mp4offset
        $partLen = $aMp4Info[$j].length - $partPos

        if ($actualSize1 -gt $partLen ){
            $readSize = $partLen
        }else{
            $readSize = $actualSize1
        }
        
        if ($aMp4Info[$j].fs -ne $null ){ # fs or cs
            if ($aMp4Info[$j].aes -eq $null){ # fs
                $aMp4Info[$j].fs.Position = $aMp4Info[$j].FSoffset + $partPos
                [void]$aMp4Info[$j].fs.read($data , $dataPos, $readSize)
            }else{ # cs
                $n = $partPos % 16

                if ($partPos -ge 16){

                    $aMp4Info[$j].fs.Position = $aMp4Info[$j].FSoffset + $partPos - $n - 16
                    $blockIV = New-Object byte[] 16
                    [void]$aMp4Info[$j].fs.read($blockIV, 0, 16)

                    $cs = new-object System.Security.Cryptography.CryptoStream (
                        $aMp4Info[$j].fs,
                        $aMp4Info[$j].aes.CreateDecryptor($aMp4Info[$j].aes.key, $blockIV),
                        0
                        )
                    $blockIV = $null

                }else{
                    $aMp4Info[$j].fs.Position = $aMp4Info[$j].FSoffset
                    $cs = new-object System.Security.Cryptography.CryptoStream (
                        $aMp4Info[$j].fs, $aMp4Info[$j].aes.CreateDecryptor(), 0
                        )
                }

                $blockSkip = new-object byte[] 16
                [void]$cs.read($blockSkip, 0, $n)

                [void]$cs.read($data, $dataPos, $readSize )
                $cs = $null
                $blockSkip = $null
            }
        }else{ # fs  $null
            if ($aMp4Info[$j].buffer.count -ne 0){
                [array]::Copy($aMp4Info[$j].buffer, $partPos, $data, $dataPos, $readSize)
            }else{
                [array]::Clear($data, $dataPos, $readSize)

                if ($aMp4Info[0].otherSrcList.count -ne 0){
                    foreach ($Mp4Info2 in $aMp4Info[0].otherSrcList){
                        $this.read2($data, $dataPos, $currentMp4offset, $readSize, $Mp4Info2)
                    }
                }
            }
            
        }
        $partPos = 0

        if ($actualSize1 -gt $partLen ){
            $actualSize1 -= $partLen
            $dataPos += $partLen
            $currentMp4offset += $partLen 
            $j++
            $partLen = $aMp4Info[$j].length
        }else{
            $actualSize1 = 0
        }
    }

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
        for ($i=0; $i -lt $this.openMp4s.count;$i++){
            if ($op.OpenId() -eq $this.openMp4s[$i].openId){
                $openAttribs = $this.openMp4s[$i]
            }
        }
        if ($i -eq $this.openMp4s.count){$perr = [Pfm]::errorNotFound}
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

function startMount($autoOpen, $driveLetter, $MoutName, $Mp4InfoList){
    #ReadOnly  UnmountOnRelease
    $mountFlags = 0x20001
    if ($autoOpen){$mountFlags = 0x20001 -bor 0x10000}
    $mcp = new-object Pfm+MountCreateParams -prop @{
        mountFlags = $mountFlags
        driveLetter = $driveLetter
        mountSourceName = $MoutName  }
    <#
    $srtFile = gi 'R:\test\Parasite.2019.BluRay.1080p.srt'
    $srtFileSize = $srtFile.Length
    #$srtBuffer = New-Object byte[]  $srtFileSize
    $srtBuffer = [io.file]::ReadAllBytes($srtFile)
    #this not work ?
    #$srtBuffer = gc 'R:\test\Parasite.2019.BluRay.1080p.srt' -enc byte
    [System.Collections.ArrayList]$srtInfo = @()
    $srtInfo.add(@{fs = $null; buffer = $srtBuffer ; Mp4offset = 0; length = $srtFileSize
            Mp4Name = $srtFile.Name; Mp4Size = $srtFileSize
    })
    $Mp4InfoList += ,$srtInfo
    #>
    $openMp4s=@()
    for ($i ,$j = 0,3; $i -lt $Mp4InfoList.count;$i++,$j++){
        $openMp4s += 	new-object Pfm+OpenAttribs -prop @{
                openSequence = 1 ; accessLevel = [Pfm]::accessLevelReadData;
                attribs = new-object Pfm+Attribs -prop @{fileType = [Pfm]::fileTypeFile ; 
                fileId = $j;fileSize=$Mp4InfoList[$i][0].Mp4Size}
                }
    }


    $msp = new-object Pfm+MarshallerServeParams  -prop @{
        volumeFlags = 1
        dispatch = new-object RarVolume  -prop @{
            Mp4InfoList = $Mp4InfoList ; openMp4s = $openMp4s
        }
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
}
#======================================================
$rarFiles, $otherGroup =  findRar $args[0]
checkPfm $dllDir


$Mp4NameList = @()
$Mp4InfoList = @()
$h0 = $null

$buffer = new-object byte[](20kb)

parseRARs $rarFiles $buffer

if ($Mp4InfoList.count -eq 0) {Write-Host 'mp4 not found';pause;exit}

Invoke-Expression $RarVolumeType
startMount $autoOpen $driveLetter $MoutName $Mp4InfoList