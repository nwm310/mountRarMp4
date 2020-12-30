param([string]$rarFilePath = '')

#==================Edit Area================
$driveLetter = 'Z'
$MoutName = "thanks for sharing"
$autoOpen = $true
$dllDir = ''

#Check PS 5.0
if ($host.Version.Major -lt 5){Write-Host 'NEED PowerShell 5.0';pause;exit}
#=============Functions、Classes =====================
function checkPfm(){
    if ($script:dllDir -ne ''){
        pushd -literal $script:dllDir
    }else{
        pushd '.'
    }
    
    $dllFles = @(gi pfmclr_[0-9][0-9][0-9].dll , pfmshim16_[0-9][0-9][0-9].dll )

    if ($dllFles.count -ne 2){
        Write-Host 'Need DLLs or too many DLLs'; pause; popd; exit
    }else{
        Add-Type -Path $dllFles[0]
    }

    if ( ! ('pfm' -as [type])){
        Write-Host 'Dlls are not loaded'; pause; popd; exit
    }

    $pfmApi = $null
    $err = [Pfm]::ApiFactory([ref]$pfmApi)
    if($err -ne 0){Write-Host '"Pismo File Mount Audit Package" was not installed'; pause; popd; exit}

    popd
}

function startMount($rarFilePath, $autoOpen, $driveLetter, $MoutName){
    #ReadOnly (0x00000001)  UnmountOnRelease (0x00020000)
    #WorldWrite (0x00000008)
    $mountFlags = 0x20001
    if ($autoOpen){$mountFlags = 0x20001 -bor 0x10000}
    $mcp = new-object Pfm+MountCreateParams -prop @{
        mountFlags = $mountFlags
        driveLetter = $driveLetter
        mountSourceName = $MoutName  }

    $msp = new-object Pfm+MarshallerServeParams  -prop @{
        volumeFlags = 1
        dispatch = [RarVolume]::new($rarFilePath)
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

class RAR {
    [byte]$Ver = 4
    [bool]$IsMultiVolume = $false

    [bool]$IsHeadEncrypt = $false
    [System.Security.Cryptography.AesCryptoServiceProvider]$AesForAll = $null
    static [string]$SHA1SPdef =  @'
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
    [hashtable]$AesTable = @{}
    [string]$password = ''

    [rarEntry[]]$Entries = @()
    [hashtable]$FsTable = @{}

    #=============================
    RAR([string]$rarFilePath){
        $file = gi -literal $rarFilePath 2>$null
        if ($file -eq $null){throw "$rarFilePath is not exist"}
        if ($file.PSIsContainer){throw "$rarFilePath is not a file"}
        if ($file.Extension -ne '.rar'){throw "$rarFilePath is not a rar file"}

        $files = @()
        if ($file.name -match '(?<name>.*)\.part(?<num>\d+)\.rar'){ # multiVolumes
            $this.IsMultiVolume = $true
            $name = $matches.name
            $Len = $matches.num.length

            $files += dir -literal $file.directory -filter "$name*.part*.rar" -file |?{
                $_.name -match "\d{$Len}\.rar$"
            } | sort

        }else{ # single file
            $files += $file
        }

        trap {$fs.close()}
        $buffer = new-object byte[](20KB)
        
        foreach ($file in $files) {
            $fs = $file.OpenRead()
            $this.FsTable[$file] = $fs
            $this.beforeFileHeader($fs, $buffer)
            $this.parseFileHeader($fs, $buffer, $file)
        }        
        $buffer = $null

    }#end of Ctor

    [void]beforeFileHeader([IO.FileStream]$fs, [byte[]]$buffer){

        $n = $fs.read($buffer , 0 , 8)
        if ($n -lt 8) {throw "$($fs.Name) : file size is too small"}
    
        if ([BitConverter]::ToString($buffer,0,7) -eq '52-61-72-21-1A-07-00'){
            $this.Ver = 4
            $fs.Position = 7
            $result = $this.getHeader4($fs, $buffer, $null)
            
            if ($result.HeadTypeName -ne 'Main') {throw "$($fs.Name) : Main header error"}
            
            if ($result.IsEncrypt){
                $this.IsHeadEncrypt = $result.IsEncrypt
                $this.AesForAll = $this.getAes($this.Ver, $this.password, $result.Salt, $null, $null)
            }
    
        }elseif ([BitConverter]::ToString($buffer,0,8) -eq '52-61-72-21-1A-07-01-00'){
            $this.Ver = 5
            $result = $this.getHeader5($fs, $buffer, $null)

            if ($result.HeadTypeName -ne 'Main' -and $result.HeadTypeName -ne 'Encryption'){
                throw "$($fs.Name) : Main header error"
            }

            if ($result.IsEncrypt){
                $this.IsHeadEncrypt = $result.IsEncrypt
                $this.AesForAll = $this.getAes($this.Ver, $this.password, $result.Salt, $result.KDFcount, $result.checkValue)
                
                [byte[]]$iv = new-object byte[] 16
                $n = $fs.read($iv, 0, 16)
                if ($n -lt 16) {throw "$($fs.Name) : file size is too small"}
                $this.AesForAll.IV = $iv

                $cs = new-object System.Security.Cryptography.CryptoStream (
                    $fs, $this.AesForAll.CreateDecryptor(), 0
                )

                $result = $this.getHeader5($cs, $buffer, $fs)
    
                if ($result.HeadTypeName -ne 'Main'){;throw "$($fs.Name) : Main header error"}
                $cs = $null

            }# end of if ($result.IsEncrypt)

        }else{throw "$($fs.Name) is not RAR"}
    }

    [void]parseFileHeader([IO.FileStream]$fs, [byte[]]$buffer, [IO.FileInfo]$fileInfo){

        while ($fs.Position -lt $fs.length){

            # read header
            if ($this.Ver -eq 4){
                if ($this.IsHeadEncrypt){
                    # salt already read
                    # all salts are the same.  skip it
                    $fs.position += 8
    
                    $cs = new-object System.Security.Cryptography.CryptoStream (
                        $fs, $this.AesForAll.CreateDecryptor(), 0
                    )
    
                    $result = $this.getHeader4($cs, $buffer, $fs)
                    $cs = $null
                
                }else{
                    $result = $this.getHeader4($fs, $buffer, $null)
                }
    
            }elseif ($this.Ver -eq 5){
                if ($this.IsHeadEncrypt){
                    $iv = new-object byte[] 16
                    $n = $fs.read($iv, 0, 16)
                    if ($n -lt 16) {throw "$($fs.Name) : file size is too small"}
            
                    $this.AesForAll.IV = $iv
            
                    $cs = new-object System.Security.Cryptography.CryptoStream (
                        $fs, $this.AesForAll.CreateDecryptor(), 0
                    )
            
                    $result = $this.getHeader5($cs, $buffer, $fs)
                    $cs = $null
                }else{
                    $result = $this.getHeader5($fs, $buffer, $null)
                }
            
            }else{throw 'RAR version error'}

            if ($result.HeadTypeName -eq 'File'){
                [rarEntry]$entry = [rarEntry]::new($result)
                $entry.rarFileInfo = $fileInfo

                if ($result.PackOffset + $result.PackSize -gt $fs.length) {
                    $entry.ActualPackSize = $fs.length - $result.PackOffset
                }else{
                    $entry.ActualPackSize = $result.PackSize
                }
                
                if ($this.IsHeadEncrypt){
                    $entry.Aes = $this.AesForAll
                }elseif ($result.IsEncrypt){
                    $entry.Aes = $this.getAes($this.Ver, $this.password, $result.Salt, $result.KDFcount, $result.checkValue)
                }
    
                if ($null -ne $entry.Aes){
                    if ($this.Ver -eq 4){
                        $entry.iv0 = $entry.Aes.IV
                    }else{# Ver 5
                        $entry.iv0 = $result.iv
                    }
                }
                
                $this.Entries += $entry
            }

            #Is this block  the last block need to be processed  ? 
            $PackEnd = $result.PackOffset + $result.PackSize
            switch -w  ($result.PackType) {
                #First pack  or Middle pack
                #no block after this block  need to be processed
                [23]{return}
    
                [01]{ # normal pack  or last pack
                    
                    if ($PackEnd -gt $fs.length) {
                        return
                    }else{
                        $fs.Position = $PackEnd
                    }
                }
                default{$fs.Position = $PackEnd}
            }
        }    
    }

    [PSCustomObject]getHeader4($fs, [byte[]]$buffer, [IO.FileStream]$fs0){
        
        $HeadTypeName = $IsEncrypt = $Salt = 
        $PackType = $PackOffset = $PackSize =
        $FullName = $FileSize = $IsCompress = $IsDir =
        $KDFcount = $iv = $checkValue = $FileLinkType = $targetName = $false

        $n = $fs.read($buffer, 0, 7)
        if ($n -lt 7) {throw "$($fs.Name) : file size is too small"}
        
        $HeadType = $buffer[2]
        $HeadFlag = [BitConverter]::ToUInt16($buffer ,3)
        $HeadSize = [BitConverter]::ToUInt16($buffer ,5)
    
        $n = $HeadSize - 7
        $n1 = $fs.read($buffer, 7, $n)
    
        if ($n1 -lt $n) {throw "$($fs.Name) : file size is too small"}
    
        #=============after reading  header into buffer===============
        if ($fs0 -ne $null){ # rar header is encrypted
            $PackOffset = $fs0.position
        }else{
            $PackOffset = $fs.position
        }
        
        switch ($HeadType){
            0x73{
                $HeadTypeName = 'Main'
                if ($HeadFlag -band 0x80){
                    $IsEncrypt = $true
    
                    #read salt after this header
                    $Salt = new-object byte[] 8
                    $n = $fs.read($Salt, 0, 8)
                    if ($n -lt 8) {throw "$($fs.Name) : file size is too small"}
                    # there is a 8 byte salt before every file header
                    $fs.position -= 8
                }
            }
    
            0x74{
                $HeadTypeName = 'File'
                
                $PackSize = [BitConverter]::ToUInt32($buffer, 7)
                $FileSize  = [BitConverter]::ToUInt32($buffer, 11)
    
                #if file size too big 
                if ($HeadFlag -band 0x100){
                    $HighSize = [BitConverter]::ToUInt32($buffer, 32)
                    $PackSize += ([uint64]$HighSize -shl 32)
    
                    $HighSize = [BitConverter]::ToUInt32($buffer, 36)
                    $FileSize += ([uint64]$HighSize -shl 32)
    
                    $namePos = 40
                }else{
                    $namePos = 32
                }
    
                #get file name
                $nameSize = [BitConverter]::ToUInt16($buffer, 26)
                $FullName = $this.RarName4($buffer,  $namePos,  $nameSize)
                
    
                #normal pack ? first pack  ?  middle pack ? last pack ?
                $PackType = $HeadFlag -band 3
    
                if ($HeadFlag -band 4){
                    $IsEncrypt = $true
                    $saltPos = $namePos + $nameSize
                    $Salt = new-object byte[] 8
                    [array]::copy($buffer, $saltPos, $Salt, 0, 8)
                }
    
                if (($HeadFlag -band 0xE0) -eq 0xE0){$isDir = $true}
    
                if ($buffer[25] -ne 0x30) {$IsCompress = $true}
            }#end of 0x74
    
            default{            
                #other block
                if ($HeadFlag -band 0x8000){ 
                    $PackSize = [BitConverter]::ToUInt32($buffer, 7)
                }
            }#end of default
        }#end of switch

        return [PSCustomObject]@{
            HeadTypeName = $HeadTypeName; IsEncrypt = $IsEncrypt; Salt = $Salt
            PackType = $PackType; PackOffset = $PackOffset; PackSize = $PackSize
            FullName = $FullName; FileSize = $FileSize; IsCompress = $IsCompress
            IsDir = $IsDir; KDFcount = $KDFcount; iv = $iv; checkValue = $checkValue
            FileLinkType = $FileLinkType; targetName = $targetName
        }
    }

    [PSCustomObject]getHeader5($fs, [byte[]]$buffer, [IO.FileStream]$fs0){
    
        $HeadTypeName = $IsEncrypt = $Salt = 
        $PackType = $PackOffset = $PackSize =
        $FullName = $FileSize = $IsCompress = $IsDir =
        $KDFcount = $iv = $checkValue = $FileLinkType = $targetName = $false
    
        #Read CRC
        $n = $fs.read($buffer, 0, 4)
        if ($n -lt 4) {throw "$($fs.Name) : file size is too small"}
    
        #Read HeadSize
        $n = $fs.read($buffer, 0, 3)
        if ($n -lt 3) {throw "$($fs.Name) : file size is too small"}
    
        $bPos = 0
        $HeadSize = $this.getVint($buffer, [ref]$bPos)

        #crypto stream can't change position(move back)
        $n1 = $n - $bPos
        #[array]::Copy($buffer, $bPos, $buffer, 0, $n1)
        for ($i = 0; $i -lt $n1; $i++){
            $buffer[$i] = $buffer[$bPos+$i]
        }
        #Read Header into buffer
        $n = $fs.read($buffer, $n1, $HeadSize - $n1)
        if ($n -lt $HeadSize - $n1) {throw "$($fs.Name) : file size is too small"}
        $bPos = 0
    
        #=============after reading  header into buffer===============
        if ($fs0 -ne $null){ # rar header is encrypted
            $PackOffset = $fs0.position
        }else{
            $PackOffset = $fs.position
        }
        
        #Read HeadType  HeadFlag
        $HeadType = $this.getVint($buffer, [ref]$bPos)
    
        $HeadFlag = $this.getVint($buffer, [ref]$bPos)
    
        switch -w ($HeadType){
            #assume that data area is not exist in main block
            1{$HeadTypeName = 'Main'}
    
            [23]{# File header or Service header
                #Extra area size
                if ($HeadFlag -band 1) {
                    $this.getVint($buffer, [ref]$bPos) > $null 
                }
    
                #Data area size
                $PackSize = 0
                if ($HeadFlag -band 2) {
                    $PackSize = $this.getVint($buffer, [ref]$bPos)
                }
    
                if ($_ -eq 2) {
                    $HeadTypeName = 'File'
                }else{#service header
                    $HeadTypeName = 'Service'
                }
    
                #File flags
                $FileFlags = $this.getVint($buffer, [ref]$bPos)
                if ($FileFlags -band 1){$isDir = $true}
    
                #Unpacked size
                $FileSize = $this.getVint($buffer, [ref]$bPos)
    
                #Attributes
                $this.getVint($buffer, [ref]$bPos) > $null
    
                #mtime
                if ($FileFlags -band 2) {$bPos +=4}
    
                #Data CRC32
                if ($FileFlags -band 4) {$bPos +=4}
    
                #Compression information
                if (  ($this.getVint($buffer, [ref]$bPos)) -band 0x0380) {$IsCompress = $true}
    
                #Host OS
                $this.getVint($buffer, [ref]$bPos) > $null
    
    
                #file name length
                $nameSize = $this.getVint($buffer, [ref]$bPos)
    
                #get file name
                $FullName = [System.Text.Encoding]::UTF8.GetString($buffer,$bPos,$nameSize)
                $bPos += $nameSize
    
                #normal pack ? first pack  ?  middle pack ? last pack ?
                $PackType = ($HeadFlag -shr 3) -band 3
    
                #encrypt ?  read extra area
                while ($bPos -lt $HeadSize){
                    $recordSize = $this.getVint($buffer, [ref]$bPos)
                    $recordEnd = $bPos + $recordSize
    
                    if ($recordEnd -gt $HeadSize){break}
                                    
                    #record type
                    $recordType = $this.getVint($buffer, [ref]$bPos)
                    if ($recordType -eq 1){#File encryption record
                        $IsEncrypt = $true
                        
                        #Encryption version
                        $this.getVint($buffer, [ref]$bPos) > $null
    
                        #Encryption flags
                        $eFlag = $this.getVint($buffer, [ref]$bPos)
    
                        #KDF count
                        $KDFcount = $buffer[$bPos++]
    
                        #salt
                        $Salt = new-object byte[] 16
                        [array]::Copy($buffer, $bPos, $Salt, 0, 16)
                        $bPos += 16
                        
                        #iv
                        $iv = new-object byte[] 16
                        [array]::Copy($buffer, $bPos, $iv, 0, 16)
                        $bPos += 16
    
                        #Check value
                        if ($eFlag -band 1){
                            $checkValue = new-object byte[] 12
                            [array]::Copy($buffer, $bPos, $checkValue, 0, 12)
                            $bPos += 12
                        }
    
                    }elseif($recordType -eq 5){#File system redirection record
                        $redirection = $this.getVint($buffer, [ref]$bPos)
                        $flag1 = $this.getVint($buffer, [ref]$bPos)
                        if ($redirection -like '[245]' -and $flag1 -eq 0){
                            $FileLinkType = 'FileCopy'
                            
                            $nameSize= $this.getVint($buffer, [ref]$bPos)

                            $targetName = [System.Text.Encoding]::UTF8.GetString(
                                $buffer, $bPos, $nameSize
                                )
                        }else{
                            $FileLinkType = 'FileOtherLink'
                        }
                        
                    }
                    $bPos = $recordEnd
                }#end of while
            }#end of [23]
    
            4{# Archive encryption header
                $HeadTypeName = 'Encryption'
                $IsEncrypt = $true

                #Encryption version
                $this.getVint($buffer, [ref]$bPos) > $null
    
                #Encryption flags
                $eFlag = $this.getVint($buffer, [ref]$bPos)
    
                #KDF count
                $KDFcount = $buffer[$bPos++]
    
                #salt
                $Salt = new-object byte[] 16
                [array]::Copy($buffer, $bPos, $Salt, 0, 16)
                $bPos += 16
    
                #Check value
                if ($eFlag -band 1){
                    $checkValue = new-object byte[] 12
                    [array]::Copy($buffer, $bPos, $checkValue, 0, 12)
                    $bPos += 12
                }
            }

            5{# End of archive header
            }

            default{
                write-host "unknown header type : $HeadType"
            }
        }# end of switch
    
        return [PSCustomObject]@{
            HeadTypeName = $HeadTypeName; IsEncrypt = $IsEncrypt; Salt = $Salt
            PackType = $PackType; PackOffset = $PackOffset; PackSize = $PackSize
            FullName = $FullName; FileSize = $FileSize; IsCompress = $IsCompress
            IsDir = $IsDir; KDFcount = $KDFcount; iv = $iv; checkValue = $checkValue
            FileLinkType = $FileLinkType; targetName = $targetName
        }
    }

    [string]RarName4([byte[]]$buffer, [uint32]$namePos, [uint32]$nameSize){
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
        $FullName = $null
    
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
                    $FullName += [System.Text.Encoding]::ASCII.GetString($buffer[$i++])
                    $j++
                }
    
                1{# one byte of unicode in encoded area
                    if ($i -ge $nameEnd){break out}
                    $FullName += [System.Text.Encoding]::Unicode.GetString(@($buffer[$i++],$HighByte))
                    $j++
                }
    
                2{# two bytes of unicode in encoded area
                    if ($i+1 -ge $nameEnd){break out}
                    $FullName += [System.Text.Encoding]::Unicode.GetString(@($buffer[$i],$buffer[$i+1]))
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
                            $FullName += [System.Text.Encoding]::Unicode.GetString(
                                @( (($buffer[$j] + $Correction) -band 0xFF) , $HighByte )
                            )
                        }
                    }else{
                        for ($L += 2 ;$L -gt 0 -and $j -lt $nameAnsiEnd ; $L-- ,$j++){
                            $FullName += [System.Text.Encoding]::ASCII.GetString($buffer[$j])
                        }
                    }
                }
            }#end of switch
            $Flags = $Flags -shl 2
            $FlagBits -=2
    
        }#end of while
    
        return $FullName
    }

    [System.Security.Cryptography.AesCryptoServiceProvider]getAes ([byte]$Ver, [string]$password, [byte[]]$salt, [byte]$KDFcount, [byte[]]$checkValue){
      
        #https://github.com/lclevy/unarcrypto
        #https://stackoverflow.com/questions/18648084/rfc2898-pbkdf2-with-sha256-as-digest-in-c-sharp
    
        if ($Ver -eq 4){
            if ($null -ne $this.AesTable."$salt"){
                return $this.AesTable."$salt"
            }

            while ($password -eq ''){
                $local:password = read-host 'password ?'
            }
            
            $this.password = $password

            $seed = [System.Text.Encoding]::Unicode.GetBytes($password) + $salt
            
            # in powershell , must : New-Object to create space , then copy seed to space
            $seedNew = New-Object byte[] $seed.length
            [array]::Copy($seed, 0, $seedNew, 0, $seed.length)
        
            [byte[]]$iv = @(0) * 16
            if ( ! ('SHA1SP.SHA1SP' -as [type])){Add-Type -TypeDef ([RAR]::SHA1SPdef) }
            $sha1 = new-object SHA1SP.SHA1SP
        
            for($i = 0; $i -lt 16; $i++){
                for($j = 0; $j -lt 0x4000; $j++){
                    $count = [System.BitConverter]::GetBytes($i*0x4000 + $j)
                    $sha1.HashCore($seedNew, 0, $seedNew.length) > $null
                    $sha1.HashCore($count, 0, 3) >$null
                    if ($j -eq 0){
                        $hash = $sha1.HashForIV()
                        $iv[$i] = $hash[19]
                    }
                }
            }
            $hash = $sha1.HashFinal()
            [byte[]]$key = $hash[3..0] + $hash[7..4] + $hash[11..8] + $hash[15..12]
    
        }elseif ($Ver -eq 5){

            if ($null -ne $this.AesTable."$checkValue"){
                return $this.AesTable."$checkValue"
            }

            while ($password -eq ''){
                $local:password = read-host 'password ?'
            }
            
            $this.password = $password
    
            while ($true){
                $h256 =  new-object System.Security.Cryptography.HMACSHA256
                $h256.Key = [System.Text.Encoding]::UTF8.GetBytes($password)
        
                $u = $h256.ComputeHash($salt + (0,0,0,1))
                
                $key = $u
              
                $count = 1 -shl $KDFcount
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
        
                if ($null -eq $checkValue){ # have no checkValue
                    break
    
                }else{# have checkValue
                    $check8 = new-object byte[] 8
        
                    for ($i = 0; $i -lt 32; $i++){
                        $check8[$i % 8] = $check8[$i % 8] -bxor $v2[$i]
                    }
        
                    if ("$check8" -eq $checkValue[0..7]){#pass ok
                        break
                        
                    }else{#pass error
                        Write-Host 'password error'
    
                        $local:password = ''
                        while ($password -eq ''){
                            $local:password = read-host 'password ?'
                        }
                        
                        $this.password = $password
                    }
                }
    
            }# end of while

            #rar 5 : iv is not yet set
            [byte[]]$iv = @(0) * 16
            
        }else{throw 'RAR version error'}

        $Aes = new-object System.Security.Cryptography.AesCryptoServiceProvider -Prop @{
            Key = $key
            IV = $iv
        }
        # Padding  none
        $Aes.Padding = 1

        if ($Ver -eq 4){
            $this.AesTable."$salt" = $Aes
        }else{
            $this.AesTable."$checkValue" = $Aes
        }
        
    
        return $Aes
    }

    [uint64]getVint([byte[]]$buffer, [ref]$bPos){
        $bPosOld = $bPos.Value
        
        while ($buffer[$bPos.Value++] -band 0x80) {}
    
        if ( ($bPos.Value - $bPosOld) -gt 9 ){throw 'Vint : too many bytes'}  # 7 * 9 = 63
    
        [uint64]$data = $n = 0
    
        while ($bPosOld -lt $bPos.Value){
            [uint64]$d = $buffer[$bPosOld++] -band 0x7F
            $data +=  $d -shl  (7 * $n++)
        }
        return $data
    }

}

class rarEntry{
    [string]$Name = ''
    [string]$FullName = ''
    [uint64]$Size = 0
    [bool]$IsDir = $false

    [bool]$IsCompress = $false
    [bool]$IsEncrypt = $false
    [byte[]]$iv0 = @()
    [System.Security.Cryptography.AesCryptoServiceProvider]$Aes = $null

    [IO.FileInfo]$rarFileInfo = $null
    [byte]$PackType = 0
    [uint64]$PackOffset = 0
    [uint64]$PackSize = 0
    [uint64]$ActualPackSize = 0

    rarEntry([PSCustomObject]$result){
        $this.FullName = $result.FullName
        $this.Name = Split-Path $result.FullName -Leaf
        $this.Size = $result.FileSize
        $this.IsDir = $result.IsDir

        $this.IsCompress = $result.IsCompress
        $this.IsEncrypt = $result.IsEncrypt
        
        $this.PackType = $result.PackType
        $this.PackOffset = $result.PackOffset
        $this.PackSize = $result.PackSize
    }
}

class File{
    [string]$FullName = ''

    [int]$nameCount = 0
    [int]$fileType = 0
    [int]$fileFlags = 0

    [long]$openId = 0
    [long]$fileId = 0

    [long]$createTime = 0
    [long]$accessTime = 0
    [long]$writeTime = 0
    [long]$changeTime = 0

    [long]$fileSize = 0
    [System.Collections.SortedList]$children = $null

    [bool]$IsEncrypt = $false
    [System.Security.Cryptography.AesCryptoServiceProvider]$Aes = $null
    [PSCustomObject[]]$Parts = @()
    <# members of PSCustomObject
    [IO.FileStream]$fs = $null
    [uint64]$fsOffset = 0
    [uint64]$Len = 0
    [uint64]$MountFileOffset = 0
    [byte[]]$iv0 = $null
    #>

    File([rarEntry]$entry){
        $this.FullName = $entry.FullName
        $this.fileSize = $entry.Size

        if($entry.IsDir){
            $this.fileType = 2
            $this.children = [System.Collections.SortedList]::new()
        }else{
            $this.fileType = 1
        }

        $this.IsEncrypt = $entry.IsEncrypt
        $this.Aes = $entry.Aes
    }

    File([int]$inFileType, [int]$inFileFlags, [long]$inWriteTime){
        $this.fileType = $inFileType
        $this.fileFlags = $inFileFlags
        $this.createTime = $inWriteTime
        $this.accessTime = $inWriteTime
        $this.writeTime = $inWriteTime
        $this.changeTime = $inWriteTime
        $this.children = [System.Collections.SortedList]::new()
    }

    static [File[]]makeFile([rarEntry[]]$entries, [hashtable]$FsTable){
        $result = @(
            for ($i = 0; $i -lt $entries.Count; $i++){

                if ($entries[$i].IsCompress){continue}
                [File]::makeFile($entries, [ref]$i, $FsTable)
            }
        )
        return $result
    }

    static [File]makeFile([rarEntry[]]$entries, [ref]$index, [hashtable]$FsTable){

        $File = $null
        $nextPartN = $nEmpty = $MountFileOffset = $midPackSize = $FullPack = 0

        while($true){
            $entry = $entries[$index.Value]

            # for multi part entry
            [uint32]$partN = 0
            if ($entry.PackType -gt 0){
                $partN = $entry.rarFileInfo.BaseName -replace '.*part',''
            }

            if ($File -eq $null){ # first time meet
                $File = [File]::new($entry)
                $MountFileOffset = $midPackSize = $nEmpty = 0

                $FullPack = $entry.Size
                if ($entry.IsEncrypt -and ($entry.Size % 16)){
                    $FullPack += 16 - ($entry.Size % 16)
                }

                if ($entry.PackType -eq 1 -or $entry.PackType -eq 3) {# first pack missing                
                    $File.Parts += @($null)
                }

            }else{ # meet again

                # missing *.part.rar  or previous pack is not complete
                if ($partN -gt $nextPartN  -or  $nEmpty -gt 0){
                    if ($entry.PackType -eq 3){ # middle pack
                        $nEmpty = $entry.PackSize * ($partN - $nextPartN) + $nEmpty

                        $File.Parts += [PSCustomObject]@{
                            fs = $null
                            fsOffset = 0
                            Len = $nEmpty
                            MountFileOffset = $MountFileOffset
                            iv0 = $null
                        }
                        $MountFileOffset += $nEmpty

                    }else{ # last pack
                        if ($File.Parts[0] -eq $null){ # MountFileOffset is fake
                            $nEmpty = $midPackSize * ($partN - $nextPartN) + $nEmpty

                        }else{# $MountFileOffset is true
                            $nEmpty = $FullPack - $entry.PackSize - $MountFileOffset
                        }

                        $File.Parts += [PSCustomObject]@{
                            fs = $null
                            fsOffset = 0
                            Len = $nEmpty
                            MountFileOffset = $MountFileOffset
                            iv0 = $null
                        }

                        $MountFileOffset = $FullPack - $entry.PackSize
                    }# end of if ($entry.PackType -eq 3){}else

                }# end of if ($partN -gt $nextPartN  -or  $nEmpty -gt 0)
            }# end of if ($mountFile  -eq $null){}else

            if ($entry.PackType -eq 1) {$MountFileOffset = $FullPack - $entry.PackSize}

            $File.Parts += [PSCustomObject]@{
                fs = $FsTable[$entry.rarFileInfo]
                fsOffset = $entry.PackOffset
                Len = $entry.ActualPackSize
                MountFileOffset = $MountFileOffset
                iv0 = $entry.iv0
            }

            $MountFileOffset += $entry.ActualPackSize

            # pack is incomplete ?
            $nEmpty = 0
            if ($entry.ActualPackSize -lt  $entry.PackSize) {
                $nEmpty = $entry.PackSize - $entry.ActualPackSize
            }

            if ($entry.PackType -eq 3) {$midPackSize = $entry.PackSize}

            if ($entry.PackType -eq 2 -or $entry.PackType -eq 3) { # first pack or middle pack
                #next RAR part number
                $nextPartN = 1 + $partN
            }
            
            # single pack or last pack
            if($entry.PackType -eq 0 -or $entry.PackType -eq 1 -or
                ($index.Value+1) -eq $entries.Count -or $entry.FullName -ne $entries[$index.Value+1].FullName ){

                if ($File.Parts[0] -eq $null){
                    if ($entry.PackType -eq 3){$File = $null; continue}

                    if ($entry.PackType -eq 1){ # to correct MountFileOffset

                        $local:parts = $File.Parts

                        if ($parts.count -gt 2){
                            $L = $parts[-1].MountFileOffset - ($parts[-2].MountFileOffset + $parts[-2].Len)
                            1 .. ($parts.Count - 2) | %{ $parts[$_].MountFileOffset += $L }
                        }
                        $local:parts[0] = [PSCustomObject]@{
                            fs = $null
                            fsOffset = 0
                            Len = $parts[1].MountFileOffset
                            MountFileOffset = 0
                            iv0 = $null
                        }
                    }
                }

                if ($MountFileOffset -lt $FullPack){
                    $File.Parts += [PSCustomObject]@{
                        fs = $null
                        fsOffset = 0
                        Len = $FullPack - $MountFileOffset
                        MountFileOffset = $MountFileOffset
                        iv0 = $null
                    }
                }

                if ($File.IsEncrypt){$File.fixFileRange()}
                if ($File.Parts[0].fs -eq $null -and $entry.Name -like '*.mp4'){
                    $r = $File.rebuildMp4Head()
                    if (! $r){$File = $null}
                }

                break
            }

            $index.Value++
        }
        return $File
    }

    [void]fixFileRange(){
        if (! $this.IsEncrypt){return}

        $local:parts = $this.Parts
        if ($parts.Count -lt 2){return}

        ($parts.Count - 1) .. 1 | %{
            $current = $parts[$_]
            $prev = $parts[$_ - 1]
            $n = $current.MountFileOffset % 16
    
            if ($current.fs -eq $null){
                if ($prev.fs -ne $null -and $n){
                    $current.MountFileOffset -= $n
                    $current.Len += $n
                    $prev.Len -= $n
                }
    
            }else{ # $current.fs -ne $null
                if ($prev.fs -ne $null){
                    if ($n){
                        $blockIV = New-Object byte[] 16
                        $blockEncrypted = New-Object byte[] 16
                        $blockOut = New-Object byte[] 16
    
                        # $pre.Len should greater than 31 .   no check here
                        $prev.fs.position = $prev.fsOffset + $prev.Len - ($n + 16)
                        [void]$prev.fs.read($blockIV, 0, 16)
                        [void]$prev.fs.read($blockEncrypted, 0, $n)
                        
                        $current.fs.position = $current.fsOffset
                        [void]$current.fs.read($blockEncrypted, $n, 16 - $n)
    
                        $current.Aes.IV = $blockIV
    
                        [void]$current.Aes.CreateDecryptor().TransformBlock($blockEncrypted, 0, 16, $blockOut, 0)
    
                        $current.iv0 = $blockEncrypted
                        $current.MountFileOffset += 16 - $n
                        $current.fsOffset += 16 - $n
                        $current.Len -= 16 - $n
    
                        $prev.Len -= $n

                        $partInsert = [PSCustomObject]@{
                            fs = [System.IO.MemoryStream]::new($blockOut)
                            fsOffset = 0
                            Len = 16
                            MountFileOffset = $current.MountFileOffset - 16
                            iv0 = $null
                        }
                        
                        $lastIndex = $parts.Count - 1
                        $prevIndex = $_ - 1
                        $parts = @($parts[0 .. $prevIndex]) + @($partInsert) + @($parts[$_ .. $lastIndex])
                        $this.Parts = $parts
    
                    }else{ # $n -eq 0
                        $blockIV = New-Object byte[] 16
                        $prev.fs.position = $prev.fsOffset + $prev.Len - 16
                        [void]$prev.fs.read($blockIV, 0, 16)
    
                        $current.iv0 = $blockIV
                    }
                }else{# $prev.fs -eq $null
                    $blockIV = New-Object byte[] 16
                    
                    if ($n){
                        $current.fs.position = $current.fsOffset + (16 - $n)
                        [void]$current.fs.read($blockIV, 0, 16)
    
                        $current.MountFileOffset += 32 - $n
                        $current.fsOffset += 32 - $n
                        $current.Len -= 32 - $n
    
                        $prev.Len += 32 - $n
                    }else{# $n -eq 0
                        $current.fs.position = $current.fsOffset
                        [void]$current.fs.read($blockIV, 0, 16)
    
                        $current.MountFileOffset += 16
                        $current.FSoffset += 16
                        $current.Len -= 16
    
                        $prev.Len += 16
                    }
    
                    $current.iv0 = $blockIV  
                }# end of $prev -eq $null
            }# end of $current -eq $null
        }# end of foreach
    }

    [bool]rebuildMp4Head(){
        if($this.Parts[0].fs -ne $null){return $true}

        write-host searching moov
        $time1 = get-date

        # mp4 only
        [byte[]]$pattern = (,0 * 11) + 1 + (,0 *15) + 1 + (,0 * 14) + 64 + (,0 * 29)

        
        [byte[]]$Bc = @(72) * 256
        $Bc[0] = 1; $Bc[1] = 11; $Bc[64] = 42
        
        [byte[]]$Gs = 1,10,9,8,7,6,5,4,3,2,1,12,72,72,72,72,72,72,
        72,72,72,72,72,72,72,72,16,72,72,72,61,72,72,72,72,72,72,
        72,72,72,72,72,72,72,72,61,72,72,72,72,72,72,72,72,72,72,
        72,72,72,72,72,61,72,72,72,72,72,72,72,72,72,72

        [uint32]$searchSize = 17MB
        if ($this.fileSize -lt $searchSize){$searchSize = $this.fileSize}

        $buffer = new-object byte[] ($searchSize)
        $searchStart = $this.fileSize - $searchSize
        $this.Read($buffer, $searchStart, $searchSize) > $null

        $bufferPos = $searchSize - $pattern.length
        while ($bufferPos -ge 0){
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

        $time2=get-date
        write-host ($time2-$time1)
        if ($bufferPos -lt 0){Write-Host 'moov not found'; return $false}
        Write-Host "moov found (at -$($searchSize - $bufferPos + 42))"

        $moovPos = $searchStart + $bufferPos - 42

        [byte[]]$ftypData = 0,0,0,0x20,0x66,0x74,0x79,0x70,0x69,0x73,0x6F,0x6D,0,0,
                            2,0,0x69,0x73,0x6F,0x6D,0x69,
                            0x73,0x6F,0x32,0x61,0x76,0x63,0x31,0x6D,0x70,0x34,0x31
        
        $mdatSize = $moovPos - 32
        if ($mdatSize -lt 4GB){
            $arr = [BitConverter]::GetBytes([uint32]$mdatSize)
            [array]::Reverse($arr)
            [byte[]]$mdatHead = $arr + 0x6D,0x64,0x61,0x74
        }else{
            $arr = [BitConverter]::GetBytes([uint64]$mdatSize)
            [array]::Reverse($arr)
            [byte[]]$mdatHead = 0,0,0,1 + 0x6D,0x64,0x61,0x74 + $arr
        }

        $this.Parts[0].fs = [System.IO.MemoryStream]::new($ftypData + $mdatHead)
        $this.Parts[0].Len = $ftypData.Count + $mdatHead.Count

        $partInsert = [PSCustomObject]@{
            fs = $null
            fsOffset = 0
            Len = 0
            MountFileOffset = $ftypData.Count + $mdatHead.Count
            iv0 = $null
        }
        
        $local:parts = $this.Parts
        $lastIndex = $parts.Count - 1
        $local:parts = @($parts[0]) + @($partInsert) + @($parts[1 .. $lastIndex])
        $parts[1].Len = $parts[2].MountFileOffset - $parts[1].MountFileOffset

        $this.Parts = $parts

        return $true
    }

    [uint64]Read([byte[]]$buffer, [uint64]$startPos, [uint64]$Len){
        if ($startPos -ge $this.fileSize){return 0}

        if ($startPos + $Len -gt $this.fileSize){
            $Len = $this.fileSize - $startPos
        }

        $local:parts = $this.Parts
        for ($i = 1; $i -lt $parts.count; $i++){
            if ($startPos -lt $parts[$i].MountFileOffset){break}
        }					
        $i--

        $bufferPos = 0
        $partPos = $startPos - $parts[$i].MountFileOffset
        $partLen = $parts[$i].Len - $partPos
        $Len1 = $Len

        while ($Len1 -gt 0){
    
            if ($Len1 -gt $partLen){
                $readSize = $partLen
            }else{
                $readSize = $Len1
            }

            if ($parts[$i].fs -ne $null){
                if($parts[$i].fs -is [System.IO.MemoryStream] -or $this.Aes -eq $null){ # ms or fs
                    
                    $parts[$i].fs.Position = $parts[$i].fsOffset + $partPos
                    [void]$parts[$i].fs.read($buffer, $bufferPos, $readSize)
                }else{ # cs
                    $n = $partPos % 16
        
                    if ($partPos -ge 16){
                        $parts[$i].fs.Position = $parts[$i].fsOffset + $partPos - $n - 16
                        $blockIV = New-Object byte[] 16
                        [void]$parts[$i].fs.read($blockIV, 0, 16)
    
                    }else{ # $startPos -lt 16
                        $parts[$i].fs.Position = $parts[$i].fsOffset
                        $blockIV = $parts[$i].iv0
                    }
    
                    $cs = new-object System.Security.Cryptography.CryptoStream (
                        $parts[$i].fs,
                        $this.Aes.CreateDecryptor($this.Aes.Key, $blockIV),
                        0
                        )
    
                    if ($n -gt 0){
                        $blockSkip = new-object byte[] $n
                        [void]$cs.read($blockSkip, 0, $n)
                    }
    
                    [void]$cs.read($buffer, $bufferPos, $readSize)
                    $cs = $null
                    $blockSkip = $null
                }
            }

            $Len1 -= $readSize
            $bufferPos += $readSize
            $i++
            $partPos = 0
            $partLen = $parts[$i].Len
        }

        return $Len
    }
}

class NameLink{
    [string]$endName = ''
    [File]$file = $null

    NameLink([string]$inEndName, [File]$inFile){
        $this.endName = $inEndName
        $this.file = $inFile
    }
}

class ListRef{
    [int]$position = 0
}

class OpenRef{
    [long]$openSequence = 0
    [File]$file = $null
    [System.Collections.Generic.SortedDictionary[long,Object]]$listRefs = $null

    OpenRef([File]$inFile){
        $this.file = $inFile;
        $this.listRefs = [System.Collections.Generic.SortedDictionary[long,Object]]::new()
    }
}


$RarVolumeType = @'
#Learn from   Pismo File Mount Development Kit   samples\tempfs_cs\tempfs.cs
class RarVolume: Pfm+FormatterDispatch{
    [Pfm+Marshaller]$marshaller = $null
    [long]$lastFileId = 0
    [long]$lastOpenSequence = 0

    [System.Collections.Generic.SortedDictionary[long,Object]]$openRefs = $null
    [System.Collections.Generic.SortedDictionary[long,Object]]$fileIds = $null
    [File]$root = $null



RarVolume([string]$rarFilePath){
    $this.lastFileId = 1
    $this.lastOpenSequence = 0
    $this.openRefs = [System.Collections.Generic.SortedDictionary[long,Object]]::new()
    $this.fileIds = [System.Collections.Generic.SortedDictionary[long,Object]]::new()

    $this.root = [File]::new([Pfm]::fileTypeFolder, 0, 0)
    $this.root.nameCount = 1
    $this.root.fileId = 1
    $this.fileIds[$this.root.fileId] = $this.root

    $rar = [RAR]::new($rarFilePath)
    $files = [File]::makeFile($rar.entries, $rar.FsTable)
    $this.makeTree($files)
}

[void]makeTree([File[]]$files){

    foreach ($file in $files){

        $arrName = @($file.FullName -split '[/\\]')
        $parent = $null
        $f = $null
        $endName = $null

        $perr = $this.FileFindName($arrName, [ref]$parent, [ref]$f, [ref]$endName)

        if ($perr -eq 0 -or $perr -eq [Pfm]::ErrorInvalid){continue}

        if ($file.fileType -eq [Pfm]::fileTypeFolder){ # $file is folder
            $this.makeFolder($file.FullName) > $null
            continue
        }

        # $file is file
        $folderPath = Split-Path $file.FullName
        $parent = $this.makeFolder($folderPath)

        if ($parent-eq $null){continue}

        $endName = Split-Path $file.FullName -Leaf
        $this.FileNameAdd($parent, 0, $endName, $file)
    }
    
    pushd (Split-Path $script:rarFilePath)
    foreach ($Key in $this.fileIds.Keys){
        $data = ConvertTo-Json $this.fileIds[$Key] -Depth 3
        $data >> MountData.txt
        
    }
    
    #sc -Path MountData.txt -Value $data  -enc UTF8
    popd
}

[File]makeFolder([string]$FolderPath){
    if ($FolderPath -eq ''){return $this.Root}

    [string[]]$arrName = @($FolderPath -split '[/\\]')
    $parent = $null
    $file = $null
    $endName = $null

    $perr = $this.FileFindName($arrName, [ref]$parent, [ref]$file, [ref]$endName)

    if ($perr -eq 0){
        return $file
    }elseif ($perr -eq [Pfm]::ErrorInvalid){
        return $null
    }

    if ($perr -eq [Pfm]::errorParentNotFound){
        $parentFolderPath = Split-Path $folderPath
        $parent = $this.makeFolder($parentFolderPath)
        if ($parent -eq $null){return $null}
    }

    $file = [File]::new([Pfm]::fileTypeFolder, 0, 0)
    $file.FullName = $FolderPath
    $endName = Split-Path $folderPath -Leaf
    $this.FileNameAdd($parent, 0, $endName, $file)

    return $file
}

[void] FileOpened([File]$file, [Pfm+OpenAttribs]$openAttribs){
    $openRef = $this.openRefs[$file.openId]

    if ($null -eq $openRef){
        $openRef = [OpenRef]::new($file)
        $this.openRefs[$file.openId] = $openRef
    }

    $openRef.openSequence = ++ $this.lastOpenSequence
    $openAttribs.openId = $file.openId
    $openAttribs.openSequence = $openRef.openSequence
    $openAttribs.accessLevel = [Pfm]::accessLevelWriteData
    $openAttribs.attribs.fileType = $file.fileType
    $openAttribs.attribs.fileFlags = $file.fileFlags
    $openAttribs.attribs.fileId = $file.fileId
    $openAttribs.attribs.createTime = $file.createTime
    $openAttribs.attribs.accessTime = $file.accessTime
    $openAttribs.attribs.writeTime = $file.writeTime
    $openAttribs.attribs.changeTime = $file.changeTime
    $openAttribs.attribs.fileSize = $file.fileSize
}

[int] FileFindOpenId([long]$openId, [ref]$file){
    $perr = [Pfm]::errorInvalid
    $file.Value = $null
    $openRef = $this.openRefs[$openId]
    if ($null -ne $openRef){
        $file.Value = $openRef.file
        $perr = 0
    }
    return $perr
}

[int] FileFindFileId([long]$fileId, [ref]$file){
    $perr = [Pfm]::errorNotFound
    $file.Value = $this.fileIds[$fileId]
    if ($null -ne $file.Value){ $perr = 0 }

    return $perr
}

[int] FileFindName ([string[]]$nameParts, [ref]$parent, [ref]$file, [ref]$endName){
    $perr = 0
    $parent.Value = $null
    $file.Value = $this.root
    $endName.Value = ""
    $i = 0

    while ($perr -eq 0 -and $i -lt $nameParts.Count){
        $parent.Value = $file.Value
        $file.Value = $null

        if ($parent.Value.fileType -ne [Pfm]::fileTypeFolder){
            $perr = [Pfm]::errorParentNotFound
            break
        }

        $endName.Value = $nameParts[$i++]
        $foldedName = $endName.Value.ToLower()
        $nameLink = $parent.Value.children[$foldedName]

        if ($null -eq $nameLink){
            $perr = [Pfm]::errorNotFound
            if ($i -ne $nameParts.Count){
                $parent.Value = $null
                $endName.Value = $null
                $perr = [Pfm]::errorParentNotFound
            }
            break

        }else{
            $file.Value = $nameLink.file
            $endName.Value = $nameLink.endName
        }
        
    }
    return $perr
}


[void] FileNameAdd($parent, $writeTime, $endName, $file){
    if ($file.fileId -eq 0){ $file.fileId = ++$this.lastFileId }
    $nameLink = [NameLink]::new($endName, $file)
    $foldedName = $endName.ToLower()
    $parent.children[$foldedName] = $nameLink
    $parent.writeTime = $writeTime
    $parent.changeTime = $writeTime
    $file.nameCount ++
    $this.fileIds[$file.fileId] = $file
}

[int] FileNameRemove($parent, $writeTime, $endName, $file){
    $perr = [Pfm]::errorNotFound
    $foldedName = $endName.ToLower()
    $nameLink = $parent.children[$foldedName]
    if ($null -ne $nameLink -and $nameLink.file -eq $file){
        $perr = 0
        $parent.children.Remove($foldedName)
        $parent.writeTime = $writeTime
        $parent.changeTime = $writeTime
        $file.nameCount--
        if ($file.nameCount -eq 0){
            $this.fileIds.Remove($file.fileId)
        }
    }
    return $perr
}

[void] Open([Pfm+MarshallerOpenOp]$op){
    $nameParts = $op.NameParts()
    $createFileType = $op.CreateFileType()
    $createFileFlags = $op.CreateFileFlags()
    $writeTime = $op.WriteTime()
    $newCreateOpenId = $op.NewCreateOpenId()
    $newExistingOpenId = $op.NewExistingOpenId()
    
    $perr = 0
    $existed = $false
    $openAttribs = [Pfm+OpenAttribs]::new()
    $parentFileId = 0
    $endName = $null

    $parent = $null
    $file = $null

    $perr = $this.FileFindName($nameParts, [ref]$parent, [ref]$file, [ref]$endName)

    if ($perr -eq 0){
        $existed = $true
        if ($parent -ne $null){ $parentFileId = $parent.fileId }
        if ($file.openId -eq 0){ $file.openId = $newExistingOpenId }
        $this.FileOpened($file, $openAttribs)
    
    }
    
    $op.Complete($perr, $existed, $openAttribs, $parentFileId, $endName, 0, $null, 0, $null)

}

[void] Replace([Pfm+MarshallerReplaceOp]$op){
    $targetOpenId = $op.TargetOpenId()
    $targetParentFileId = $op.TargetParentFileId()
    $targetEndName = $op.TargetEndName()
    $createFileFlags = $op.CreateFileFlags()
    $writeTime = $op.WriteTime()
    $newCreateOpenId = $op.NewCreateOpenId()
    $perr = 0
    $openAttribs = [Pfm+OpenAttribs]::new()
    $targetFile = $null
    $parent = $null
    $file = $null

    $perr = $this.FileFindOpenId($targetOpenId, [ref]$targetFile)
    if ($perr -eq 0){
        $perr = $this.FileFindFileId($targetParentFileId, [ref]$parent)
        if ($perr -eq 0){
            $file = $this.MakeFile($targetFile.fileType, $createFileFlags, $writeTime)
            $perr = $this.FileNameRemove($parent, $writeTime, $targetEndName, $targetFile)
            if ($perr -eq 0){
                $this.FileNameAdd($parent, $writeTime, $targetEndName, $file)
                $file.openId = $newCreateOpenId
                $this.FileOpened($file, $openAttribs)
            }
        }
    }
    $op.Complete($perr, $openAttribs, $null)

}

[void] Move([Pfm+MarshallerMoveOp] $op){
    $sourceOpenId = $op.SourceOpenId()
    $sourceParentFileId = $op.SourceParentFileId()
    $sourceEndName = $op.SourceEndName()
    $targetNameParts = $op.TargetNameParts()
    $deleteSource = $op.DeleteSource()
    $writeTime = $op.WriteTime()
    $newExistingOpenId = $op.NewExistingOpenId()
    $perr = 0
    $existed = $false
    $openAttribs = [Pfm+OpenAttribs]::new()
    $parentFileId = 0
    $endName = $null
    $sourceFile = $null
    $targetParent = $null
    $targetFile = $null
    $sourceParent = $null

    $perr = $this.FileFindOpenId($sourceOpenId, [ref]$sourceFile)
    if ($perr -eq 0){
        $perr = $this.FileFindName($targetNameParts, [ref]$targetParent, [ref]$targetFile, [ref]$endName)
        if ($perr -eq 0){
            $existed = $true
            if ($targetParent -ne $null){ $parentFileId = $targetParent.fileId}
            if ($targetFile.openId -eq 0){ $targetFile.openId = $newExistingOpenId }
            $this.FileOpened($targetFile, $openAttribs)
        }elseif( $perr -eq [Pfm]::errorNotFound){
            $this.FileNameAdd($targetParent, $writeTime, $endName, $sourceFile)
            $perr = 0
            $parentFileId = $targetParent.fileId
            $this.FileOpened($sourceFile, $openAttribs)
            if ($deleteSource -and $this.FileFindFileId($sourceParentFileId, [ref]$sourceParent) -eq 0){
                $this.FileNameRemove($sourceParent, $writeTime, $sourceEndName, $sourceFile)
            }
        }
    }
    $op.Complete($perr, $existed, $openAttribs, $parentFileId, $endName, 0, $null, 0, $null)
}

[void] MoveReplace([Pfm+MarshallerMoveReplaceOp] $op){
    $sourceOpenId = $op.SourceOpenId()
    $sourceParentFileId = $op.SourceParentFileId()
    $sourceEndName = $op.SourceEndName()
    $targetOpenId = $op.TargetOpenId()
    $targetParentFileId = $op.TargetParentFileId()
    $targetEndName = $op.TargetEndName()
    $deleteSource = $op.DeleteSource()
    $writeTime = $op.WriteTime()
    $perr = 0
    $sourceFile = $null
    $sourceParent = $null
    $targetFile = $null
    $targetParent = $null

    $perr = $this.FileFindOpenId($sourceOpenId, [ref]$sourceFile)
    if ($perr -eq 0){ $perr = $this.FileFindFileId($sourceParentFileId, [ref]$sourceParent) }
    if ($perr -eq 0){ $perr = $this.FileFindOpenId($targetOpenId, [ref]$targetFile) }
    if ($perr -eq 0){ $perr = $this.FileFindFileId($targetParentFileId, [ref]$targetParent) }
    if ($perr -eq 0){ $perr = $this.FileNameRemove($targetParent, $writeTime, $targetEndName, $targetFile)}
    if ($perr -eq 0){ $this.FileNameAdd($targetParent, $writeTime, $targetEndName, $sourceFile)}
    if ($perr -eq 0 -and $deleteSource){ $this.FileNameRemove($sourceParent, $writeTime, $sourceEndName, $sourceFile)}

    $op.Complete( $perr)
}

[void] Delete([Pfm+MarshallerDeleteOp] $op){
    $openId = $op.OpenId()
    $parentFileId = $op.ParentFileId()
    $endName = $op.EndName()
    $writeTime = $op.WriteTime()
    $perr = 0
    $file = $null
    $parent = $null

    $perr = $this.FileFindOpenId($openId, [ref]$file)
    if ($perr -eq 0){
        $perr = $this.FileFindFileId($parentFileId, [ref]$parent)
        if ($perr -eq 0){ $this.FileNameRemove($parent, $writeTime, $endName, $file) }
    }
    $op.Complete( $perr)
}

[void] Close([Pfm+MarshallerCloseOp] $op){
    $openId = $op.OpenId()
    $openSequence = $op.OpenSequence()
    $perr = 0
    $openRef = $null

    $openRef = $this.openRefs[$openId]
    if ($null -eq $openRef){
        $perr = [Pfm]::errorInvalid
    }else{
        if ($openRef.openSequence -le $openSequence){
            $this.openRefs.Remove($openId)
        }
    }
   
    $op.Complete( $perr)

}

[void] FlushFile([Pfm+MarshallerFlushFileOp] $op){
    $openId = $op.OpenId()
    $flushFlags = $op.FlushFlags()
    $fileFlags = $op.FileFlags()
    $createTime = $op.CreateTime()
    $accessTime = $op.AccessTime()
    $writeTime = $op.WriteTime()
    $changeTime = $op.ChangeTime()
    $perr = 0
    $openAttribs = [Pfm+OpenAttribs]::new()
    $file = $null

    $perr = $this.FileFindOpenId($openId, [ref]$file)
    if ($perr -eq 0){
        if ($fileFlags -ne [Pfm]::fileFlagsInvalid){
            $file.fileFlags = $fileFlags
        }
        if ($createTime -ne [Pfm]::timeInvalid){
            $file.createTime = $createTime
        }
        if ($accessTime -ne [Pfm]::timeInvalid){
            $file.accessTime = $accessTime
        }
        if ($writeTime -ne [Pfm]::timeInvalid){
            $file.writeTime = $writeTime
        }
        if ($changeTime -ne [Pfm]::timeInvalid){
            $file.changeTime = $changeTime
        }
        if (($flushFlags -band [Pfm]::flushFlagOpen) -ne 0){
            $this.FileOpened($file, $openAttribs)
        }
    }
    $op.Complete($perr, $openAttribs, $null)
}

[void] List([Pfm+MarshallerListOp] $op){
    $openId = $op.OpenId()
    $listId = $op.ListId()
    $perr = 0
    $noMore = $true
    $children = $null
    $Attribs = [Pfm+Attribs]::new()
    $openRef = $null
    $listRef = $null
    $nameLink = $null
    $file = $null

    $openRef = $this.openRefs[$openId]
    if ($null -eq $openRef){
        $perr = [Pfm]::errorInvalid
    }else{
        $listRef = $openRef.listRefs[$listId]
        if ($null -eq $listRef){
            $listRef = [ListRef]::new()
            $openRef.listRefs[$listId] =  $listRef
        }
        $children = $openRef.file.children

        while ($true){
            if($listRef.position -ge $children.Count){
                $noMore = $true
            }else{
                $nameLink = $children.GetByIndex($listRef.position)
                $file = $nameLink.file
                $attribs.fileId = $file.fileId
                $attribs.fileType = $file.fileType
                $attribs.createTime = $file.createTime
                $attribs.accessTime = $file.accessTime
                $attribs.writeTime = $file.writeTime
                $attribs.changeTime = $file.changeTime
                $attribs.fileSize = $file.fileSize

                if ($op.Add($attribs, $nameLink.endName)){
                    $listRef.position ++
                    continue
                }
            }
            break
        }
    }
    $op.Complete($perr, $noMore)
}

[void] ListEnd([Pfm+MarshallerListEndOp] $op){
    $openId = $op.OpenId()
    $listId = $op.ListId()
    $perr = 0
    $openRef = $null

    $openRef = $this.openRefs[$openId]
    if ($null -eq $openRef){
        $perr = [Pfm]::errorInvalid
    }else{
        $openRef.listRefs.Remove($listId)
    }
    $op.Complete( $perr)
}

[void] Read( [Pfm+MarshallerReadOp] $op){
    $openId = $op.OpenId()
    $fileOffset = $op.FileOffset()
    $data = $op.Data()
    $requestedSize = $op.RequestedSize()
    $perr = 0
    $actualSize = 0
    $file = $null

    $perr = $this.FileFindOpenId($openId, [ref]$file)
    if ($perr -eq 0){
        $actualSize = $file.Read($data, $fileOffset, $requestedSize)
    }
    $op.Complete($perr, $actualSize)
}


[void] Write([Pfm+MarshallerWriteOp] $op){
    $op.Complete([Pfm]::errorAccessDenied, 0)
}

[void] SetSize([Pfm+MarshallerSetSizeOp] $op){
    $op.Complete([Pfm]::errorAccessDenied)
}

[void] Capacity([Pfm+MarshallerCapacityOp] $op){
    $op.Complete([Pfm]::errorSuccess, 10TB, 9TB)
}

[void] FlushMedia([Pfm+MarshallerFlushMediaOp] $op){
    $op.Complete([Pfm]::errorSuccess, -1)
}

[void] Control([Pfm+MarshallerControlOp] $op){
    $op.Complete([Pfm]::errorInvalid, 0)
}

[void] MediaInfo([Pfm+MarshallerMediaInfoOp] $op){
    $mediaInfo = [Pfm+MediaInfo]::new()
    $op.Complete([Pfm]::errorSuccess, $mediaInfo, "RarMp4")
}

[void] Access([Pfm+MarshallerAccessOp] $op){
    $openId = $op.OpenId()
    $perr = 0
    $openAttribs = [Pfm+OpenAttribs]::new()
    $file = $null

    $perr = $this.FileFindOpenId($openId, [ref]$file)
    if ($perr -eq 0){ $this.FileOpened($file, $openAttribs) }
    $op.Complete($perr, $openAttribs, $null)
}

[void] ReadXattr([Pfm+MarshallerReadXattrOp] $op){
    $op.Complete([Pfm]::errorNotFound, 0, 0)
}

[void] WriteXattr([Pfm+MarshallerWriteXattrOp] $op){
    $op.Complete([Pfm]::errorAccessDenied, 0)
}


}
'@

cd -literal $PSScriptRoot

if ($rarFilePath -like '*.rar'){
    if (Test-Path -literal $rarFilePath -PathType Leaf){
        $file = gi -literal $rarFilePath
        $rarFilePath = $file.FullName
        cd -literal $file.DirectoryName
    
    }else{
        $rarFilePath = ''
    }

}else{
    $rarFilePath = ''
}

if ($rarFilePath -eq ''){
    $files = @(dir *.rar -file)
    if ($files.Count -gt 0){
        $rarFilePath = $files[0].FullName
    }else{
        Write-Host 'rar not found'; pause; exit
    }
}

checkPfm
Invoke-Expression $RarVolumeType
startMount $rarFilePath $autoOpen $driveLetter $MoutName