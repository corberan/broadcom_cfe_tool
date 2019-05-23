# broadcom_cfe_tool
A tool for compressing/decompressing data from/to Broadcom CFE file


usage:
```powershell
cp .\mtd0.bin .\mtd0_new.bin
.\broadcom_cfe_tool.exe -d -i .\mtd0.bin -o phicomm_k2p_b1_cfe_nvram.txt
.\broadcom_cfe_tool.exe -z -i .\phicomm_k2p_b1_cfe_nvram.txt -o .\mtd0_new.bin
```

--help:
```
-z, --compress            compress NVRAM data to CFE file
-d, --decompress          decompress embedded NVRAM data from CFE file
-b, --offset=<n>          offset within output to embed NVRAM (default 0x400)
-c, --count=<n>           bytes of embed NVRAM to write (default 0x1000)
--nvram_space=<n>         size of the NVRAM partition space (default 0x10000)
-i, --input=<file>        input file
-o, --output=<file>       output file
```