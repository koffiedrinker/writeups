# For 200

> We got memory image from victim pc. Please analyze malicious indicator. 7z password : novirus

```bash
openssl enc -d -aes-256-cbc -k BnKUyuHfJf31804OmzkO -in files10.enc -out files10.zip
```

The contents of the zip file is a 7z compressed file:

```
koffiedrinker$ unzip -v ../../../trendmicro2017/for200/files10.zip 
Archive:  ../../../trendmicro2017/for200/files10.zip
 Length   Method    Size  Ratio   Date   Time   CRC-32    Name
--------  ------  ------- -----   ----   ----   ------    ----
57290506  Stored 57290506   0%  06-05-17 17:39  78534fd4  VictimMemory.7z
--------          -------  ---                            -------
57290506         57290506   0%                            1 file
```

Uncompressing with `unzip files10.zip` and `7za e VictimMemory.7z`, we are left with `VictimMemory.img`.

Since we're dealing with a memory dump, let's use Volatility to analyze it.

```
[koffiedrinker@ctf for200]$ ./vol.py -f VictimMemory.img imageinfo                        
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x86_23418, Win7SP0x86, Win7SP1x86
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace (/data/for200/VictimMemory.img)
                      PAE type : PAE
                           DTB : 0x185000L
                          KDBG : 0x8333ec28L
          Number of Processors : 1
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0x8333fc00L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2017-04-11 02:35:28 UTC+0000
     Image local date and time : 2017-04-11 11:35:28 +0900
```

Let's use the suggested `Win7SP1x86_23418` profile to list the processes. I prefer using `pstree` because it already shows visually parent-child relationships.

```
[koffiedrinker@ctf for200]$ ./vol.py -f VictimMemory.img --profile=Win7SP1x86_23418 pstree
Volatility Foundation Volatility Framework 2.6
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x89d8a530:wininit.exe                               412    344      3     78 2017-04-11 02:27:45 UTC+0000
. 0x88a0c030:lsass.exe                                516    412      7    547 2017-04-11 02:27:48 UTC+0000
. 0x88a056d8:services.exe                             508    412      7    220 2017-04-11 02:27:47 UTC+0000
.. 0x869fa6c0:VSSVC.exe                              2304    508     12    194 2017-04-11 02:33:08 UTC+0000
.. 0x89d91030:svchost.exe                            1288    508     17    304 2017-04-11 02:28:00 UTC+0000
.. 0x86d7b030:VGAuthService.                         1424    508      3     87 2017-04-11 02:28:03 UTC+0000
.. 0x89d6b030:mscorsvw.exe                           3096    508      6     74 2017-04-11 02:30:34 UTC+0000
.. 0x88bd3a98:msdtc.exe                              1420    508     14    150 2017-04-11 02:28:28 UTC+0000
.. 0x88a4bcd8:vmacthlp.exe                            676    508      3     53 2017-04-11 02:27:52 UTC+0000
.. 0x88a808a0:svchost.exe                             808    508     20    465 2017-04-11 02:27:53 UTC+0000
... 0x88aa7130:audiodg.exe                            952    808      4    122 2017-04-11 02:27:55 UTC+0000
.. 0x869b6030:msiexec.exe                            3612    508      9    278 2017-04-11 02:34:25 UTC+0000
.. 0x89c0fb78:svchost.exe                            1668    508      8     92 2017-04-11 02:28:12 UTC+0000
.. 0x86986030:sppsvc.exe                             3264    508      4    146 2017-04-11 02:30:44 UTC+0000
.. 0x89a3b8e0:SearchIndexer.                         2376    508     12    576 2017-04-11 02:29:03 UTC+0000
.. 0x88a87518:svchost.exe                             844    508     18    419 2017-04-11 02:27:53 UTC+0000
... 0x88b91030:dwm.exe                                568    844      3     70 2017-04-11 02:28:22 UTC+0000
.. 0x86dcf2d0:vmtoolsd.exe                           1484    508      8    289 2017-04-11 02:28:07 UTC+0000
... 0x89a73d40:cmd.exe                               3880   1484      0 ------ 2017-04-11 02:35:27 UTC+0000
.... 0x869b8d40:ipconfig.exe                         3900   3880      0 ------ 2017-04-11 02:35:28 UTC+0000
.. 0x89d0b030:spoolsv.exe                            1232    508     12    326 2017-04-11 02:27:59 UTC+0000
.. 0x86400838:taskhost.exe                           1976    508      9    165 2017-04-11 02:28:18 UTC+0000
.. 0x8697fa58:svchost.exe                            3300    508      9    299 2017-04-11 02:30:45 UTC+0000
.. 0x89a131f8:WmiApSrv.exe                           3728    508      5    111 2017-04-11 02:31:41 UTC+0000
.. 0x88add030:svchost.exe                            1116    508     16    391 2017-04-11 02:27:57 UTC+0000
.. 0x88a5e528:svchost.exe                             720    508      7    284 2017-04-11 02:27:53 UTC+0000
.. 0x88a8baf8:svchost.exe                             868    508     42   1017 2017-04-11 02:27:53 UTC+0000
.. 0x88a47130:svchost.exe                             616    508     10    359 2017-04-11 02:27:51 UTC+0000
... 0x89b5b5b0:WmiPrvSE.exe                          2108    616     10    294 2017-04-11 02:28:37 UTC+0000
... 0x88be3300:WmiPrvSE.exe                           204    616     10    204 2017-04-11 02:28:31 UTC+0000
.. 0x88ab6c88:svchost.exe                            1008    508     13    282 2017-04-11 02:27:56 UTC+0000
.. 0x8697bd40:svchost.exe                            3324    508      5     66 2017-04-11 02:33:09 UTC+0000
.. 0x8694bd40:svchost.exe                            3192    508      9    126 2017-04-11 02:30:40 UTC+0000
. 0x88a0ba38:lsm.exe                                  524    412     10    143 2017-04-11 02:27:48 UTC+0000
 0x86d1d7e8:csrss.exe                                 352    344      9    470 2017-04-11 02:27:43 UTC+0000
. 0x86784030:conhost.exe                             3888    352      0 ------ 2017-04-11 02:35:28 UTC+0000
 0x8594b7e0:System                                      4      0     91    490 2017-04-11 02:27:39 UTC+0000
. 0x86dd0d40:smss.exe                                 268      4      2     29 2017-04-11 02:27:39 UTC+0000
 0x89d83478:csrss.exe                                 404    396     10    199 2017-04-11 02:27:45 UTC+0000
. 0x86938030:conhost.exe                             1868    404      3    100 2017-04-11 02:32:03 UTC+0000
 0x89da3530:winlogon.exe                              444    396      3    114 2017-04-11 02:27:45 UTC+0000
 0x88bbaab8:explorer.exe                              940    356     31    865 2017-04-11 02:28:23 UTC+0000
. 0x8691c030:cmd.exe                                 4080    940      1     20 2017-04-11 02:32:02 UTC+0000
.. 0x88abfa78:svchost.exe                            3828   4080      1      7 2017-04-11 02:35:18 UTC+0000
. 0x88bca030:vmtoolsd.exe                            2216    940      6    191 2017-04-11 02:28:51 UTC+0000
```

Near the bottom we note an interesting chain: `Explorer.exe -> cmd.exe -> svchost.exe`. That doesn't look right.

Let's dump how `svchost.exe` was executed:

```
[koffiedrinker@ctf for200]$ ./vol.py -f VictimMemory.img --profile=Win7SP1x86_23418 cmdline --pid=940,4080,3828
Volatility Foundation Volatility Framework 2.6
************************************************************************
explorer.exe pid:    940
Command line : C:\Windows\Explorer.EXE
************************************************************************
cmd.exe pid:   4080
Command line : "C:\Windows\system32\cmd.exe" 
************************************************************************
svchost.exe pid:   3828
Command line : svchost.exe  1.tmp 0x0 1
```

So `svchost.exe` takes as arguments: `1.tmp 0x0 1`, that's kinda unusual...

Note that `cmdscan` would have also told us this (since it was started by `cmd.exe`):

```
[koffiedrinker@ctf for200]$ ./vol.py -f VictimMemory.img --profile=Win7SP1x86_23418 cmdscan           
Volatility Foundation Volatility Framework 2.6
**************************************************
CommandProcess: conhost.exe Pid: 1868
CommandHistory: 0x31e818 Application: svchost.exe Flags: Allocated
CommandCount: 0 LastAdded: -1 LastDisplayed: -1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x190
Cmd #11 @ 0x10000: ?????
Cmd #37 @ 0x10000: ?????
**************************************************
CommandProcess: conhost.exe Pid: 1868
CommandHistory: 0x33a338 Application: cmd.exe Flags: Allocated, Reset
CommandCount: 2 LastAdded: 1 LastDisplayed: 1
FirstCommand: 0 CommandCountMax: 50
ProcessHandle: 0x58
Cmd #0 @ 0x33a700: cd %temp%
Cmd #1 @ 0x2d3b38: svchost.exe 1.tmp 0x0 1
```

Let's dump the `svchost.exe` and dump `1.tmp` since this is probably some kind of input file.

```
[koffiedrinker@ctf for200]$ ./vol.py -f VictimMemory.img --profile=Win7SP1x86_23418 procdump --pid=3828 --dump-dir=dump_files/
Volatility Foundation Volatility Framework 2.6
Process(V) ImageBase  Name                 Result
---------- ---------- -------------------- ------
0x88abfa78 0x00ed0000 svchost.exe          OK: executable.3828.exe
[koffiedrinker@ctf for200]$ ./vol.py -f VictimMemory.img --profile=Win7SP1x86_23418 dumpfiles --regex=1.tmp --pid=3828 --dump-dir=dump_files/
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x88bb47c0   3828   \Device\HarddiskVolume1\Users\Taro\AppData\Local\Temp\1.tmp
SharedCacheMap 0x88bb47c0   3828   \Device\HarddiskVolume1\Users\Taro\AppData\Local\Temp\1.tmp
```

Taking a look at `1.tmp` leaves us without a clue of what the contents mean:
```
[koffiedrinker@ctf dump_files]$ xxd -c32 file.3828.0x86c8dec0.dat | head -n20
0000000: 9090 9090 9090 9090 9090 9090 9090 9090 5589 e583 ec60 c645 daa8 c645 dbff c645  ................U....`.E...E...E
0000020: dc88 c645 ddd0 c645 deb2 c645 dff6 c645 e0f8 c645 e1ea c645 e2ff c645 e3ff c645  ...E...E...E...E...E...E...E...E
0000040: e4d2 c645 e5ff c645 e6ff c645 e7c2 c645 e8dc c645 e9c2 c645 ead8 c645 ebff c645  ...E...E...E...E...E...E...E...E
0000060: ecf6 c645 edff c645 eefa c645 efff c645 bc55 c645 bd8b c645 beec c645 bf51 c645  ...E...E...E...E.U.E...E...E.Q.E
0000080: c0e8 c645 c100 c645 c200 c645 c300 c645 c400 c645 c558 c645 c62d c645 c752 c645  ...E...E...E...E...E.X.E.-.E.R.E
00000a0: c81f c645 c934 c645 ca01 c645 cb2d c645 cc52 c645 cd1f c645 ce34 c645 cf01 c645  ...E.4.E...E.-.E.R.E...E.4.E...E
00000c0: d0e8 c645 d100 c645 d200 c645 d300 c645 d400 c645 d590 c645 d690 c645 d7c9 c645  ...E...E...E...E...E...E...E...E
00000e0: d8c3 c645 d9cc c645 a600 c645 a75b c645 a800 c645 a900 c645 aa00 c645 ab00 c645  ...E...E...E.[.E...E...E...E...E
0000100: ac00 c645 ad00 c645 ae2b c645 af17 c645 b000 c645 b119 c645 b23f c645 b300 c645  ...E...E.+.E...E...E...E.?.E...E
0000120: b400 c645 b500 c645 b600 c645 b703 c645 b800 c645 b913 c645 ba00 c645 bb05 c745  ...E...E...E...E...E...E...E...E
0000140: fc16 0000 00c7 45f4 0000 0000 c745 f000 0000 008b 45f0 83f8 1673 708d 55da 8b45  ......E......E......E....sp.U..E
0000160: f001 d00f b600 0fb6 c089 45f8 8d55 a68b 45f0 01d0 0fb6 000f b6c0 8945 f483 7df4  ..........E..U..E..........E..}.
0000180: 007e 0a83 45f8 0183 6df4 01eb f08b 45fc 83e8 010f b644 05bc 0fb6 c029 45f8 8b45  .~..E...m.....E......D.....)E..E
00001a0: fc83 e801 0fb6 4405 bc0f b6c0 3145 f8d1 7df8 8b45 f889 c18d 55da 8b45 f001 d088  ......D.....1E..}..E....U..E....
00001c0: 0883 6dfc 0183 45f0 01eb 8890 c9c3 0000 0000 0000 0000 0000 0000 0000 0000 0000  ..m...E.........................
00001e0: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
0000200: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
0000220: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
0000240: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
0000260: 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000  ................................
```

The remainder of the file is full of zero bytes, the "file" is basically just a memory page with the file contents in the beginning.

It's highly likely that we'll know what to do with the file once we know what `svchost.exe` does with it. Time to fire up radare2.

```
[koffiedrinker@ctf dump_files]$ r2 -A executable.3828.exe 
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
 -- Your project name should contain an uppercase letter, 8 vowels, some numbers, and the first 5 numbers of your private bitcoin key.
[0x00ed1406]> afl
0x00ed1000    9 398          sub.MSVCR120.dll_printf_0
0x00ed118e    3 15   -> 266  fcn.00ed118e
0x00ed1406   25 10   -> 340  entry0
0x00ed1410    3 61           sub.KERNEL32.dll_IsDebuggerPresent_410
0x00ed144d    3 251          loc.00ed144d
0x00ed1598    1 6            sub.MSVCR120.dll__XcptFilter_598
0x00ed159e    1 6            sub.MSVCR120.dll__amsg_exit_59e
0x00ed15b0    7 67           fcn.00ed15b0
0x00ed1600    3 137          fcn.00ed1600
0x00ed16c0    5 49           fcn.00ed16c0
0x00ed16f1    9 156          sub.KERNEL32.dll_GetSystemTimeAsFileTime_6f1
0x00ed178d    1 3            fcn.00ed178d
0x00ed17cc    4 157          sub.KERNEL32.dll_DecodePointer_7cc
0x00ed186c    1 9            fcn.00ed186c
0x00ed1875    1 21           fcn.00ed1875
0x00ed188a    6 32           fcn.00ed188a
0x00ed18ca    3 39           fcn.00ed18ca
0x00ed18f2    1 6            sub.MSVCR120.dll__initterm_e_8f2
0x00ed18f8    1 6            sub.MSVCR120.dll__initterm_8f8
0x00ed1900    1 69           fcn.00ed1900
0x00ed1945    1 20           fcn.00ed1945
0x00ed197c    1 6            sub.MSVCR120.dll__crt_debugger_hook_97c
0x00ed1982    1 6            sub.MSVCR120.dll___crtUnhandledException_982
0x00ed1988    1 6            sub.MSVCR120.dll___crtTerminateProcess_988
0x00ed198e    1 6            sub.MSVCR120.dll__terminate__YAXXZ_98e
0x00ed1994    1 6            sub.MSVCR120.dll___crtSetUnhandledExceptionFilter_994
0x00ed199a    1 6            sub.MSVCR120.dll__lock_99a
0x00ed19a0    1 6            sub.MSVCR120.dll__unlock_9a0
0x00ed19a6    1 6            sub.MSVCR120.dll___dllonexit_9a6
0x00ed19ac    1 6            sub.MSVCR120.dll__invoke_watson_9ac
0x00ed19b2    1 6            sub.MSVCR120.dll__controlfp_s_9b2
0x00ed19b8    1 6            sub.MSVCR120.dll__except_handler4_common_9b8
0x00ed19be    1 6            sub.KERNEL32.dll_IsProcessorFeaturePresent_9be
0x00ed19d0    4 43           fcn.00ed19d0
```

The first function is actually `main()`, or at least contains the overall logic of the program. 

Printing the strings in rodata, we find the usage string so we now know what the arguments to `svchost.exe` (more or less) mean:
```
[0x00ed1000]> iz
vaddr=0x00ed2120 paddr=0x00000f20 ordinal=001 sz=53 len=52 section=.rdata type=ascii string=usage: this.exe <input file> <offset> <isLongSleep>\n
vaddr=0x00ed2158 paddr=0x00000f58 ordinal=002 sz=19 len=18 section=.rdata type=ascii string=offset eg) 0xFFFF\n
vaddr=0x00ed216c paddr=0x00000f6c ordinal=003 sz=17 len=16 section=.rdata type=ascii string=file name is %s\n
vaddr=0x00ed2184 paddr=0x00000f84 ordinal=004 sz=14 len=13 section=.rdata type=ascii string=offset is %x\n
...
```

Looking at the calls in main:
```
[0x00ed1000]> pdf~call
|           0x00ed1008      e8c3090000     call fcn.00ed19d0
|       |   0x00ed102e      ffd6           call esi
|       |   0x00ed1035      ffd6           call esi
|       |   0x00ed103c      ff159820ed00   call dword [sym.imp.MSVCR120.dll_exit] ; 0xed2098
|           0x00ed1051      ffd7           call edi
|           0x00ed1062      ff15b020ed00   call dword [sym.imp.MSVCR120.dll_sscanf] ; 0xed20b0
|           0x00ed1073      ffd7           call edi
|           0x00ed107b      ff15a420ed00   call dword [sym.imp.MSVCR120.dll_fopen] ; 0xed20a4
|           0x00ed1096      ff15a020ed00   call dword [sym.imp.MSVCR120.dll_fread] ; 0xed20a0
|           0x00ed10af      ff150820ed00   call dword [sym.imp.KERNEL32.dll_VirtualAlloc] ; 0xed2008
|       |   0x00ed10c0      ffd7           call edi
|       |   0x00ed10d0      e8b9000000     call fcn.00ed118e
|           0x00ed10e7      ff15ac20ed00   call dword [sym.imp.MSVCR120.dll_memmove] ; 0xed20ac
|           0x00ed1102      ff15b020ed00   call dword [sym.imp.MSVCR120.dll_sscanf] ; 0xed20b0
|       |   0x00ed1119      ff150420ed00   call dword [sym.imp.KERNEL32.dll_Sleep] ; 0xed2004 ; "F\xba\fv\xb6/\rv]7\rv\xde/\rv\x80\xbb\fv\xc4\xca\fv\x9f\xbb\fv\xb5v\rv\xa8>\fv\x95\xa2[w\x10\xcd[w"
|           0x00ed112f      ff150c20ed00   call dword [sym.imp.KERNEL32.dll_CreateThread] ; 0xed200c ; "]7\rv\xde/\rv\x80\xbb\fv\xc4\xca\fv\x9f\xbb\fv\xb5v\rv\xa8>\fv\x95\xa2[w\x10\xcd[w"
|       |   0x00ed1140      ffd7           call edi
|       |   0x00ed1150      e839000000     call fcn.00ed118e
|           0x00ed115e      ffd7           call edi
|           0x00ed1166      ff150020ed00   call dword [sym.imp.KERNEL32.dll_WaitForSingleObject] ; 0xed2000
|           0x00ed1172      ff159c20ed00   call dword [sym.imp.MSVCR120.dll_fclose] ; 0xed209c
|           0x00ed1185      e804000000     call fcn.00ed118e
```

To make a long story short, this function opens the "1.tmp" file, reads it, moves it to it's own memory page and then executes the contents of it by calling `CreateThread()` with the memory page as starting address. So let's open "1.tmp" in radare2 and disassemble it. :) (Suddenly the 0x90's begin to make sense in "1.tmp")

```
[koffiedrinker@ctf dump_files]$ r2 file.3828.0x86c8dec0.dat 
 -- You crackme up!
[0x00000000]> pd 139
            0x00000000      90             nop
            0x00000001      90             nop
            0x00000002      90             nop
            0x00000003      90             nop
            0x00000004      90             nop
            0x00000005      90             nop
            0x00000006      90             nop
            0x00000007      90             nop
            0x00000008      90             nop
            0x00000009      90             nop
            0x0000000a      90             nop
            0x0000000b      90             nop
            0x0000000c      90             nop
            0x0000000d      90             nop
            0x0000000e      90             nop
            0x0000000f      90             nop
            0x00000010      55             push rbp
            0x00000011      89e5           mov ebp, esp
            0x00000013      83ec60         sub esp, 0x60               ; '`'
            0x00000016      c645daa8       mov byte [rbp - 0x26], 0xa8
            0x0000001a      c645dbff       mov byte [rbp - 0x25], 0xff
            0x0000001e      c645dc88       mov byte [rbp - 0x24], 0x88
            0x00000022      c645ddd0       mov byte [rbp - 0x23], 0xd0
            0x00000026      c645deb2       mov byte [rbp - 0x22], 0xb2
            0x0000002a      c645dff6       mov byte [rbp - 0x21], 0xf6
            0x0000002e      c645e0f8       mov byte [rbp - 0x20], 0xf8
            0x00000032      c645e1ea       mov byte [rbp - 0x1f], 0xea
            0x00000036      c645e2ff       mov byte [rbp - 0x1e], 0xff
            0x0000003a      c645e3ff       mov byte [rbp - 0x1d], 0xff
            0x0000003e      c645e4d2       mov byte [rbp - 0x1c], 0xd2
            0x00000042      c645e5ff       mov byte [rbp - 0x1b], 0xff
            0x00000046      c645e6ff       mov byte [rbp - 0x1a], 0xff
            0x0000004a      c645e7c2       mov byte [rbp - 0x19], 0xc2
            0x0000004e      c645e8dc       mov byte [rbp - 0x18], 0xdc
            0x00000052      c645e9c2       mov byte [rbp - 0x17], 0xc2
            0x00000056      c645ead8       mov byte [rbp - 0x16], 0xd8
            0x0000005a      c645ebff       mov byte [rbp - 0x15], 0xff
            0x0000005e      c645ecf6       mov byte [rbp - 0x14], 0xf6
            0x00000062      c645edff       mov byte [rbp - 0x13], 0xff
            0x00000066      c645eefa       mov byte [rbp - 0x12], 0xfa
            0x0000006a      c645efff       mov byte [rbp - 0x11], 0xff
            0x0000006e      c645bc55       mov byte [rbp - 0x44], 0x55 ; 'U'
            0x00000072      c645bd8b       mov byte [rbp - 0x43], 0x8b
            0x00000076      c645beec       mov byte [rbp - 0x42], 0xec
            0x0000007a      c645bf51       mov byte [rbp - 0x41], 0x51 ; 'Q'
            0x0000007e      c645c0e8       mov byte [rbp - 0x40], 0xe8
            0x00000082      c645c100       mov byte [rbp - 0x3f], 0
            0x00000086      c645c200       mov byte [rbp - 0x3e], 0
            0x0000008a      c645c300       mov byte [rbp - 0x3d], 0
            0x0000008e      c645c400       mov byte [rbp - 0x3c], 0
            0x00000092      c645c558       mov byte [rbp - 0x3b], 0x58 ; 'X'
            0x00000096      c645c62d       mov byte [rbp - 0x3a], 0x2d ; '-'
            0x0000009a      c645c752       mov byte [rbp - 0x39], 0x52 ; 'R'
            0x0000009e      c645c81f       mov byte [rbp - 0x38], 0x1f
            0x000000a2      c645c934       mov byte [rbp - 0x37], 0x34 ; '4'
            0x000000a6      c645ca01       mov byte [rbp - 0x36], 1
            0x000000aa      c645cb2d       mov byte [rbp - 0x35], 0x2d ; '-'
            0x000000ae      c645cc52       mov byte [rbp - 0x34], 0x52 ; 'R'
            0x000000b2      c645cd1f       mov byte [rbp - 0x33], 0x1f
            0x000000b6      c645ce34       mov byte [rbp - 0x32], 0x34 ; '4'
            0x000000ba      c645cf01       mov byte [rbp - 0x31], 1
            0x000000be      c645d0e8       mov byte [rbp - 0x30], 0xe8
            0x000000c2      c645d100       mov byte [rbp - 0x2f], 0
            0x000000c6      c645d200       mov byte [rbp - 0x2e], 0
            0x000000ca      c645d300       mov byte [rbp - 0x2d], 0
            0x000000ce      c645d400       mov byte [rbp - 0x2c], 0
            0x000000d2      c645d590       mov byte [rbp - 0x2b], 0x90
            0x000000d6      c645d690       mov byte [rbp - 0x2a], 0x90
            0x000000da      c645d7c9       mov byte [rbp - 0x29], 0xc9
            0x000000de      c645d8c3       mov byte [rbp - 0x28], 0xc3
            0x000000e2      c645d9cc       mov byte [rbp - 0x27], 0xcc
            0x000000e6      c645a600       mov byte [rbp - 0x5a], 0
            0x000000ea      c645a75b       mov byte [rbp - 0x59], 0x5b ; '['
            0x000000ee      c645a800       mov byte [rbp - 0x58], 0
            0x000000f2      c645a900       mov byte [rbp - 0x57], 0
            0x000000f6      c645aa00       mov byte [rbp - 0x56], 0
            0x000000fa      c645ab00       mov byte [rbp - 0x55], 0
            0x000000fe      c645ac00       mov byte [rbp - 0x54], 0
            0x00000102      c645ad00       mov byte [rbp - 0x53], 0
            0x00000106      c645ae2b       mov byte [rbp - 0x52], 0x2b ; '+'
            0x0000010a      c645af17       mov byte [rbp - 0x51], 0x17
            0x0000010e      c645b000       mov byte [rbp - 0x50], 0
            0x00000112      c645b119       mov byte [rbp - 0x4f], 0x19
            0x00000116      c645b23f       mov byte [rbp - 0x4e], 0x3f ; '?'
            0x0000011a      c645b300       mov byte [rbp - 0x4d], 0
            0x0000011e      c645b400       mov byte [rbp - 0x4c], 0
            0x00000122      c645b500       mov byte [rbp - 0x4b], 0
            0x00000126      c645b600       mov byte [rbp - 0x4a], 0
            0x0000012a      c645b703       mov byte [rbp - 0x49], 3
            0x0000012e      c645b800       mov byte [rbp - 0x48], 0
            0x00000132      c645b913       mov byte [rbp - 0x47], 0x13
            0x00000136      c645ba00       mov byte [rbp - 0x46], 0
            0x0000013a      c645bb05       mov byte [rbp - 0x45], 5
            0x0000013e      c745fc160000.  mov dword [rbp - 4], 0x16
            0x00000145      c745f4000000.  mov dword [rbp - 0xc], 0
            0x0000014c      c745f0000000.  mov dword [rbp - 0x10], 0
        .-> 0x00000153      8b45f0         mov eax, dword [rbp - 0x10]
        |   0x00000156      83f816         cmp eax, 0x16
       ,==< 0x00000159      7370           jae 0x1cb
       ||   0x0000015b      8d55da         lea edx, [rbp - 0x26]
       ||   0x0000015e      8b45f0         mov eax, dword [rbp - 0x10]
       ||   0x00000161      01d0           add eax, edx
       ||   0x00000163      0fb600         movzx eax, byte [rax]
       ||   0x00000166      0fb6c0         movzx eax, al
       ||   0x00000169      8945f8         mov dword [rbp - 8], eax
       ||   0x0000016c      8d55a6         lea edx, [rbp - 0x5a]
       ||   0x0000016f      8b45f0         mov eax, dword [rbp - 0x10]
       ||   0x00000172      01d0           add eax, edx
       ||   0x00000174      0fb600         movzx eax, byte [rax]
       ||   0x00000177      0fb6c0         movzx eax, al
       ||   0x0000017a      8945f4         mov dword [rbp - 0xc], eax
      .---> 0x0000017d      837df400       cmp dword [rbp - 0xc], 0
     ,====< 0x00000181      7e0a           jle 0x18d
     ||||   0x00000183      8345f801       add dword [rbp - 8], 1
     ||||   0x00000187      836df401       sub dword [rbp - 0xc], 1
     |`===< 0x0000018b      ebf0           jmp 0x17d
     `----> 0x0000018d      8b45fc         mov eax, dword [rbp - 4]
       ||   0x00000190      83e801         sub eax, 1
       ||   0x00000193      0fb64405bc     movzx eax, byte [rbp + rax - 0x44]
       ||   0x00000198      0fb6c0         movzx eax, al
       ||   0x0000019b      2945f8         sub dword [rbp - 8], eax
       ||   0x0000019e      8b45fc         mov eax, dword [rbp - 4]
       ||   0x000001a1      83e801         sub eax, 1
       ||   0x000001a4      0fb64405bc     movzx eax, byte [rbp + rax - 0x44]
       ||   0x000001a9      0fb6c0         movzx eax, al
       ||   0x000001ac      3145f8         xor dword [rbp - 8], eax
       ||   0x000001af      d17df8         sar dword [rbp - 8], 1
       ||   0x000001b2      8b45f8         mov eax, dword [rbp - 8]
       ||   0x000001b5      89c1           mov ecx, eax
       ||   0x000001b7      8d55da         lea edx, [rbp - 0x26]
       ||   0x000001ba      8b45f0         mov eax, dword [rbp - 0x10]
       ||   0x000001bd      01d0           add eax, edx
       ||   0x000001bf      8808           mov byte [rax], cl
       ||   0x000001c1      836dfc01       sub dword [rbp - 4], 1
       ||   0x000001c5      8345f001       add dword [rbp - 0x10], 1
       |`=< 0x000001c9      eb88           jmp 0x153
       `--> 0x000001cb      90             nop
            0x000001cc      c9             leave
            0x000001cd      c3             ret
```

Looks like executable code alright. Since this code is simply executing CPU instructions without any library calls or anything (just a small stack to keep state), we can easily emulate this with [Unicorn](https://github.com/unicorn-engine/unicorn). So after compiling and installing (with Python bindings) Unicorn, I wrote this small script which is entirely based upon the `shellcode.py` example script. I just did some small modifications to print the stack at the end since it contains (hopefully) the juicy bits.

```python
#!/usr/bin/env python
# Sample code for X86 of Unicorn. Nguyen Anh Quynh <aquynh@gmail.com>

from __future__ import print_function
from unicorn import *
from unicorn.x86_const import *

from binascii import *

SIKRIT_CODE = unhexlify("909090909090909090909090909090905589e583ec60c645daa8c645dbffc645dc88c645ddd0c645deb2c645dff6c645e0f8c645e1eac645e2ffc645e3ffc645e4d2c645e5ffc645e6ffc645e7c2c645e8dcc645e9c2c645ead8c645ebffc645ecf6c645edffc645eefac645efffc645bc55c645bd8bc645beecc645bf51c645c0e8c645c100c645c200c645c300c645c400c645c558c645c62dc645c752c645c81fc645c934c645ca01c645cb2dc645cc52c645cd1fc645ce34c645cf01c645d0e8c645d100c645d200c645d300c645d400c645d590c645d690c645d7c9c645d8c3c645d9ccc645a600c645a75bc645a800c645a900c645aa00c645ab00c645ac00c645ad00c645ae2bc645af17c645b000c645b119c645b23fc645b300c645b400c645b500c645b600c645b703c645b800c645b913c645ba00c645bb05c745fc16000000c745f400000000c745f0000000008b45f083f81673708d55da8b45f001d00fb6000fb6c08945f88d55a68b45f001d00fb6000fb6c08945f4837df4007e0a8345f801836df401ebf08b45fc83e8010fb64405bc0fb6c02945f88b45fc83e8010fb64405bc0fb6c03145f8d17df88b45f889c18d55da8b45f001d08808836dfc018345f001eb8890") # removed c9 (leave) and c3 (ret) at the end

# memory address where emulation starts
ADDRESS = 0x1000000

# Test X86 32 bit
def test_i386(mode, code):
    print("Emulate x86 code")
    try:
        # Initialize emulator
        mu = Uc(UC_ARCH_X86, mode)

        # map 2MB memory for this emulation
        mu.mem_map(ADDRESS, 2 * 1024 * 1024)

        # write machine code to be emulated to memory
        mu.mem_write(ADDRESS, code)

        # initialize stack
        mu.reg_write(UC_X86_REG_ESP, ADDRESS + 0x200000)

        # emulate machine code in infinite time
        mu.emu_start(ADDRESS, ADDRESS + len(code))

        # now print out some registers
        esp = mu.reg_read(UC_X86_REG_ESP)
        rbp = mu.reg_read(UC_X86_REG_RBP)
        print("ESP: 0x%x, RBP: 0x%x" % (esp, rbp))
        bytes_to_read = 0x60 # The size of our stack...
        try:
            buf = mu.mem_read(esp, bytes_to_read)
            print(">>> buffer = 0x%x, size = %u, content = " \
                        %(esp, bytes_to_read), end="")
            for i in buf:
                print("%c" %i, end="")
            print("")
        except UcError as e:
            print(">>> buffer = 0x%x, size = %u, content = <unknown>\n" \
                        %(esp, bytes_to_read))
        print(">>> Emulation done")

    except UcError as e:
        print("ERROR: %s" % e)



if __name__ == '__main__':
    test_i386(UC_MODE_64, SIKRIT_CODE)
```

We thus just emulate all instructions and then print the memory area that contains the stack. This gives us...

```bash
[koffiedrinker@ctf for200]$ python2 unicorn_emulation_small.py 
Emulate x86 code
ESP: 0x11fff98, RBP: 0x11ffff8
>>> buffer = 0x11fff98, size = 96, content = [+?U??Q?X-R4-R4??????TMCTF{static_analyzer}}
>>> Emulation done
```

... the flag.

Flag: TMCTF{static_analyzer}
