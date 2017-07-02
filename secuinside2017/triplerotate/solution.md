# TripleRotate

> Decrypt it!

`encrypt` file contains:
```
[koffiedrinker@ctf TripleRotate]$ cat encrypt 
0 0 1 0 0 0 1 0 1 1 0 1 0 1 1 0 1 1 1 0 0 0 1 0 1 0 1 1 1 0 1 0 0 0 0 1 0 0 0 1 1 0 1 1 0 1 1 0 0 0 0 0 1 1 0 1 1 1 0 0 1 0 1 0 1 0 1 1 0 0 1 0 1 0 1 0 1 0 0 0 0 1 1 1 0 1 0 0 1 1 0 0 0 0 0 1 1 1 0 1 1 0 0 0 1 1 1 1 1 1 1 1 0 1 1 1 0 1 0 1 1 0 1 0 1 0 0 1 0 0 0 1 0 0 0 1 1 0 0 1 0 1 0 0 1 0 0 1 1 0 0 0 1 1 0 1 1 1 0 0 1 0 0 1 0 1 1 0 0 1 1 0 1 1 1 1 0 1 1 1 0 1 0 1 1 0 0 1 0 0 1 0 0 0 1 0 1 0 0 0 1 
```

`prob` file:
```
[koffiedrinker@ctf TripleRotate]$ file prob 
prob: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=26a87d66cee9849e606408ca0d67f2023af31da4, stripped, with debug_info
```

Playing around:
```
[koffiedrinker@ctf TripleRotate]$ ./prob 
Input : encrypt
check your input
[koffiedrinker@ctf TripleRotate]$ ./prob 
Input : 0 0 1 0 0 0 1 0 1 1 0 1 0 1 1 0 1 1 1 0 0 0 1 0 1 0 1 1 1 0 1 0 0 0 0 1 0 0 0 1 1 0 1 1 0 1 1 0 0 0 0 0 1 1 0 1 1 1 0 0 1 0 1 0 1 0 1 1 0 0 1 0 1 0 1 0 1 0 0 0 0 1 1 1 0 1 0 0 1 1 0 0 0 0 0 1 1 1 0 1 1 0 0 0 1 1 1 1 1 1 1 1 0 1 1 1 0 1 0 1 1 0 1 0 1 0 0 1 0 0 0 1 0 0 0 1 1 0 0 1 0 1 0 0 1 0 0 1 1 0 0 0 1 1 0 1 1 1 0 0 1 0 0 1 0 1 1 0 0 1 1 0 1 1 1 1 0 1 1 1 0 1 0 1 1 0 0 1 0 0 1 0 0 0 1 0 1 0 0 0 1 
check your input
[koffiedrinker@ctf TripleRotate]$ cat encrypt | perl -ne 's/ //g;print' | ./prob 
Input : check your input
*** stack smashing detected ***: ./prob terminated
Segmentation fault (core dumped)
```

Some more info about `prob`:
```
[koffiedrinker@ctf TripleRotate]$ r2 -A prob 
[x] Analyze all flags starting with sym. and entry0 (aa)
[x] Analyze len bytes of instructions for references (aar)
[x] Analyze function calls (aac)
[ ] [*] Use -AA or aaaa to perform additional experimental analysis.
[x] Constructing a function name for fcn.* and sym.func.* functions (aan))
 -- Use 'e asm.offset=true' to show offsets in 16bit segment addressing mode.
[0x00400640]> afl
0x00400578    3 36           sub.__gmon_start___224_578
0x004005b0    2 16   -> 32   sym.imp.puts
0x004005c0    2 16   -> 48   sym.imp.__stack_chk_fail
0x004005d0    2 16   -> 48   sym.imp.printf
0x004005e0    2 16   -> 48   sym.imp.fputc
0x004005f0    2 16   -> 48   sym.imp.__libc_start_main
0x00400600    2 16   -> 48   loc.imp.__gmon_start__
0x00400610    2 16   -> 48   sym.imp.malloc
0x00400620    2 16   -> 48   sym.imp.fopen
0x00400630    2 16   -> 48   sym.imp.__isoc99_scanf
0x00400640    1 41           entry0
0x00400670    6 100          fcn.00400670
0x004006e0    4 34           fcn.004006e0
0x00400704   13 370          main
0x00400876   10 290          sub.malloc_876
0x00400998   12 311          fcn.00400998
0x00400c70    4 54           fcn.00400c70
[0x00400640]> iz
vaddr=0x00400cbc paddr=0x00000cbc ordinal=000 sz=9 len=8 section=.rodata type=ascii string=Input : 
vaddr=0x00400cc8 paddr=0x00000cc8 ordinal=001 sz=17 len=16 section=.rodata type=ascii string=check your input
vaddr=0x00400cd9 paddr=0x00000cd9 ordinal=002 sz=10 len=9 section=.rodata type=ascii string=Length : 
vaddr=0x00400ce6 paddr=0x00000ce6 ordinal=003 sz=18 len=17 section=.rodata type=ascii string=check your length
vaddr=0x00400cfb paddr=0x00000cfb ordinal=004 sz=8 len=7 section=.rodata type=ascii string=encrypt
```

It turns out that writing a write-up for a Reverse Engineering challenge is really boring. So I will just explain how the program worked and show my solution script. The decompiled code can be found at the end of this write-up if you're interested in that.

The main function takes a input string of length 9 and then asks for a length. The length is used as the output length of the `encrypt` file. Our received `encrypt` file has 201 non-whitespace chars. `malloc_876` creates three buffers of this length which will be used to for manipulations and later on they are merged in the final encrypted buffer that is written to `encrypt`. `fcn.00400998` takes our input string of 9 characters and creates a bit string from it with each bit as a 8-bit number. So for example the letter "a" would become `00 01 01 00 00 00 00 01`. This leads to a buffer of size 0x48 (9 times 8) since we have an input string of size 9. This string is then chopped up in three pieces: the first 0x17 bytes go to array 1, the next 0x18 go to array 2 and the last 0x19 go to array 3 but all in reverse.

Each of these arrays is then passed to a function where the original content (0x17 bytes for array 1 for example) is extended to the full length of the buffer (your input length). For example, array 2 is passed to `fcn.00400b22`. After extending the arrays, they are merged in one final buffer that is written to the `encrypt` file.

Since all operations on the input are reversible, we can use a SAT solver to find us an input that matches the `encrypt` file. The code below does just that and prints out a bit string which I then quickly manipulated with Perl to give the final flag.

```python
from z3 import *

length = 201
s = Solver()

arr_encrypted = "0 0 1 0 0 0 1 0 1 1 0 1 0 1 1 0 1 1 1 0 0 0 1 0 1 0 1 1 1 0 1 0 0 0 0 1 0 0 0 1 1 0 1 1 0 1 1 0 0 0 0 0 1 1 0 1 1 1 0 0 1 0 1 0 1 0 1 1 0 0 1 0 1 0 1 0 1 0 0 0 0 1 1 1 0 1 0 0 1 1 0 0 0 0 0 1 1 1 0 1 1 0 0 0 1 1 1 1 1 1 1 1 0 1 1 1 0 1 0 1 1 0 1 0 1 0 0 1 0 0 0 1 0 0 0 1 1 0 0 1 0 1 0 0 1 0 0 1 1 0 0 0 1 1 0 1 1 1 0 0 1 0 0 1 0 1 1 0 0 1 1 0 1 1 1 1 0 1 1 1 0 1 0 1 1 0 0 1 0 0 1 0 0 0 1 0 1 0 0 0 1".split(" ")
arr0 = [] # Output array
arr1 = [] # The three arrays used in the program...
arr2 = []
arr3 = []
for i in range(202):
	print(i)
	arr0.append(BitVec("arr0_%i" % i, 8))
	arr1.append(BitVec("arr1_%i" % i, 8))
	arr2.append(BitVec("arr2_%i" % i, 8))
	arr3.append(BitVec("arr3_%i" % i, 8))

i = 0
for str_bit in arr_encrypted:
	arr0[i] = ord(str_bit) - 0x30 # Make it either 0x00 or 0x01...
	i += 1

print("Adding conditions...")

# Conditions from fcn.00400acf
i = 0
while(length - 0x17 > i):
	s.add(arr1[i + 0x17] == arr1[i] ^ arr1[i + 5])
	i += 1

# Conditions from fcn.00400b22
i = 0
while(length - 0x18 > i):
	s.add(arr2[i + 0x18] == arr2[i] ^ (arr2[i + 1] ^ (arr2[i + 3] ^ arr2[i + 4])))
	i += 1

# Conditions from fcn.00400b9b
i = 0
while(length - 0x19 > i):
	s.add(arr3[i + 0x19] == arr3[i] ^ arr3[i + 3])
	i += 1

for i in range(202):
	# The merge that happens in malloc_876, maps the 3 arrays to the output (encrypt file)
	s.add(arr0[i] == ((arr1[i] & arr2[i]) ^ (arr2[i] & arr3[i])) ^ arr3[i])
	# Each number is either 0 or 1
	s.add(arr0[i] < 2)
	s.add(arr0[i] >= 0)
	s.add(arr1[i] < 2)
	s.add(arr1[i] >= 0)
	s.add(arr2[i] < 2)
	s.add(arr2[i] >= 0)
	s.add(arr3[i] < 2)
	s.add(arr3[i] >= 0)

print("Checking if solvable...")
print(s.check())
print("Printing model...")
print(s.model())

m = s.model()
print("Bitstring...")
# Print first 0x17 bits of input string
for i in range(0x17):
	print(m[arr1[0x16 - i]])

# Print second 0x18 bits of input string
for i in range(0x18):
	print(m[arr2[0x17 - i]])

# Print final 0x19 bits of input string
for i in range(0x19):
	print(m[arr3[0x18 - i]])
```

Since I'm most comt comfortable with Perl, I quickly switch to it to do the final conversion to a string:
```perl
print 'SECU[';
print pack("B*", <DATA>);
print "]\n";

__DATA__
010010010101111101001100001100000111011000110011010111110111101001000101
```

```bash
koffiedrinker$ perl sol.pl 
SECU[I_L0v3_zE]
```

Flag: SECU[I_L0v3_zE]

## Decompiled code

All done by hand because I cannot afford IDA Pro.

```
func main() {

	printf("Input :");
	scanf("%s", local_20h); // Store string at local_20h

	// Calculate length in assembly, see http://www.int80h.org/strlen/
	rax = assembly_calculations(local_20h);

	if(rax != 9) { // if length != 9
		puts("check your input\n");
		// Do stack smash detection
		return;
	}

	printf("Length :");
	scanf("%d", local_2ch); // Store number at local_2ch
	if(local_2ch <= 0xc8) { // Has to be more than 200! "encrypt" file is just 201 bytes!
		puts("check your length\n");
		// Do stack smash detection
		return;
	}

	local_40h = malloc(local_2ch);
	
	// So our input, length and malloced buffer
	malloc_876(&local_20h, local_2ch, &local_40h);

	local_38h = fopen("encrypt", "wb");
	local_28h = 0;
	while(local_28h < local_2ch) {
		meh = local_40h[local_28h]; // Get a char from stringbuf
		if(meh == '\x00') {
			eax = 0x30; // "0"
		} else {
			eax = 0x31; // "1"
		}

		fputc(eax, local_38h);
		fputc("\x20", local_38h);

		local_28h++;
	}

}

func malloc_876(inputbuf, length, allocbuf) {
	// Function pointers...
	ptr_1 = 0x400acf;
	ptr_2 = 0x400b22;
	ptr_3 = 0x400b9b;
	ptrs[] = {ptr_1, ptr_2, ptr_3}; // local_60h


	// Create three buffers of size length and store in local_40h array
	local_1ch = 0;
	QWORD local_40h[3] = (); // Array of 3 qwords
	while(local_1ch <= 2) {
		local_40h[local_1ch] = malloc(length);
		local_1ch++;
	}

	fcn.00400998(&local_40h, &inputbuf);

	local_18h = 0;
	while(local_18h <= 2) {
		ptrs[local_18h](local_40h[local_18h], length); // Jump to address
		local_18h++;
	}

	i = 0;
	while(i < length) {
		// Does stuff on local_40h qwords and allocbuf
		// Probably mapping it...
		ecx = local_40h[0][i];
		edx = local_40h[1][i];
		edi = ecx & edx;

		ecx = local_40h[1][i];
		edx = local_40h[2][i];
		edx = edx & ecx;
	
		ecx = edi ^ edx;

		edx = local_40h[2][i];
		allocbuf[i] = ecx ^ edx;

		// Or shorter: ((0 & 1) ^ (1 & 2)) ^ 2 
		// allocbuf[i] = ((bufs[0][i] & bufs[1][i]) ^ (bufs[1][i] & bufs[2][i])) ^ local_40h[2][i];
		
		i++;
	}
}

func fcn.00400998(bufs, inputbuf) {
	local_50h = some buf of size 0x48, i think.
	dword[] local_80h = {0x00, 0x17, 0x18, 0x19};

	// This loop manipulates the inputbuf and stores the manipulated
	// result in local_50h.
	i = 0;

	// Convert our input into bit representation:
	// "a" = 00 01 01 00 00 00 00 01 => 01100001 => bin('a')
	while(i <= 0x47) { // 71
		// Manipulating the index because our input is only 9 bytes
		// But we need to make the input 0x48 bytes...
		eax = i;
		edx = 7 + i;
		eax = edx if eax < 0;
		eax = eax >> 3;

		// They get a byte from the inputbuf
		inputbuf[eax];
		// They do some trickery on the byte...

		local_50h[i] = the byte after manipulations.
	}

	// This loop does trickery on the 3 bufs...
	j = 0; k = 0;
	while(j <= 2) {
		k = local_80h[j] + k;
		local_54h = local_80h[j + 1];

		while(local_54 not signed) { // local_54 >= 0?
			bufs[j][local_54h]  = local_50h;
			local_50h++; // Move ptr to next char in buffer
			local_54h--;
		}


		j++;
	}
}

func fcn.00400acf(buf, length) {
	i = 0;
	while(length - 0x17 > i) {
		ecx = buf[i + 5];
		edx = buf[i];
		buf[i + 0x17] = edx ^ ecx;

		i++;
	}
}

func fcn.00400b22(buf, length) {
	i = 0;
	while(length - 0x18 > i) {
		ecx = buf[i + 4];
		edx = buf[i + 3];
		ecx = ecx ^ edx;
		
		edx = buf[i + 1];
		ecx = ecx ^ edx;

		edx = buf[i];
		ecx = ecx ^ edx;

		buf[i + 0x18] = ecx;

		i++;
	}
}

func fcn.00400b9b(buf, length) {
	i = 0;
	while(length - 0x19 > i) {
		ecx = buf[i + 3];
		edx = buf[i];
		buf[i + 0x19] = edx ^ ecx;

		i++;
	}
}
```

### Dynamic analysis

Some output from r2 debugger:
```
[0x7f1102610d70]> db 0x004008e2
[0x7f1102610d70]> dc
Selecting and continuing: 460
Input : abcdefghi
Length : 201
hit breakpoint at: 4008e2
[0x004008e2]> px @ rsp
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7fffe4657700  0000 0000 0000 0000 30f8 9900 0000 0000  ........0.......
0x7fffe4657710  5b00 0000 c900 0000 c077 65e4 ff7f 0000  [........we.....
0x7fffe4657720  cf0a 4000 0000 0000 220b 4000 0000 0000  ..@.....".@.....
0x7fffe4657730  9b0b 4000 0000 0000 e0aa 6002 117f 0000  ..@.......`.....
0x7fffe4657740  10f9 9900 0000 0000 f0f9 9900 0000 0000  ................
0x7fffe4657750  d0fa 9900 0000 0000 0000 0000 0000 0000  ................
0x7fffe4657760  0000 0000 0300 0000 44cd 2e02 117f 0000  ........D.......
0x7fffe4657770  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x7fffe4657780  e077 65e4 ff7f 0000 ee07 4000 0000 0000  .we.......@.....
0x7fffe4657790  0000 0000 0000 0000 ffff ffff ffff ffff  ................
0x7fffe46577a0  30f8 9900 0000 0000 230c 4000 0000 0000  0.......#.@.....
0x7fffe46577b0  0000 0000 c900 0000 0000 0000 0000 0000  ................
0x7fffe46577c0  6162 6364 6566 6768 6900 4000 0000 0000  abcdefghi.@.....
0x7fffe46577d0  c078 65e4 ff7f 0000 000e 796f 51ea 2c4b  .xe.......yoQ.,K
0x7fffe46577e0  f00b 4000 0000 0000 9122 2902 117f 0000  ..@......").....
0x7fffe46577f0  0000 0000 0000 0000 c878 65e4 ff7f 0000  .........xe.....
[0x004008e2]> dm
sys   4K 0x0000000000400000 * 0x0000000000401000 s -r-x /data/TripleRotate/prob /data/TripleRotate/prob ; map._data_TripleRotate_prob._r_x
sys   4K 0x0000000000601000 - 0x0000000000602000 s -r-- /data/TripleRotate/prob /data/TripleRotate/prob ; map._data_TripleRotate_prob._rw_
sys   4K 0x0000000000602000 - 0x0000000000603000 s -rw- /data/TripleRotate/prob /data/TripleRotate/prob ; reloc.puts_0
sys 132K 0x000000000099f000 - 0x00000000009c0000 s -rw- [heap] [heap]
...
[0x004008e2]> px @ 0x099f910
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f910  0100 0000 0101 0000 0100 0000 0101 0001  ................
0x0099f920  0000 0000 0101 0000 0000 0000 0000 0000  ................
0x0099f930  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f940  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f950  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f960  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f970  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f980  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f990  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f9a0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f9b0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f9c0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f9d0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f9e0  0000 0000 0000 0000 e100 0000 0000 0000  ................
0x0099f9f0  0101 0000 0101 0001 0001 0000 0101 0000  ................
0x0099fa00  0001 0000 0101 0001 0000 0000 0000 0000  ................
[0x004008e2]> px @ 0x099f9f0
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f9f0  0101 0000 0101 0001 0001 0000 0101 0000  ................
0x0099fa00  0001 0000 0101 0001 0000 0000 0000 0000  ................
0x0099fa10  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa20  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa30  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa40  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa50  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa60  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa70  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa80  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fa90  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099faa0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fab0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fac0  0000 0000 0000 0000 e100 0000 0000 0000  ................
0x0099fad0  0100 0001 0001 0100 0000 0001 0001 0100  ................
0x0099fae0  0101 0100 0001 0100 0000 0000 0000 0000  ................
[0x004008e2]> px @ 0x099fad0
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099fad0  0100 0001 0001 0100 0000 0001 0001 0100  ................
0x0099fae0  0101 0100 0001 0100 0000 0000 0000 0000  ................
0x0099faf0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb00  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb10  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb20  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb30  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb40  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb50  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb60  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb70  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb80  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fb90  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fba0  0000 0000 0000 0000 6104 0200 0000 0000  ........a.......
0x0099fbb0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fbc0  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

So this is what we get after fcn.00400998...

And after the calling of the three functions:
```
[0x004008e2]> db 0x00400913
[0x004008e2]> dc
Selecting and continuing: 460
hit breakpoint at: 400913
[0x004008e2]> px @ 0x099f910
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f910  0100 0000 0101 0000 0100 0000 0101 0001  ................
0x0099f920  0000 0000 0101 0000 0000 0101 0100 0100  ................
0x0099f930  0001 0001 0100 0001 0000 0001 0001 0100  ................
0x0099f940  0101 0100 0000 0100 0101 0101 0001 0101  ................
0x0099f950  0100 0001 0001 0001 0001 0101 0100 0000  ................
0x0099f960  0000 0000 0100 0100 0001 0101 0001 0000  ................
0x0099f970  0101 0101 0000 0100 0100 0000 0100 0001  ................
0x0099f980  0101 0001 0001 0001 0001 0000 0001 0101  ................
0x0099f990  0001 0100 0001 0100 0101 0101 0100 0101  ................
0x0099f9a0  0001 0001 0001 0101 0001 0101 0000 0101  ................
0x0099f9b0  0000 0100 0000 0101 0001 0101 0000 0100  ................
0x0099f9c0  0000 0100 0101 0100 0100 0001 0100 0100  ................
0x0099f9d0  0001 0100 0101 0101 0100 0000 0000 0000  ................
0x0099f9e0  0000 0000 0000 0000 e100 0000 0000 0000  ................
0x0099f9f0  0101 0000 0101 0001 0001 0000 0101 0000  ................
0x0099fa00  0001 0000 0101 0001 0101 0100 0100 0001  ................
[0x004008e2]> px @ 0x099f9f0
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f9f0  0101 0000 0101 0001 0001 0000 0101 0000  ................
0x0099fa00  0001 0000 0101 0001 0101 0100 0100 0001  ................
0x0099fa10  0001 0101 0000 0100 0001 0100 0001 0101  ................
0x0099fa20  0101 0100 0001 0101 0000 0100 0000 0101  ................
0x0099fa30  0101 0100 0100 0001 0001 0100 0000 0100  ................
0x0099fa40  0001 0000 0001 0001 0101 0100 0001 0100  ................
0x0099fa50  0100 0001 0000 0000 0100 0101 0101 0101  ................
0x0099fa60  0001 0101 0001 0100 0000 0101 0101 0101  ................
0x0099fa70  0101 0000 0101 0001 0001 0000 0100 0000  ................
0x0099fa80  0001 0000 0000 0100 0101 0100 0100 0001  ................
0x0099fa90  0000 0001 0101 0100 0101 0101 0101 0100  ................
0x0099faa0  0101 0100 0000 0100 0000 0101 0100 0101  ................
0x0099fab0  0000 0001 0100 0100 0000 0000 0000 0000  ................
0x0099fac0  0000 0000 0000 0000 e100 0000 0000 0000  ................
0x0099fad0  0100 0001 0001 0100 0000 0001 0001 0100  ................
0x0099fae0  0101 0100 0001 0100 0000 0001 0000 0101  ................
[0x004008e2]> px @ 0x099fad0
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099fad0  0100 0001 0001 0100 0000 0001 0001 0100  ................
0x0099fae0  0101 0100 0001 0100 0000 0001 0000 0101  ................
0x0099faf0  0001 0001 0000 0000 0101 0100 0100 0101  ................
0x0099fb00  0001 0000 0001 0000 0101 0100 0100 0101  ................
0x0099fb10  0101 0001 0100 0000 0100 0101 0000 0001  ................
0x0099fb20  0101 0001 0100 0100 0100 0000 0101 0100  ................
0x0099fb30  0100 0001 0101 0101 0100 0000 0001 0101  ................
0x0099fb40  0001 0101 0101 0001 0000 0101 0000 0001  ................
0x0099fb50  0101 0001 0101 0100 0001 0000 0100 0100  ................
0x0099fb60  0001 0001 0101 0101 0100 0001 0001 0100  ................
0x0099fb70  0000 0000 0101 0000 0001 0001 0000 0001  ................
0x0099fb80  0100 0001 0000 0101 0000 0101 0001 0101  ................
0x0099fb90  0001 0100 0101 0100 0100 0000 0000 0000  ................
0x0099fba0  0000 0000 0000 0000 6104 0200 0000 0000  ........a.......
0x0099fbb0  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099fbc0  0000 0000 0000 0000 0000 0000 0000 0000  ................
```

So these three functions spread the "randomness" over the full buffer...

```
[0x004008e2]> px @ 0x099f910
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f910  0100 0000 0101 0000 0100 0000 0101 0001  ................
0x0099f920  0000 0000 0101 0000 0000 0000 0000 0000  ................
0x0099f930  0000 0000 0000 0000 0000 0000 0000 0000  ................
0x0099f940  0000 0000 0000 0000 0000 0000 0000 0000  ................
[0x004008e2]> px @ 0x099f910
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f910  0100 0000 0101 0000 0100 0000 0101 0001  ................
0x0099f920  0000 0000 0101 0000 0000 0101 0100 0100  ................
0x0099f930  0001 0001 0100 0001 0000 0001 0001 0100  ................
0x0099f940  0101 0100 0000 0100 0101 0101 0001 0101  ................
0x0099f950  0100 0001 0001 0001 0001 0101 0100 0000  ................
0x0099f960  0000 0000 0100 0100 0001 0101 0001 0000  ................
0x0099f970  0101 0101 0000 0100 0100 0000 0100 0001  ................
0x0099f980  0101 0001 0001 0001 0001 0000 0001 0101  ................
0x0099f990  0001 0100 0001 0100 0101 0101 0100 0101  ................
0x0099f9a0  0001 0001 0001 0101 0001 0101 0000 0101  ................
0x0099f9b0  0000 0100 0000 0101 0001 0101 0000 0100  ................
0x0099f9c0  0000 0100 0101 0100 0100 0001 0100 0100  ................
0x0099f9d0  0001 0100 0101 0101 0100 0000 0000 0000  ................
0x0099f9e0  0000 0000 0000 0000 e100 0000 0000 0000  ................
0x0099f9f0  0101 0000 0101 0001 0001 0000 0101 0000  ................
0x0099fa00  0001 0000 0101 0001 0101 0100 0100 0001  ................
```

Note that the original bytes in the beginning stay the same...

Breaking down what 0x00400998 does:
```
[0x00400a47]> px @ rsp
- offset -       0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x7ffea61bd4a0  00d6 1ba6 fe7f 0000 80d5 1ba6 fe7f 0000  ................
0x7ffea61bd4b0  0000 0000 1700 0000 1800 0000 1900 0000  ................
0x7ffea61bd4c0  5b00 0000 6e00 0000 e0d4 1ba6 fe7f 0000  [...n...........
0x7ffea61bd4d0  4800 0000 0000 0000 7700 0000 7c00 0000  H.......w...|...
0x7ffea61bd4e0  0001 0100 0000 0001 0001 0100 0000 0100  ................
0x7ffea61bd4f0  0001 0100 0000 0101 0001 0100 0001 0000  ................
0x7ffea61bd500  0001 0100 0001 0001 0001 0100 0001 0100  ................
0x7ffea61bd510  0001 0100 0001 0101 0001 0100 0100 0000  ................
0x7ffea61bd520  0001 0100 0100 0001 00e3 3c8f 6ee8 2b55  ..........<.n.+U
0x7ffea61bd530  c0d5 1ba6 fe7f 0000 e208 4000 0000 0000  ..........@.....
0x7ffea61bd540  0000 0000 0000 0000 30f8 9500 0000 0000  ........0.......
0x7ffea61bd550  5b00 0000 c900 0000 00d6 1ba6 fe7f 0000  [...............
0x7ffea61bd560  cf0a 4000 0000 0000 220b 4000 0000 0000  ..@.....".@.....
0x7ffea61bd570  9b0b 4000 0000 0000 e08a f705 817f 0000  ..@.............
0x7ffea61bd580  10f9 9500 0000 0000 f0f9 9500 0000 0000  ................
0x7ffea61bd590  d0fa 9500 0000 0000 0000 0000 0000 0000  ................
```

We convert "abcdefghi" into "bit strings": a is "00 01 01 00 00 00 00 01" above at 0x...bd4e0.

We take the first 0x17 bytes and put them in reverse in arr 1, then we take the next 0x18 bytes and put them in reverse in arr 2, etc.....
```
local_50h
0x7ffea61bd4e0  0001 0100 0000 0001 0001 0100 0000 0100  ................
0x7ffea61bd4f0  0001 0100 0000 01

arr1
- offset -   0 1  2 3  4 5  6 7  8 9  A B  C D  E F  0123456789ABCDEF
0x0099f910  0100 0000 0101 0000 0100 0000 0101 0001  ................
0x0099f920  0000 0000 0101 00
```


