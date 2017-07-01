from z3 import *

length = 201
s = Solver()

arr_encrypted = "0 0 1 0 0 0 1 0 1 1 0 1 0 1 1 0 1 1 1 0 0 0 1 0 1 0 1 1 1 0 1 0 0 0 0 1 0 0 0 1 1 0 1 1 0 1 1 0 0 0 0 0 1 1 0 1 1 1 0 0 1 0 1 0 1 0 1 1 0 0 1 0 1 0 1 0 1 0 0 0 0 1 1 1 0 1 0 0 1 1 0 0 0 0 0 1 1 1 0 1 1 0 0 0 1 1 1 1 1 1 1 1 0 1 1 1 0 1 0 1 1 0 1 0 1 0 0 1 0 0 0 1 0 0 0 1 1 0 0 1 0 1 0 0 1 0 0 1 1 0 0 0 1 1 0 1 1 1 0 0 1 0 0 1 0 1 1 0 0 1 1 0 1 1 1 1 0 1 1 1 0 1 0 1 1 0 0 1 0 0 1 0 0 0 1 0 1 0 0 0 1".split(" ")
arr0 = []
arr1 = []
arr2 = []
arr3 = []
for i in range(202):
	print(i)
	arr0.append(BitVec("arr0_%i" % i, 8))
	arr1.append(BitVec("arr1_%i" % i, 8))
	arr2.append(BitVec("arr2_%i" % i, 8))
	arr3.append(BitVec("arr3_%i" % i, 8))

print("Adding conditions...")
i = 0
for str_bit in arr_encrypted:
	arr0[i] = ord(str_bit) - 0x30 # Make it either 0x00 or 0x01...
	i += 1

i = 0
while(length - 0x17 > i):
	s.add(arr1[i + 0x17] == arr1[i] ^ arr1[i + 5])
	i += 1

i = 0
while(length - 0x18 > i):
	s.add(arr2[i + 0x18] == arr2[i] ^ (arr2[i + 1] ^ (arr2[i + 3] ^ arr2[i + 4])))
	i += 1

i = 0
while(length - 0x19 > i):
	s.add(arr3[i + 0x19] == arr3[i] ^ arr3[i + 3])
	i += 1

for i in range(202):
	s.add(arr0[i] == ((arr1[i] & arr2[i]) ^ (arr2[i] & arr3[i])) ^ arr3[i])
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
for i in range(0x17):
	print(m[arr1[0x16 - i]])
for i in range(0x18):
	print(m[arr2[0x17 - i]])
for i in range(0x19):
	print(m[arr3[0x18 - i]])
