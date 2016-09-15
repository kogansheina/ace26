#!/usr/bin/env python
from bitstring import BitString
from ace import writeToLst
from ace import evaluateExpression
import opcodes

NONE_SEGMENT = -1
DATA_SEGMENT = 0
CONTEXT_SEGMENT = 1
CODE_SEGMENT = 2
DATA_ERROR = -1
DATA_BYTE = 0
DATA_SHORT = 1
DATA_WORD = 2
DATA_ALIGN = 3

#segments are dictionaries of tuples (type,data)
#type : 0 - byte, 1 - short, 2 - word
dataSegment = {}
contextSegment = {}

#code is a dictionary , key =address, value =code)
codeSegment = {}

# labels is a dictionary : key is label, value is a tuple (segment,address,(path,filename,linenumber))
labels = {}

#list of tuples to be resolved later - unknown label address
#the tuple is (address in code segment,label) 
unresolved = []

#dictionary : key = address, value - for ld is the loaded address
prediction = [0]*opcodes.CODE_SEG_SIZE
#current data
current_segment = NONE_SEGMENT
current_data_address = 0
current_context_address = 0
current_code_address = 0

codedefault = 0xFC000000
	
def handle_immediate (word):
	"""
	Evaluate an immediate value 
	Returns True and the value
	Otherwise False
	"""
	e = evaluateExpression(word)
	try:
		value = eval(e)
		return (True,value)
	except NameError:
		return (False,-1)

def handle_register (word):
	"""
	Evaluate a registers
	Returns True and register value  
	OR -1 if not register
	Otherwise False
	"""
	if word.startswith('r'):
		value = eval(word[1:])
		if value < 0 or value > 31:
			return (False,0)
		else:
			return (True,value)
	else:
		return (True,-1)

def handle_label (word,tf,segment):
	"""
	Evaluate a possible label
	Returns True and labels's address
	Label's address may be 0x00FFFFFF, if it is still unresolved
	OR -1 if not label
	Otherwise False
	"""
	global unresolved
	global labels

	label = ''
	if word.startswith(':'):
		label = word[1:]
	elif word.startswith('@:'):
		label = word[2:]
	if label != '':
		if label in labels:
			valueTuple = labels[label]
			if valueTuple[0] != segment:
				return (False,0)
			value = valueTuple[1]
		else:
			labels[label] = (segment,current_code_address,tf)
			value = 0x0000FFFF
			unresolved.append((current_code_address,label))
		return (True,value)
	else:
		return (True,-1)

def check_ld (codebits,previous_codebits,store):

	if previous_codebits[opcodes.ldOpcode['direct_or_index'][0]:opcodes.ldOpcode['direct_or_index'][1]] == 0 \
		and previous_codebits[opcodes.ldOpcode['immediate_or_register'][0]:opcodes.ldOpcode['immediate_or_register'][1]] == 1:
		previous_immediate = codebits[opcodes.ldOpcode['immediate'][0]:opcodes.ldOpcode['immediate'][1]]
		if store:
			if codebits[opcodes.ldOpcode['direct_or_index'][0]:opcodes.ldOpcode['direct_or_index'][1]] == 0 \
			and codebits[opcodes.ldOpcode['immediate_or_register'][0]:opcodes.ldOpcode['immediate_or_register'][1]] == 1:
				current_immediate = codebits[opcodes.ldOpcode['immediate'][0]:opcodes.ldOpcode['immediate'][1]]
				if current_immediate == previous_immediate:
					return False
		else: # inconditional jmp
			if codebits[opcodes.jmpOpcode['immediate_or_register'][0]:opcodes.jmpOpcode['immediate_or_register'][1]] == 1:
				if previous_immediate == codebits[opcodes.jmpOpcode['immediate_value'][0]:opcodes.jmpOpcode['immediate_value'][1]]:
					return False
	return True

def checkRestrictions(listfd,tf,codebits):
	op5 = codebits[opcodes.jmpOpcode['opcode'][0]:opcodes.jmpOpcode['opcode'][1]].unpack('uint:5')[0]
	op = codebits[opcodes.ldOpcode['opcode'][0]:opcodes.ldOpcode['opcode'][1]].unpack('uint:6')[0]
	cc = current_code_address - 4
	if cc in codeSegment:
		previous = BitString(uint=codeSegment[cc],length=32)
	else:
		previous = 0
	cc -= 4
	if cc in codeSegment:
		previous2 = BitString(uint=codeSegment[cc],length=32)
	else:
		previous2 = 0
	
	if previous :
		prevop5 = previous[opcodes.jmpOpcode['opcode'][0]:opcodes.jmpOpcode['opcode'][1]].unpack('uint:5')[0]
		prevop = previous[opcodes.ldOpcode['opcode'][0]:opcodes.ldOpcode['opcode'][1]].unpack('uint:6')[0]
		# if previous opcode was Load
		if prevop == opcodes.OPCODE_CODE_LD \
		or prevop == opcodes.OPCODE_CODE_LDC \
		or prevop == opcodes.OPCODE_CODE_LDIO:
		# if current is ST check the immediate value
			if op == opcodes.OPCODE_CODE_ST:
				if not check_ld(codebits,previous,True):
					writeToLst(listfd,"ERROR : Restriction, ST cannot use the loaded value of a previous LD, in file %s at line %d" % (tf[0]+tf[1],tf[2]))
					return False
		# if previous opcode was ALU
		elif prevop == opcodes.OPCODE_CODE_ADD \
		or prevop == opcodes.OPCODE_CODE_SUB \
		or prevop == opcodes.OPCODE_CODE_MULT \
		or prevop == opcodes.OPCODE_CODE_AND \
		or prevop == opcodes.OPCODE_CODE_OR \
		or prevop == opcodes.OPCODE_CODE_XOR :
			# if current is JMP
			if op5 == opcodes.OPCODE_CODE_JMP:
				if codebits[opcodes.jmpOpcode['address_register'][0]:opcodes.jmpOpcode['address_register'][1]] == \
					previous[opcodes.aluOpcode['destination_register'][0]:opcodes.aluOpcode['destination_register'][1]]:
					writeToLst(listfd,"ERROR : Restriction, JMP cannot use the result of a previous ALU, in file %s at line %d" % (tf[0]+tf[1],tf[2]))
					return False
		# if previous opcode was some JMP
		elif prevop5 == opcodes.OPCODE_CODE_JMP \
		or prevop == opcodes.OPCODE_CODE_LJMP \
		or prevop5 == opcodes.OPCODE_CODE_CMPJMP \
		or prevop == opcodes.OPCODE_CODE_BEZ  :
			if (op5 == opcodes.OPCODE_CODE_JMP \
				and codebits[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] == opcodes.OPCODE_CONDITION_ALWAYS) \
				or op == opcodes.OPCODE_CODE_RET \
				or op == opcodes.OPCODE_CODE_CSSVR:
				writeToLst(listfd,"ERROR : Restriction, JMP,RET ot CTX_SWAP cannot be used after a JMP, in file %s at line %d" % (tf[0]+tf[1],tf[2]))
				return False
		# if previous opcode was CTX_SWAP
		elif prevop == opcodes.OPCODE_CODE_CSSVR:
			if codebits[opcodes.ldOpcode['destination_register'][0]:opcodes.ldOpcode['destination_register'][1]] >= 16 :
				writeToLst(listfd,"ERROR : Restriction, after CTX_SWAP r16-r31 cannot be used as destination, in file %s at line %d" % (tf[0]+tf[1],tf[2]))
				return False
	if previous2: # if second previous opcode was Load
		prevop = previous2[opcodes.ldOpcode['opcode'][0]:opcodes.ldOpcode['opcode'][1]].unpack('uint:6')[0]
		if prevop == opcodes.OPCODE_CODE_LD \
		or prevop == opcodes.OPCODE_CODE_LDC \
		or prevop == opcodes.OPCODE_CODE_LDIO:
		#if current is unconditional JMP
			if op5 == opcodes.OPCODE_CODE_JMP \
				and codebits[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] == opcodes.OPCODE_CONDITION_ALWAYS:
				if not check_ld(codebits,previous2,False):
					writeToLst(listfd,"ERROR : Restriction, uncontitional JMP cannot use the loaded value of a second previous LD, in file %s at line %d" % (tf[0]+tf[1],tf[2]))
					return False
	return True
	
def checkUnresolved():
	global codeSegment

	for c in range(len(unresolved)):
		tp = unresolved[c]
		label = tp[1]
		adr = tp[0]
		if label in labels :
			unresolved[c] = ('','')
			newadr = labels[label][1] # address to replace the unknown
			old = BitString(uint=codeSegment[adr],length=32) # code to put newadr
			opcode = old[opcodes.jmpOpcode['opcode'][0]:opcodes.jmpOpcode['opcode'][1]].unpack('uint:5')[0]
			if opcode == opcodes.OPCODE_CODE_JMP:
				relative_address = newadr - adr
				if relative_address > 0:
					newadr = relative_address >> 2
				else:
					newadr = (((~ (abs (relative_address) - 4 ) ) >> 2) | opcodes.SIGN_FLAG ) 
				old[opcodes.jmpOpcode['immediate_value'][0]:opcodes.jmpOpcode['immediate_value'][1]] = newadr & 0x3ff 
			else:
				opcode = old[opcodes.bezOpcode['opcode'][0]:opcodes.bezOpcode['opcode'][1]].unpack('uint:6')[0]
				if opcode == opcodes.OPCODE_CODE_BEZ \
				or opcode == opcodes.OPCODE_CODE_CMPJMP :
					relative_address = newadr - adr
					if relative_address > 0:
						newadr = relative_address >> 2
					else:
						newadr = (((~ (abs (relative_address) - 4 ) ) >> 2) | opcodes.SIGN_FLAG )
					old[opcodes.bezOpcode['immediate_value'][0]:opcodes.bezOpcode['immediate_value'][1]] = newadr & 0x3ff
				# all the 6 bits opcode
				elif opcode == opcodes.OPCODE_CODE_LD or \
					opcode == opcodes.OPCODE_CODE_ST or \
					opcode == opcodes.OPCODE_CODE_LDC or \
					opcode == opcodes.OPCODE_CODE_STC:
					old[opcodes.ldOpcode['immediate'][0]:opcodes.ldOpcode['immediate'][1]] = newadr & 0x3ff
				elif opcode == opcodes.OPCODE_CODE_LDIO or \
					opcode == opcodes.OPCODE_CODE_STIO:
					old[opcodes.ldioOpcode['immediate'][0]:opcodes.ldioOpcode['immediate'][1]] = newadr & 0xffff
				elif opcode == opcodes.OPCODE_CODE_CSSVR:
					old[opcodes.ctxswapOpcode['immediate_value'][0]:opcodes.ctxswapOpcode['immediate_value'][1]] = newadr & 0xffff			
				elif opcode == opcodes.OPCODE_CODE_LJMP:
					old[opcodes.jmplngOpcode['immediate_value'][0]:opcodes.jmplngOpcode['immediate_value'][1]] = newadr & 0x3fff
				elif opcode == opcodes.OPCODE_CODE_MOVEIMM:
					old[opcodes.movOpcode['immediate_value'][0]:opcodes.movOpcode['immediate_value'][1]] = newadr & 0xffff
			codeSegment[adr] = old.unpack('uint:32')[0] # return the solved opcode
			#print '0x%x code=0x%x' % (adr,codeSegment[adr])
		else:
			print "Label %s in not resolved" % (label)
			
def handle_assembly_line(listfiled,current,tf):
	global current_data_address
	global current_context_address
	global current_code_address
	global current_segment
	global labels
	global dataSegment
	global contextSegment
	global codeSegment
	
	ac = ('','',DATA_ALIGN)
	rt = True
	if current_segment == DATA_SEGMENT:
		current_address = current_data_address
	elif current_segment == CONTEXT_SEGMENT:
		current_address = current_context_address
	else: current_address = current_code_address
	#check line
	if current[0] == ".task":
		try:
			value = eval(evaluateExpression(current[1]))
		except NameError:
			writeToLst (listfiled,"ERROR: Data value incorrect , in file %s, line %d" % (tf[0]+tf[1],tf[2]))
			rt = False
		if value > opcodes.NUMBER_OF_THREADS:
			writeToLst (listfiled,"ERROR: Threads number overflow, in file %s, line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
			rt = False
		value = value * opcodes.NUMBER_OF_PRIVATE_REGISTERS * 4
		if value in contextSegment:
			writeToLst (listfiled,"ERROR: context segment overlapped, in file %s, line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
			rt = False
		contextSegment[value] = (current_code_address,DATA_WORD)
		current_segment = CODE_SEGMENT	
	elif current[0] == ".data":
		current_segment = DATA_SEGMENT
		try:
			current_data_address = eval(evaluateExpression(current[1]))
		except NameError:
			rt = False
			writeToLst (listfiled,"ERROR: Data value incorrect, in file %s, line %d" % (tf[0]+tf[1],tf[2]))
	elif current[0] == ".context":
		current_segment = CONTEXT_SEGMENT
		try:
			current_context_address = eval(evaluateExpression(current[1]))
		except NameError:
			rt = False
			writeToLst (listfiled,"ERROR: Context value incorrect, in file %s, line %d" % (tf[0]+tf[1],tf[2]))
	elif current[0].startswith(":"):
		if current_segment == DATA_SEGMENT:
			current_address = current_data_address
		elif current_segment == CONTEXT_SEGMENT:
			current_address = current_context_address
		else:
			current_address = current_code_address
		if current[0][1:] in labels:
			labels[current[0][1:]] = (current_segment,current_address,tf)
		else:
			labels[current[0][1:]] = (current_segment,current_address,tf)
	elif current[0] == ".code":
		current_segment = CODE_SEGMENT
		try:
			current_code_address = eval(evaluateExpression(current[1]))
		except NameError:
			rt = False
			writeToLst (listfiled,"ERROR: Code value incorrect, in file %s, line %d" % (tf[0]+tf[1],tf[2]))
	elif current_segment == DATA_SEGMENT:
		fd = handle_data(listfiled,current,tf)
		if fd[1] != DATA_ERROR: # error			
			if fd[1] != DATA_ALIGN: # align
				dataSegment[current_data_address] = (fd[2],fd[1])
				ac = (current_data_address,fd[2],fd[1])
			current_data_address = fd[0]
		else: rt = False	
	elif current_segment == CONTEXT_SEGMENT:
		fd = handle_data(listfiled,current,tf)
		if fd[1] != DATA_ERROR:			
			if fd[1] != DATA_ALIGN:
				contextSegment[current_context_address] = (fd[2],fd[1])
				ac = (current_context_address,fd[2],fd[1])		
			current_context_address = fd[0]
		else: rt = False
	else:
		if current_code_address in codeSegment:
			writeToLst (listfiled,"ERROR: Code overlapping at 0x%08x, in file %s, line %d" % (current_code_address,tf[0]+tf[1],tf[2]))
			rt = False
		else:
			fd = handle_code(listfiled,current,tf)
			if fd[0]:
				if checkRestrictions(listfiled,tf,fd[1]):
					ac = (current_code_address,fd[1].unpack('uint:32')[0],DATA_WORD)
					codeSegment[current_code_address] = fd[1].unpack('uint:32')[0]
					current_code_address += 4
			else: rt = False		
	
	return (rt,ac)

# receives list
def handle_data(listfiled,line,tf):
	"""
	handle data instructions. returns the current address,value type and its value as tuple
	"""
	
	if current_segment == DATA_SEGMENT:		
		current_address = current_data_address
		if current_address in dataSegment:
			writeToLst (listfiled,"ERROR: data segment overlapped(0x%x), in file %s, line %d" % (current_address,tf[0]+tf[1],tf[2]))
			return (current_address,DATA_ERROR,0)
		if current_address >= opcodes.DATA_SEGMENT_SIZE:
			writeToLst (listfiled,"ERROR: data segment overflow(0x%x : 0x%x), in file %s, line %d" % (current_address,opcodes.DATA_SEGMENT_SIZE,tf[0]+tf[1],tf[2]))
			return (current_address,DATA_ERROR,0)	
	else:
		current_address = current_context_address
		if current_address in contextSegment:
			writeToLst (listfiled,"ERROR: context segment overlapped(0x%x), in file %s, line %d" % (current_address,tf[0]+tf[1],tf[2]))
			return (current_address,DATA_ERROR,0)
		if current_address >= opcodes.CONTEXT_SEGMENT_SIZE:
			writeToLst (listfiled,"ERROR: context segment overflow(0x%x : 0x%x), in file %s, line %d" % (current_address,opcodes.CONTEXT_SEGMENT_SIZE,tf[0]+tf[1],tf[2]))
			return (current_address,DATA_ERROR,0)
	try:
		value = eval(evaluateExpression(line[1]))
	except NameError:
		writeToLst (listfiled,"ERROR: Data value incorrect , in file %s, line %d" % (tf[0]+tf[1],tf[2]))
		return (current_address,DATA_ERROR,0)
	rt = (current_address,DATA_ERROR,0)
	if line[0] == ".data8":
		if value < -128 or value > 0xff:
			value = value & 0xff
			writeToLst (listfiled,"WARNING: 8 bit data value truncated, in file %s, line %d" % (tf[0]+tf[1],tf[2]))
		else:			
			current_address += 1
			rt = (current_address,DATA_BYTE,value)
	elif line[0] == ".data16":
		if value < -256 or value > 0xffff:
			value = value & 0xffff
			writeToLst (listfiled,"WARNING: 16 bit data value truncated, in file %s, line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
		else:
			if current_address % 2 != 0:
				writeToLst (listfiled,"WARNING: 16 bit data value not aligned - force it, in file %s, line %d" % (tf[0]+tf[1],tf[2]))
				current_address += 1			
			current_address += 2
			rt = (current_address,DATA_SHORT,value)
	elif line[0] == ".data32":
		if current_address % 4 != 0:
			writeToLst (listfiled,"WARNING: 32 bit data value not aligned - force it, in file %s, line %d" % (tf[0]+tf[1],tf[2]))
			current_address += 4 - current_address % 4	
		current_address += 4
		rt = (current_address,DATA_WORD,value)
	elif line[0] == ".algn":
		if value == 16:
			if current_address % 2 != 0:
				current_address += 1
		elif value == 32:
			if current_address % 4 != 0:
				current_address += 4 - current_address % 4
		elif value != 8:
			writeToLst (listfiled,"ERROR: illegal value, in file %s, line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
			return (current_address,DATA_ERROR,0)
		rt = (current_address,DATA_ALIGN,0)		
	else:
		writeToLst (listfiled,"ERROR: unknown code directive, in file %s, line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
	return rt
				
def handle_code(listfiled,line,tf):
	"""
	call the opcode procedure, returns
	"""
	
	if current_code_address >= opcodes.CODE_SEGMENT_SIZE:
		writeToLst (listfiled,"ERROR: Code segment overflow, in file %s, line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
	else:
		dict = {"jmp":jmp,
			"ljmp":ljmp,
			"jmp=0":jmp0,
			"jmp!=0":jmpn0,
			"jmp>=0":jmpge0,
			"jmp<=0":jmple0,
			"jmp>0":jmpg0,
			"jmp<0":jmpl0,
			"jmp_set":jmp_set,
			"jmp_clr":jmp_clr,
			"jmpz":jmpz,
			"jmpnz":jmpnz,
			"jmp_cmp":jmp_cmp,
			"call":call,
			"lcall":lcall,
			"call=0":call0,
			"call!=0":calln0,
			"call>0":callg0,
			"call>=0":callge0,
			"call<=0":callle0,
			"call<0":calll0,
			"call_set":call_set,
			"call_clr":call_clr,
			"callz":callz,
			"callnz":callnz,
			"alu":alu,
			"ret":ret,
			"ld8":ld8, 
			"ld16":ld16,
			"ld32":ld32,
			"ld64":ld64,
			"ldc8":ldc8, 
			"ldc16":ldc16,
			"ldc32":ldc32,
			"ldc64":ldc64,
			"st8":st8, 
			"st16":st16,
			"st32":st32,
			"st64":st64,
			"stc8":stc8, 
			"stc16":stc16,
			"stc32":stc32,
			"stc64":stc64,
			"ldio8":ldio8,
			"stio8":stio8,
			"ldio16":ldio16,
			"stio16":stio16,
			"ldio32":ldio32,
			"stio32":stio32,
			"mov":mov,
			"shift":shift,
			"extract":extract,
			"insert":insert,
			"ctx_swap":ctxswap,
			"dma_rd":dmard,
			"dma_lkp":dmaalu,
			"dma_wr":dmawr,
			"hash":hashf,
			"crc32":crccalc32,
			"crc10":crccalc10,
			"cam_lkp":camlkp,
			"bbtx":bbtx,
			"bbmsg":bbmsg,
			"ffi8":ffi8,
			"ffi16":ffi16,
			"chksm":chksm,
			"auth":auth,
			"counter":counter,
			"crypt":crypt,
			"signext":signext,
			"nop":nop
			}
		if line[0] in dict:
 			functionToCall = dict[line[0]]
 			return functionToCall(listfiled,line[1:],tf)
 		else:
 			writeToLst (listfiled,"ERROR : unknown assembler opcode '%s', in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
 	return (False,BitString(0x00000000))		


def check_jmp(operand,codeing,imed):
	global prediction
	
	if operand == "ds1":
		codeing[opcodes.jmpOpcode['execute_delay_slot'][0]:opcodes.jmpOpcode['execute_delay_slot'][1]] = 1
	elif operand == "ds2":
		codeing[opcodes.jmpOpcode['execute_delay_slot'][0]:opcodes.jmpOpcode['execute_delay_slot'][1]] = 2
	elif operand == "predict" and not imed:
		codeing[opcodes.jmpOpcode['update'][0]:opcodes.jmpOpcode['update'][1]] = 1
	elif operand == "taken":
		prediction[ current_code_address >>2 ] = 1
	else:
		return (False,codeing)
	return (True,codeing)
	
def check_jmp_set(listfiled,line,tf,codeing):

	tp = handle_register(line[1])
	if tp[0] and tp[1] != -1:
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = tp[1]
	else:
		writeToLst (listfiled,"ERROR : JMP wrong register : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	if len(line) > 2:
		tp = handle_immediate(line[2])
		if tp[0] :
			if tp[1] > 0x1F:
				writeToLst (listfiled,"ERROR : JMP immediate value  error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeing)
			else:
				if tp[1] <= 31:
					codeing[opcodes.jmpOpcode['condition_bit_offset'][0]:opcodes.jmpOpcode['condition_bit_offset'][1]] = tp[1] # immediate				
				else:
					writeToLst (listfiled,"ERROR : JMP immediate value error(1) : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
					return (False,codeing)
		else:
			writeToLst (listfiled,"ERROR : JMP immediate value error(1) : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeing)
	else:
		writeToLst (listfiled,"ERROR : JMP immediate value expected, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	if len(line) > 3:
		rr = check_jmp(line[3],codeing,False)
		if len(line) > 4 and rr[0]:
			return check_jmp(line[4],codeing,False)
	return (True,codeing)
	
def assembly_jmp(listfiled,line,tf,condition,is_call):	
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	imed = False
	codeing[opcodes.jmpOpcode['opcode'][0]:opcodes.jmpOpcode['opcode'][1]] = opcodes.OPCODE_CODE_JMP
	codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_ALWAYS
	codeing[opcodes.jmpOpcode['call'][0]:opcodes.jmpOpcode['call'][1]] = is_call	
	if len(line) < 1:
		writeToLst (listfiled,"ERROR : JMP : wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if tp[0] and tp[1] != -1:
		codeing[opcodes.jmpOpcode['address_register'][0]:opcodes.jmpOpcode['address_register'][1]] = tp[1]
	elif not tp[0]:
		writeToLst (listfiled,"ERROR : JMP destination error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else:
		tp = handle_label(line[0],tf,CODE_SEGMENT)
		if not tp[0]:
			writeToLst (listfiled,"ERROR : JMP label : '%s' not in code segment, in file %s line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		elif tp[1] == -1 :
			writeToLst (listfiled,"ERROR : JMP destination error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		else:
			imed = True
			codeing[opcodes.jmpOpcode['immediate_or_register'][0]:opcodes.jmpOpcode['immediate_or_register'][1]] = 1
			if tp[1] != 0x0000FFFF:				
				relative_address = tp[1] - current_code_address
				if ( abs ( relative_address ) > opcodes.MAX_RELATIVE_JMP_DISTANCE ):
					writeToLst (listfiled,"ERROR : JMP label unreachable: '0x%x - 0x%x' not in code segment, in file %s line %d" % (relative_address,tp[1],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				if relative_address > 0:
					codeing[opcodes.jmpOpcode['immediate_value'][0]:opcodes.jmpOpcode['immediate_value'][1]] = (relative_address >> 2)  # immediate value
				else:
					codeing[opcodes.jmpOpcode['immediate_value'][0]:opcodes.jmpOpcode['immediate_value'][1]] = (((~ (abs (relative_address) - 4 ) ) >> 2) | opcodes.SIGN_FLAG ) 
	if condition == opcodes.ASSEMBLY_CONDITION_ZERO:
		if len(line) > 1:
			if not check_jmp(line[1],codeing,imed)[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 2:
			tp = check_jmp(line[2],codeing,imed)
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			codeing = tp[1]
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_EQUAL
	elif condition == opcodes.ASSEMBLY_CONDITION_NOT_ZERO:
		if len(line) > 1:
			if not check_jmp(line[1],codeing,imed)[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 2:
			tp = check_jmp(line[2],codeing,imed)
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			codeing = tp[1]
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_EQUAL
		codeing[opcodes.jmpOpcode['invert_condition'][0]:opcodes.jmpOpcode['invert_condition'][1]] = 1
	elif condition == opcodes.ASSEMBLY_CONDITION_LESS:
		if len(line) > 1:
			tp = check_jmp(line[1],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 2:
			tp = check_jmp(line[2],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_LESS
	elif condition == opcodes.ASSEMBLY_CONDITION_LESS_EQUAL:
		if len(line) > 1:
			tp = check_jmp(line[1],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 2:
			tp = check_jmp(line[2],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_GREATER
		codeing[opcodes.jmpOpcode['invert_condition'][0]:opcodes.jmpOpcode['invert_condition'][1]] = 1
	elif condition == opcodes.ASSEMBLY_CONDITION_GREATER:
		if len(line) > 1:
			tp = check_jmp(line[1],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 2:
			tp = check_jmp(line[2],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_GREATER	
	elif condition == opcodes.ASSEMBLY_CONDITION_GREATER_EQUAL:
		if len(line) > 1:
			tp = check_jmp(line[1],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 2:
			tp = check_jmp(line[2],codeing,imed)
			codeing = tp[1]
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		codeing[opcodes.jmpOpcode['condition'][0]:opcodes.jmpOpcode['condition'][1]] = opcodes.OPCODE_CONDITION_LESS
		codeing[opcodes.jmpOpcode['invert_condition'][0]:opcodes.jmpOpcode['invert_condition'][1]] = 1
	elif condition == opcodes.ASSEMBLY_CONDITION_SET:
		if len(line) < 2:
			writeToLst (listfiled,"ERROR : JMP register expected, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		tp = check_jmp_set(listfiled,line,tf,codeing)
		codeing = tp[1]
		if not tp[0]:
			return (False,codeingdef)
		codeing[opcodes.jmpOpcode['jmp_register'][0]:opcodes.jmpOpcode['jmp_register'][1]] = 1		
	elif condition == opcodes.ASSEMBLY_CONDITION_CLEAR:
		if len(line) < 2:
			writeToLst (listfiled,"ERROR : JMP register expected, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		tp = check_jmp_set(listfiled,line,tf,codeing)
		codeing = tp[1]
		if not tp[0]:
			return (False,codeingdef)
		codeing[opcodes.jmpOpcode['jmp_register'][0]:opcodes.jmpOpcode['jmp_register'][1]] = 1
		codeing[opcodes.jmpOpcode['invert_condition'][0]:opcodes.jmpOpcode['invert_condition'][1]] = 1
	elif condition == opcodes.ASSEMBLY_CONDITION_NONE:
		if len(line) > 1:
			writeToLst (listfiled,"ERROR : JMP unexpected symbol '%s' , in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)
	
def jmp(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_NONE,False)
		
def jmp0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_ZERO,False)		
	
def jmpn0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_NOT_ZERO,False)		
	
def jmpge0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_GREATER_EQUAL,False)	
	
def jmple0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_LESS_EQUAL,False)		
	
def jmpg0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_GREATER,False)		
	
def jmpl0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_LESS,False)
	
def jmp_set(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_SET,False)	
	
def jmp_clr(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_CLEAR,False)		
	
def call(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_NONE,True)		

def call0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_ZERO,True)		
	
def calln0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_NOT_ZERO,True)	
	
def callg0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_GREATER,True)		
	
def callge0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_GREATER_EQUAL,True)	
	
def calll0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_LESS,True)	
	
def callle0(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_LESS_EQUAL,True)		
	
def call_set(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_SET,True)	
	
def call_clr(listfiled,line,tf):
	return assembly_jmp(listfiled,line,tf,opcodes.ASSEMBLY_CONDITION_CLEAR,True)
	
def assembly_ljmp(listfiled,line,tf,is_call):
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	codeing[opcodes.jmplngOpcode['opcode'][0]:opcodes.jmplngOpcode['opcode'][1]] = opcodes.OPCODE_CODE_LJMP
	codeing[opcodes.jmplngOpcode['call'][0]:opcodes.jmplngOpcode['call'][1]] = is_call
	if len(line) < 1:
		writeToLst (listfiled,"ERROR : JMP : wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_label(line[0],tf,CODE_SEGMENT)
	if not tp[0]:
		writeToLst (listfiled,"ERROR : JMP label not in code segment, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] == -1:
		writeToLst (listfiled,"ERROR : JMP destination not in code segment, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.jmplngOpcode['immediate_value'][0]:opcodes.jmplngOpcode['immediate_value'][1]] = tp[1] & 0x3ff # immediate value			
	return (True,codeing)
	
def ljmp(listfiled,line,tf):
 	return assembly_ljmp(listfiled,line,tf,False)		
	
def lcall(listfiled,line,tf):
	return assembly_ljmp(listfiled,line,tf,True)		

def check_bez(operand,codeing,imed):
	global prediction
	
	if operand == "32bit":
		codeing[opcodes.bezOpcode['size'][0]:opcodes.bezOpcode['size'][1]] = opcodes.OPCODE_32BIT
	elif operand == "16msb":
		codeing[opcodes.bezOpcode['size'][0]:opcodes.bezOpcode['size'][1]] = opcodes.OPCODE_16MSB
	elif operand == "16lsb":
		codeing[opcodes.bezOpcode['size'][0]:opcodes.bezOpcode['size'][1]] = opcodes.OPCODE_16LSB
	elif operand == "ds1":
		codeing[opcodes.bezOpcode['execute_delay_slot'][0]:opcodes.bezOpcode['execute_delay_slot'][1]] = 1
	elif operand== "ds2":
		codeing[opcodes.bezOpcode['execute_delay_slot'][0]:opcodes.bezOpcode['execute_delay_slot'][1]] = 2
	elif operand == "predict" and not imed:
		codeing[opcodes.bezOpcode['update'][0]:opcodes.bezOpcode['update'][1]] = 1
	elif operand == "taken":
		prediction[ current_code_address >>2 ] = 1
	else:
		return (False,codeing)
	return (True,codeing)
	
def assembly_bez(listfiled,line,tf,condition,is_call):
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	imed = False
	codeing[opcodes.bezOpcode['opcode'][0]:opcodes.bezOpcode['opcode'][1]] = opcodes.OPCODE_CODE_BEZ
	codeing[opcodes.bezOpcode['size'][0]:opcodes.bezOpcode['size'][1]] = opcodes.OPCODE_32BIT
	codeing[opcodes.bezOpcode['invert_condition'][0]:opcodes.bezOpcode['invert_condition'][1]] = condition
	codeing[opcodes.bezOpcode['call'][0]:opcodes.bezOpcode['call'][1]] = is_call
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : JMP : wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : JMP destination error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else:
		if tp[1] != -1:
			codeing[opcodes.bezOpcode['address_register'][0]:opcodes.bezOpcode['address_register'][1]] = tp[1]
		else:
			tp = handle_label(line[0],tf,CODE_SEGMENT)
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP label : '%s' not in code segment, in file %s line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if tp[1] == -1:
				writeToLst (listfiled,"ERROR : JMP destination error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			imed = True
			codeing[opcodes.bezOpcode['immediate_or_register'][0]:opcodes.bezOpcode['immediate_or_register'][1]] = 1 # immediate
			if tp[1] != 0x0000ffff:
				relative_address = tp[1] - current_code_address
				if ( abs ( relative_address ) > opcodes.MAX_RELATIVE_JMP_DISTANCE ):
					writeToLst (listfiled,"ERROR : JMP label unreachable: '0x%x - 0x%x' not in code segment, in file %s line %d" % (relative_address,tp[1],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				if relative_address > 0:
					codeing[opcodes.bezOpcode['immediate_value'][0]:opcodes.bezOpcode['immediate_value'][1]] = (relative_address >> 2)  # immediate value
				else:
					codeing[opcodes.bezOpcode['immediate_value'][0]:opcodes.bezOpcode['immediate_value'][1]] = (((~ (abs (relative_address) - 4 ) ) >> 2) | opcodes.SIGN_FLAG) 
	tp = handle_register(line[1])
	if tp[0] and tp[1] != -1:
		codeing[opcodes.bezOpcode['source_a'][0]:opcodes.bezOpcode['source_a'][1]] = tp[1]
	else:
		writeToLst (listfiled,"ERROR : JMP reister expected : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if len(line) > 2:
		tp = check_bez(line[2],codeing,imed)
		codeing = tp[1]
		if not tp[0]:		
			writeToLst (listfiled,"ERROR : JMP unexpected symbol : '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	if len(line) > 3:
		tp = check_bez(line[3],codeing,imed)
		codeing = tp[1]
		if not tp[0]:		
			writeToLst (listfiled,"ERROR : JMP unexpected symbol : '%s', in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	if len(line) > 4:
		tp = check_bez(line[4],codeing,imed)
		codeing = tp[1]
		if not tp[0]:		
			writeToLst (listfiled,"ERROR : JMP unexpected symbol : '%s', in file %s line %d" % (line[4],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)

def jmpz(listfiled,line,tf):
 	return assembly_bez(listfiled,line,tf,False,False)		
	
def jmpnz(listfiled,line,tf):
	return assembly_bez(listfiled,line,tf,True,False)		
	
def jmp_cmp(listfiled,line,tf):
	global prediction
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	imed = False
	codeing[opcodes.cmpjmpOpcode['opcode'][0]:opcodes.cmpjmpOpcode['opcode'][1]] = opcodes.OPCODE_CODE_CMPJMP
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : JMP : wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if tp[0] and tp[1] != -1:
		codeing[opcodes.cmpjmpOpcode['address_register'][0]:opcodes.cmpjmpOpcode['address_register'][1]] = tp[1]
	elif not tp[0]:
		writeToLst (listfiled,"ERROR : JMP destination error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else:
		tp = handle_label(line[0],tf,CODE_SEGMENT)
		if tp[0] and tp[1] == -1:
			writeToLst (listfiled,"ERROR : JMP destination  error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		if not tp[0]:
			writeToLst (listfiled,"ERROR : JMP label : '%s' not in code segment, in file %s line %d" % (line[0][1:],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		codeing[opcodes.cmpjmpOpcode['immediate_or_register'][0]:opcodes.cmpjmpOpcode['immediate_or_register'][1]] = 1
		imed = True			
		if tp[1] != 0x0000FFFF:
			relative_address = tp[1] - current_code_address
			if ( abs ( relative_address ) > opcodes.MAX_RELATIVE_JMP_DISTANCE ):
				writeToLst (listfiled,"ERROR : JMP label unreachable: '0x%x - 0x%x' not in code segment, in file %s line %d" % (relative_address,tp[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if relative_address > 0:
				codeing[opcodes.cmpjmpOpcode['immediate_value'][0]:opcodes.cmpjmpOpcode['immediate_value'][1]] = (relative_address >> 2)  # immediate value
			else:
				codeing[opcodes.cmpjmpOpcode['immediate_value'][0]:opcodes.cmpjmpOpcode['immediate_value'][1]] = (((~ (abs (relative_address) - 4 ) ) >> 2) | opcodes.SIGN_FLAG) 
	tp = handle_register(line[1])
	if tp[0] and tp[1] == -1:
		writeToLst (listfiled,"ERROR : JMP register expected : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	elif not tp[0]:
		writeToLst (listfiled,"ERROR : JMP register error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.cmpjmpOpcode['source_a'][0]:opcodes.cmpjmpOpcode['source_a'][1]] = tp[1]
	if line[2] == '==':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_EQUAL
	elif line[2] == '!=':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_EQUAL
		codeing[opcodes.cmpjmpOpcode['invert_condition'][0]:opcodes.cmpjmpOpcode['invert_condition'][1]] = 1
	elif line[2] == '>':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_GREATER
	elif line[2] == '<=':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_GREATER
		codeing[opcodes.cmpjmpOpcode['invert_condition'][0]:opcodes.cmpjmpOpcode['invert_condition'][1]] = 1
	elif line[2] == 'or':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_BIT_OR
	elif line[2] == '!or':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_BIT_OR
		codeing[opcodes.cmpjmpOpcode['invert_condition'][0]:opcodes.cmpjmpOpcode['invert_condition'][1]] = 1
	elif line[2] == 'and':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_BIT_AND
	elif line[2] == '!and':
		codeing[opcodes.cmpjmpOpcode['operation'][0]:opcodes.cmpjmpOpcode['operation'][1]] = opcodes.OPCODE_OPERATION_BIT_AND
		codeing[opcodes.cmpjmpOpcode['invert_condition'][0]:opcodes.cmpjmpOpcode['invert_condition'][1]] = 1
	else:
		writeToLst (listfiled,"ERROR : JMP unexpected symbol : '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : JMP destination error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[0]:
		if tp[1] != -1:
			codeing[opcodes.cmpjmpOpcode['source_b'][0]:opcodes.cmpjmpOpcode['source_b'][1]] = tp[1]
		else:
			tp = handle_immediate(line[3])
			if not tp[0]:
				writeToLst (listfiled,"ERROR : JMP immediate value error(1) : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if tp[1] != -1:
				if tp[1] > 0x1f:
					writeToLst (listfiled,"ERROR : JMP immediate value  error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				else:
					codeing[opcodes.cmpjmpOpcode['bsel'][0]:opcodes.cmpjmpOpcode['bsel'][1]] = 1 # immediate
					codeing[opcodes.cmpjmpOpcode['source_b'][0]:opcodes.cmpjmpOpcode['source_b'][1]] = tp[1]			
	if len(line) > 5:
		if line[4] == 'predict' and not imed:
			codeing[opcodes.cmpjmpOpcode['update'][0]:opcodes.cmpjmpOpcode['update'][1]] = 1
		elif line[4] == 'taken':
			prediction[ current_code_address >>2 ] = 1
		else:
			writeToLst (listfiled,"ERROR : JMP option  error : '%s', in file %s line %d" % (line[4],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
	return (True,codeing)	
				
def callnz(listfiled,line,tf):
	return assembly_bez(listfiled,line,tf,False,True)
	
def callz(listfiled,line,tf):
	return assembly_bez(listfiled,line,tf,True,True)
 			
def ret(listfiled,line,tf):

	codeing = BitString('0x00000000')
	codeing[opcodes.retOpcode['opcode'][0]:opcodes.retOpcode['opcode'][1]] = opcodes.OPCODE_CODE_RET	
	return (True,codeing)
	
def alu(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	codeing[opcodes.aluOpcode['update_flags'][0]:opcodes.aluOpcode['update_flags'][1]] = 1
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : ALU : wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : ALU dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] == -1:
		writeToLst (listfiled,"ERROR : ALU dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.aluOpcode['destination_register'][0]:opcodes.aluOpcode['destination_register'][1]] = tp[1] # dest	
	tp = handle_register(line[1])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : ALU A_operand error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] == -1:
		writeToLst (listfiled,"ERROR : ALU A_operand error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.aluOpcode['source_a'][0]:opcodes.aluOpcode['source_a'][1]] = tp[1] # A operand
	tp = handle_register(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : ALU B_operand error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] != -1:
		codeing[opcodes.aluOpcode['source_b_or_immediate'][0]:opcodes.aluOpcode['source_b_or_immediate'][1]] = tp[1] # B operand
	else:
		tp = handle_immediate(line[3])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : ALU B_operand error(2) : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		else:
			if tp[1] > 0xff:
				writeToLst (listfiled,"ERROR : ALU B_operand error(1) : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
				return (False,codeingdef) 
			else:
				codeing[opcodes.aluOpcode['immediate_or_register'][0]:opcodes.aluOpcode['immediate_or_register'][1]] = 1 # immediate value
				codeing[opcodes.aluOpcode['source_b_or_immediate'][0]:opcodes.aluOpcode['source_b_or_immediate'][1]] = tp[1] 
	if line[2].endswith('~'):
		codeing[opcodes.aluOpcode['invert_source'][0]:opcodes.aluOpcode['invert_source'][1]] = 1 # invert
		op = line[2].replace('~','')
	else:
		op = line[2]
	if op == '+':
		codeing[opcodes.aluOpcode['opcode'][0]:opcodes.aluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_ADD
	elif op == '-':
		codeing[opcodes.aluOpcode['opcode'][0]:opcodes.aluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_SUB
	elif op == '*':
		codeing[opcodes.aluOpcode['opcode'][0]:opcodes.aluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_MULT
	elif op == 'and':
		codeing[opcodes.aluOpcode['opcode'][0]:opcodes.aluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_AND
	elif op == 'or':
		codeing[opcodes.aluOpcode['opcode'][0]:opcodes.aluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_OR
	elif op == 'xor':
		codeing[opcodes.aluOpcode['opcode'][0]:opcodes.aluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_XOR	
	else:		
		writeToLst (listfiled,"ERROR : ALU operator error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if len(line) >= 5:
		codeing[opcodes.aluOpcode['update_flags'][0]:opcodes.aluOpcode['update_flags'][1]] = 1 #  update flags
		if line[4] == 'flags_bypass' or line[4] == 'bypass_flags':
			codeing[opcodes.aluOpcode['update_flags'][0]:opcodes.aluOpcode['update_flags'][1]] = 0 # do not update flags
		elif line[4] == '<<8':
			if op == '*':
				writeToLst (listfiled,"ERROR : ALU shift flag is forbidden with '*' operator , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			else:
				codeing[opcodes.aluOpcode['byte_shift'][0]:opcodes.aluOpcode['byte_shift'][1]] = opcodes.OPCODE_BYTE_SHIFT_LEFT_1
		elif line[4] == '<<16':
			if op == '*':
				writeToLst (listfiled,"ERROR : ALU shift flag is forbidden with '*' operator , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			else:
				codeing[opcodes.aluOpcode['byte_shift'][0]:opcodes.aluOpcode['byte_shift'][1]] = opcodes.OPCODE_BYTE_SHIFT_LEFT_2
		elif line[4] == '<<24':
			if op == '*':
				writeToLst (listfiled,"ERROR : ALU shift flag is forbidden with '*' operator , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			else:
				codeing[opcodes.aluOpcode['byte_shift'][0]:opcodes.aluOpcode['byte_shift'][1]] = opcodes.OPCODE_BYTE_SHIFT_LEFT_3
		elif line[4] == '>>8':
			if op == '*':
				writeToLst (listfiled,"ERROR : ALU shift flag is forbidden with '*' operator , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			else:
				codeing[opcodes.aluOpcode['byte_shift'][0]:opcodes.aluOpcode['byte_shift'][1]] = opcodes.OPCODE_BYTE_SHIFT_RIGHT_1
		elif line[4] == '>>16':
			codeing[opcodes.aluOpcode['byte_shift'][0]:opcodes.aluOpcode['byte_shift'][1]] = opcodes.OPCODE_BYTE_SHIFT_RIGHT_2
		elif line[4] == '>>24':
			if op == '*':
				writeToLst (listfiled,"ERROR : ALU shift flag is forbidden with '*' operator , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			else:
				codeing[opcodes.aluOpcode['byte_shift'][0]:opcodes.aluOpcode['byte_shift'][1]] = opcodes.OPCODE_BYTE_SHIFT_RIGHT_3
		else:
			writeToLst (listfiled,"ERROR : ALU option error : %s, in file %s line %d" % (line[4],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
			
	return (True,codeing)
#################################################
#              ldX / ldcX / stX / stcX 
################################################
	
def assembly_ld (listfiled,line,tf,opcode,size):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	imed_or_reg = 0
	immediate_address = 0
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : LD - wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : LD dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	elif tp[1] == -1:
		writeToLst (listfiled,"ERROR : LD dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if size == opcodes.OPCODE_SIZE_64 and (tp[1] & 1 == 1):
		writeToLst (listfiled,"ERROR : LD destination register must be even, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.ldOpcode['opcode'][0]:opcodes.ldOpcode['opcode'][1]] = opcode
	codeing[opcodes.ldOpcode['destination_register'][0]:opcodes.ldOpcode['destination_register'][1]] = tp[1] # dest	
	tp = handle_label(line[1],tf,DATA_SEGMENT)
	if not tp[0]:
		writeToLst (listfiled,"ERROR : LD label : %s not in data segment, in file %s line %d" % (line[1][1:],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else:
		if tp[1] != -1:
			imed_or_reg = 1
			immediate_address = tp[1]
			if immediate_address > 0xffff:
				writeToLst (listfiled,"WARNING : LD label : %s has too large value, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			codeing[opcodes.ldOpcode['immediate_or_register'][0]:opcodes.ldOpcode['immediate_or_register'][1]] = 1 # immediate
			codeing[opcodes.ldOpcode['immediate'][0]:opcodes.ldOpcode['immediate'][1]] = immediate_address & 0xffff
		else:
			tp = handle_register(line[1])
			if not tp[0]:
				writeToLst (listfiled,"ERROR : LD sram address error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			else:
				if tp[1] != -1:
					codeing[opcodes.ldOpcode['base_address'][0]:opcodes.ldOpcode['base_address'][1]] = tp[1]
				else:
					tp = handle_immediate(line[1])
					if not tp[0]:
						writeToLst (listfiled,"ERROR : LD immediate value error(1) : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
						return (False,codeingdef)
					else:
						imed_or_reg = 1
						immediate_address = tp[1]
						if immediate_address > 0xffff:
							writeToLst (listfiled,"ERROR : LD immediate value  error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
							return (False,codeingdef)
						codeing[opcodes.ldOpcode['immediate_or_register'][0]:opcodes.ldOpcode['immediate_or_register'][1]] = 1 # immediate
						codeing[opcodes.ldOpcode['immediate'][0]:opcodes.ldOpcode['immediate'][1]] = immediate_address # immediate value
	lowhigh = False
	if len(line) > 2:
		if (line[2] == 'low' or line[2] == 'high') and imed_or_reg == 1:
			writeToLst (listfiled,"ERROR : low/high option does go with immediate value, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		if line[2] == 'low':
			lowhigh = True
			codeing[opcodes.ldOpcode['high_or_low'][0]:opcodes.ldOpcode['high_or_low'][1]] = 0
		elif line[2] == 'high':
			lowhigh = True
			codeing[opcodes.ldOpcode['high_or_low'][0]:opcodes.ldOpcode['high_or_low'][1]] = 1
		else:
			codeing[opcodes.ldOpcode['direct_or_index'][0]:opcodes.ldOpcode['direct_or_index'][1]] = 1 # immediate
			tp = handle_register(line[2])
			if not tp[0]:
				writeToLst (listfiled,"ERROR : LD sram address error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			elif tp[1] != -1:
				codeing[opcodes.ldOpcode['offset'][0]:opcodes.ldOpcode['offset'][1]] = tp[1] << 1
				
			else:
				tp = handle_immediate(line[2])
				if not tp[0]:
					writeToLst (listfiled,"ERROR : LD immediate value error(3) : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				codeing[opcodes.ldOpcode['immediate_or_register'][0]:opcodes.ldOpcode['immediate_or_register'][1]] = 1
				#if imed_or_reg == 1:
				#	writeToLst (listfiled,"ERROR : LD immediate value error(2) : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				#	return (False,codeingdef)
				if tp[1] > 0x7ff:
					writeToLst (listfiled,"ERROR : LD immediate value  error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				else:
					codeing[opcodes.ldOpcode['offset'][0]:opcodes.ldOpcode['offset'][1]] = tp[1]
		if len(line) > 3:
			if (line[3] == 'low' or line[3] == 'high') and (imed_or_reg == 1 or lowhigh):
				writeToLst (listfiled,"ERROR : low/high option does go with immediate value, in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if line[3] == 'low':
				codeing[opcodes.ldOpcode['high_or_low'][0]:opcodes.ldOpcode['high_or_low'][1]] = 0
			elif line[3] == 'high':
				codeing[opcodes.ldOpcode['high_or_low'][0]:opcodes.ldOpcode['high_or_low'][1]] = 1
			else:
				writeToLst (listfiled,"ERROR : LD wrong option : '%s', in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
	codeing[opcodes.ldOpcode['size'][0]:opcodes.ldOpcode['size'][1]] = size
	if size == opcodes.OPCODE_SIZE_16:
		if immediate_address & 1!= 0:
			writeToLst (listfiled,"ERROR : LD immediate address not aligned to 16 bits, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	elif size == opcodes.OPCODE_SIZE_32:
		if immediate_address & 3 != 0:
			writeToLst (listfiled,"ERROR : LD immediate address not aligned to 32 bits, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	elif size == opcodes.OPCODE_SIZE_64:
		if immediate_address & 7 != 0:
			writeToLst (listfiled,"ERROR : LD immediate address not aligned to 64 bits, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)

def ld8(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LD,opcodes.OPCODE_SIZE_8)
	 
def ld16(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LD,opcodes.OPCODE_SIZE_16)

def ld32(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LD,opcodes.OPCODE_SIZE_32)
	
def ld64(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LD,opcodes.OPCODE_SIZE_64)
	
def ldc8(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LDC,opcodes.OPCODE_SIZE_8)
	
def ldc16(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LDC,opcodes.OPCODE_SIZE_16)
	
def ldc32(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LDC,opcodes.OPCODE_SIZE_32)
	
def ldc64(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_LDC,opcodes.OPCODE_SIZE_64)	

def st8(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_ST,opcodes.OPCODE_SIZE_8)
	 
def st16(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_ST,opcodes.OPCODE_SIZE_16)
	
def st32(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_ST,opcodes.OPCODE_SIZE_32)
	
def st64(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_ST,opcodes.OPCODE_SIZE_64)
	
def stc8(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_STC,opcodes.OPCODE_SIZE_8)
	
def stc16(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_STC,opcodes.OPCODE_SIZE_16)
	
def stc32(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_STC,opcodes.OPCODE_SIZE_32)
	
def stc64(listfiled,line,tf):
	return assembly_ld(listfiled,line,tf,opcodes.OPCODE_CODE_STC,opcodes.OPCODE_SIZE_64)

#################################################
#              ldioX / stioX
################################################	
def assembly_ldio(listfiled,line,tf,opcode,size):
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : LDIO - wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if tp[0] and tp[1] == -1:
		writeToLst (listfiled,"ERROR : LDIO dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if not tp[0]:
		writeToLst (listfiled,"ERROR : LDIO dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.ldioOpcode['opcode'][0]:opcodes.ldioOpcode['opcode'][1]] = opcode
	if opcode == opcodes.OPCODE_CODE_LDIO:
		codeing[opcodes.ldioOpcode['destination_register'][0]:opcodes.ldioOpcode['destination_register'][1]] = tp[1] # dest
	else:
		codeing[opcodes.ldioOpcode['source_address'][0]:opcodes.ldioOpcode['source_address'][1]] = tp[1]
	imed_or_reg = 0
	immediate_address = 0
	tp = handle_label(line[1],tf,DATA_SEGMENT)
	if not tp[0]:
		writeToLst (listfiled,"ERROR : LDIO label : '%s' not in data segment, in file %s line %d" % (line[1][1:],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else:
		if tp[1] != -1:
			imed_or_reg = 1
			immediate_address = tp[1]
			codeing[opcodes.ldioOpcode['immediate_or_register'][0]:opcodes.ldioOpcode['immediate_or_register'][1]] = 1 # immediate
			codeing[opcodes.ldioOpcode['immediate'][0]:opcodes.ldioOpcode['immediate'][1]] = immediate_address & 0x3ff
		else:
			tp = handle_register(line[1])
			if not tp[0]:
				writeToLst (listfiled,"ERROR : LDIO address error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			elif tp[1] != -1:
				codeing[opcodes.ldioOpcode['address'][0]:opcodes.ldioOpcode['address'][1]] = tp[1]
			else:
				tp = handle_immediate(line[1])
				if not tp[0]:
					writeToLst (listfiled,"ERROR : LDIO immediate value error(4) : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				if tp[1] != -1:
					if tp[1] > 0x3ff:
						writeToLst (listfiled,"ERROR : LDIO immediate value  error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
						return (False,codeingdef)
				imed_or_reg = 1
				immediate_address = tp[1]
				codeing[opcodes.ldioOpcode['immediate_or_register'][0]:opcodes.ldioOpcode['immediate_or_register'][1]] = 1 # immediate
				codeing[opcodes.ldioOpcode['immediate'][0]:opcodes.ldioOpcode['immediate'][1]] = immediate_address # immediate value
	if len(line) > 2:
		if (line[2] == 'low' or line[2] == 'high') and imed_or_reg == 1:
			writeToLst (listfiled,"ERROR : LDIO low/high option does go with immediate value, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		if line[2] == 'low':
			codeing[opcodes.ldioOpcode['high_or_low'][0]:opcodes.ldioOpcode['high_or_low'][1]] = 0
		elif line[2] == 'high':
			codeing[opcodes.ldioOpcode['high_or_low'][0]:opcodes.ldioOpcode['high_or_low'][1]] = 1
		else:
			writeToLst (listfiled,"ERROR : LDIO option '%s' wrong, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)

	codeing[opcodes.ldOpcode['size'][0]:opcodes.ldOpcode['size'][1]] = size
	if size == opcodes.OPCODE_SIZE_16:
		if immediate_address & 1!= 0:
			writeToLst (listfiled,"ERROR : LDIO immediate address not aligned to 16 bits, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	elif size == opcodes.OPCODE_SIZE_32:
		if immediate_address & 3 != 0:
			writeToLst (listfiled,"ERROR : LDIO immediate address not aligned to 32 bits, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)
	
def ldio8(listfiled,line,tf):
	return assembly_ldio(listfiled,line,tf,opcodes.OPCODE_CODE_LDIO,opcodes.OPCODE_SIZE_8)
	
def ldio16(listfiled,line,tf):		
	return assembly_ldio(listfiled,line,tf,opcodes.OPCODE_CODE_LDIO,opcodes.OPCODE_SIZE_16)
	
def ldio32(listfiled,line,tf):
	return assembly_ldio(listfiled,line,tf,opcodes.OPCODE_CODE_LDIO,opcodes.OPCODE_SIZE_32)	
	
def stio8(listfiled,line,tf):
	return assembly_ldio(listfiled,line,tf,opcodes.OPCODE_CODE_STIO,opcodes.OPCODE_SIZE_8)
	
def stio16(listfiled,line,tf):	
	return assembly_ldio(listfiled,line,tf,opcodes.OPCODE_CODE_STIO,opcodes.OPCODE_SIZE_16)
	
def stio32(listfiled,line,tf):
	return assembly_ldio(listfiled,line,tf,opcodes.OPCODE_CODE_STIO,opcodes.OPCODE_SIZE_32)
	
#################################################
#   mov,shift,extract,insert
################################################
	
def mov(listfiled,line,tf):
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : MOV - wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : MOV dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] == -1:
		writeToLst (listfiled,"ERROR : MOV dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.movOpcode['opcode'][0]:opcodes.movOpcode['opcode'][1]] = opcodes.OPCODE_CODE_MOVEIMM
	codeing[opcodes.movOpcode['destination_register'][0]:opcodes.movOpcode['destination_register'][1]] = tp[1] # dest
	tp = handle_label(line[1],tf,DATA_SEGMENT)
	if not tp[0]:
		writeToLst (listfiled,"ERROR : MOV label : '%s' not in data segment, in file %s line %d" % (line[1][2:],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] != -1:
		codeing[opcodes.movOpcode['immediate_value'][0]:opcodes.movOpcode['immediate_value'][1]] = tp[1] # immediate value	
	else: 
		tp = handle_immediate(line[1])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : MOV immediate value error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		codeing[opcodes.movOpcode['immediate_value'][0]:opcodes.movOpcode['immediate_value'][1]] = tp[1] # immediate value
	if len(line) > 2:
		if line[2] == '<<16':
			codeing[opcodes.movOpcode['high_or_low'][0]:opcodes.movOpcode['high_or_low'][1]]  = 1
		elif line[2] == 'clear':
			codeing[opcodes.movOpcode['clear'][0]:opcodes.movOpcode['clear'][1]]  = 1
		else :
			writeToLst (listfiled,"ERROR : MOV option error : '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		if len(line) > 3:
			if line[3] == 'clear':
				codeing[opcodes.movOpcode['clear'][0]:opcodes.movOpcode['clear'][1]]  = 1
			else :
				writeToLst (listfiled,"ERROR : MOV option error : '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
	return (True,codeing)
	
def shift(listfiled,line,tf):
	
	codeingdef = BitString('0x00000000')
	codeing = codeingdef	
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : SHIFT wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : SHIFT dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.shiftOpcode['opcode'][0]:opcodes.shiftOpcode['opcode'][1]] = opcodes.OPCODE_CODE_SHIFT
	codeing[opcodes.shiftOpcode['destination_register'][0]:opcodes.shiftOpcode['destination_register'][1]] = tp[1] # dest	
	if line[1] == 'asr':
		codeing[opcodes.shiftOpcode['mode'][0]:opcodes.shiftOpcode['mode'][1]] = opcodes.OPCODE_SHIFT_MODE_ASR
	elif line[1] == 'asl':
		codeing[opcodes.shiftOpcode['mode'][0]:opcodes.shiftOpcode['mode'][1]] = opcodes.OPCODE_SHIFT_MODE_ASL
	elif line[1] == 'rsr':
		codeing[opcodes.shiftOpcode['mode'][0]:opcodes.shiftOpcode['mode'][1]] = opcodes.OPCODE_SHIFT_MODE_RSR
	elif line[1] == 'rsr16':
		codeing[opcodes.shiftOpcode['mode'][0]:opcodes.shiftOpcode['mode'][1]] = opcodes.OPCODE_SHIFT_MODE_RSR16
	else:
		writeToLst (listfiled,"ERROR : SHIFT mode error : '%s', in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[2])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : SHIFT srce_reg error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.shiftOpcode['source_a'][0]:opcodes.shiftOpcode['source_a'][1]] = tp[1]
	tp = handle_register(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : SHIFT address error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	elif tp[1] != -1:
		codeing[opcodes.shiftOpcode['source_b_or_immediate'][0]:opcodes.shiftOpcode['source_b_or_immediate'][1]] = tp[1] 
	else:
		tp = handle_immediate(line[3])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : SHIFT immediate value error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		else:
			if tp[1] > 31:
				writeToLst (listfiled,"ERROR : SHIFT immediate value  overflow - %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			codeing[opcodes.shiftOpcode['immediate_or_register'][0]:opcodes.shiftOpcode['immediate_or_register'][1]] = 1 # immediate 
			codeing[opcodes.shiftOpcode['source_b_or_immediate'][0]:opcodes.shiftOpcode['source_b_or_immediate'][1]] = tp[1] # immediate value
																															 
 	return (True,codeing)		

def assembly_extract(listfiled,line,tf,opcode):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT dest_reg error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.insertOpcode['opcode'][0]:opcodes.insertOpcode['opcode'][1]] = opcode
	codeing[opcodes.insertOpcode['destination_register'][0]:opcodes.insertOpcode['destination_register'][1]] = tp[1] # dest	
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT srce_reg error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.insertOpcode['source_a'][0]:opcodes.insertOpcode['source_a'][1]] = tp[1]
	tp = handle_immediate(line[2])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT offset value error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] > 32 or tp[1] < 0:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT offset value  overflow - %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else: 
		valueB = tp[1]
		codeing[opcodes.insertOpcode['offset'][0]:opcodes.insertOpcode['offset'][1]] = tp[1] # immediate value
	tp = handle_immediate(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT width value error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] > 32 or tp[1] < 0:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT width value  overflow - %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	else: 
		valueA = tp[1]
		codeing[opcodes.insertOpcode['width'][0]:opcodes.insertOpcode['width'][1]] = tp[1] # immediate value
	if valueA + valueB  > 32:
		writeToLst (listfiled,"ERROR : EXTRACT/INSERT overflow in opernands 3 and 4, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
 	return (True,codeing)
	
def extract(listfiled,line,tf):	
	return assembly_extract(listfiled,line,tf,opcodes.OPCODE_CODE_EXTRACT)
			
def insert(listfiled,line,tf):	
	return assembly_extract(listfiled,line,tf,opcodes.OPCODE_CODE_INSERT)
	
#################################################
#              dma
################################################
	
def ctxswap(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	codeing[opcodes.ctxswapOpcode['opcode'][0]:opcodes.ctxswapOpcode['opcode'][1]] = opcodes.OPCODE_CODE_CSSVR
	codeing[opcodes.ctxswapOpcode['save'][0]:opcodes.ctxswapOpcode['save'][1]] = 1
	if len(line) > 0:
		if line[0] == 'dont_save':
			codeing[opcodes.ctxswapOpcode['save'][0]:opcodes.ctxswapOpcode['save'][1]] = 0
		elif line[0] == 'async_en':
			codeing[opcodes.ctxswapOpcode['async_en'][0]:opcodes.ctxswapOpcode['async_en'][1]] = 1
		else:
			tp = handle_label(line[0],tf,CODE_SEGMENT)
			if not tp[0]:
				writeToLst (listfiled,"ERROR : CTX_SWAP label : %s not in code segment, in file %s line %d" % (line[1][1:],tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if tp[1] != -1:
				codeing[opcodes.ctxswapOpcode['update_r16'][0]:opcodes.ctxswapOpcode['update_r16'][1]] = 1
				codeing[opcodes.ctxswapOpcode['immediate_value'][0]:opcodes.ctxswapOpcode['immediate_value'][1]] = tp[1] # immediate value
			else:
				writeToLst (listfiled,"ERROR : ctx_swap error - label expected, in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if len(line) > 1:
				if line[1] == 'async_en':
					codeing[opcodes.ctxswapOpcode['async_en'][0]:opcodes.ctxswapOpcode['async_en'][1]] = 1
				else:
					writeToLst (listfiled,"ERROR : ctx_swap option error '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
	return (True,codeing)		
	
def assembly_dma(listfiled,line,tf,opcode):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 3:
		writeToLst (listfiled,"ERROR : DMA wrong number of arguments, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.dmaOpcode['opcode'][0]:opcodes.dmaOpcode['opcode'][1]] = opcode
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : DMA source a register error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.dmaOpcode['source_a'][0]:opcodes.dmaOpcode['source_a'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : DMA source c register error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.dmaOpcode['source_c'][0]:opcodes.dmaOpcode['source_c'][1]] = tp[1]
	tp = handle_register(line[2])
	if not tp[0] :
		writeToLst (listfiled,"ERROR : DMA source b register error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] != -1:
		codeing[opcodes.dmaOpcode['source_b_or_immediate'][0]:opcodes.dmaOpcode['source_b_or_immediate'][1]] = tp[1]
	else:
		tp = handle_immediate(line[2])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : DMA source b register error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		else:
			codeing[opcodes.dmaOpcode['immediate_or_register'][0]:opcodes.dmaOpcode['immediate_or_register'][1]] = 1
			codeing[opcodes.dmaOpcode['source_b_or_immediate'][0]:opcodes.dmaOpcode['source_b_or_immediate'][1]] = tp[1]
	if len(line) > 3:
		options = line[3:]
		invoke = 0
		addr_calc = 0
		update = 0
		mask = 0
		sram = 0
		common = 0
		ctx_swap = 0
		async_en = 0
		if 'invoke' in options:
			invoke = options.count('invoke')
			codeing[opcodes.dmaOpcode['invoke'][0]:opcodes.dmaOpcode['invoke'][1]] = 1
		if 'addr_calc' in options:
			addr_calc = options.count('add_calc')
			codeing[opcodes.dmaOpcode['addr_calc'][0]:opcodes.dmaOpcode['addr_calc'][1]] = 1
		if 'mask' in options:
			mask = options.count('mask')
			codeing[opcodes.dmaOpcode['mask'][0]:opcodes.dmaOpcode['mask'][1]] = 1
		if 'update' in options:
			update = options.count('update')
			codeing[opcodes.dmaOpcode['update_r16'][0]:opcodes.dmaOpcode['update_r16'][1]] = 1
		if 'ctx_swap' in options:
			ctx_swap = options.count('ctx_swap')
			codeing[opcodes.dmaOpcode['context_swap'][0]:opcodes.dmaOpcode['context_swap'][1]] = 1
		if 'async_en' in options:
			async_en = options.count('async_en')
			codeing[opcodes.dmaOpcode['async_enable'][0]:opcodes.dmaOpcode['async_enable'][1]] = 1
		if 'common' in options:
			common = options.count('common')
			codeing[opcodes.dmaOpcode['common_or_private'][0]:opcodes.dmaOpcode['common_or_private'][1]] = 1
		if 'sram' in options:
			sram = options.count('sram')
			codeing[opcodes.dmaOpcode['mem'][0]:opcodes.dmaOpcode['mem'][1]] = 1
		if invoke > 1 or async_en > 1 or mask > 1 or addr_calc > 1 or \
			ctx_swap > 1 or update > 1 or common > 1 or sram > 1 :
			writeToLst (listfiled,"ERROR : DMA option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if invoke < 1 and async_en < 1 and mask < 1 and addr_calc < 1 and \
				ctx_swap < 1 and update < 1 and common < 1 and sram < 1 :
			writeToLst (listfiled,"ERROR : DMA unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		if mask == 1 and ctx_swap == 1 and opcode == opcodes.OPCODE_CODE_DMAWR >> 2:
			writeToLst (listfiled,"ERROR : DMA_WR 'mask' and 'ctx_swap' cannot be used together, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)

def dmard(listfiled,line,tf):
	return assembly_dma(listfiled,line,tf,opcodes.OPCODE_CODE_DMARD >> 2)
	
def dmawr(listfiled,line,tf):
	return assembly_dma(listfiled,line,tf,opcodes.OPCODE_CODE_DMAWR >> 2)
	
def hashf(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 6:
		writeToLst (listfiled,"ERROR : HASH wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.hashOpcode['opcode'][0]:opcodes.hashOpcode['opcode'][1]] = opcodes.OPCODE_CODE_HASH
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : HASH key 1 error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.hashOpcode['source_c'][0]:opcodes.hashOpcode['source_c'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : HASH key 2 error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.hashOpcode['source_a'][0]:opcodes.hashOpcode['source_a'][1]] = tp[1]
	if line[2] == '48bit':
		codeing[opcodes.hashOpcode['ks'][0]:opcodes.hashOpcode['ks'][1]] = 0
	elif line[2] == '60bit':
		codeing[opcodes.hashOpcode['ks'][0]:opcodes.hashOpcode['ks'][1]] = 1
	else:
		writeToLst (listfiled,"ERROR : HASH key size error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if line[3] == 'src':
		codeing[opcodes.hashOpcode['sa'][0]:opcodes.hashOpcode['sa'][1]] = 1
		if line[2] == '60bit':
			writeToLst (listfiled,"ERROR : HASH src can't be used together with 60bit, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	elif line[3] == 'dst':
		codeing[opcodes.hashOpcode['sa'][0]:opcodes.hashOpcode['sa'][1]] = 0
	tp = handle_immediate(line[4])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : HASH result slot error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.hashOpcode['res_slot'][0]:opcodes.hashOpcode['res_slot'][1]] = tp[1]
	tp = handle_immediate(line[5])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : HASH table error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.hashOpcode['table'][0]:opcodes.hashOpcode['table'][1]] = tp[1]
	if len(line) > 6:
		options = line[6:]
		invoke = 0
		refresh = 0
		update = 0
		ctx_swap = 0
		if 'invoke' in options:
			invoke = options.count('invoke')
			codeing[opcodes.hashOpcode['invoke'][0]:opcodes.hashOpcode['invoke'][1]] = 1
		if 'refresh' in options:
			refresh = options.count('refresh')
			codeing[opcodes.hashOpcode['rq'][0]:opcodes.hashOpcode['rq'][1]] = 1
		if 'ctx_swap' in options:
			ctx_swap = options.count('ctx_swap')
			codeing[opcodes.hashOpcode['cs'][0]:opcodes.hashOpcode['cs'][1]] = 1
		if 'update' in options:
		 	update = options.count('update')
		 	codeing[opcodes.hashOpcode['update_r16'][0]:opcodes.hashOpcode['update_r16'][1]] = 1
		if invoke > 1 or  ctx_swap > 1 or update > 1 or refresh > 1 :
			writeToLst (listfiled,"ERROR : HASH option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if invoke < 1 and  ctx_swap < 1 and update < 1 and refresh < 1 :
			writeToLst (listfiled,"ERROR : HASH unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)

	return (True,codeing)		
	
def assembly_crc(listfiled,line,tf,size):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 3:
		writeToLst (listfiled,"ERROR : CRC wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.crcOpcode['opcode'][0]:opcodes.crcOpcode['opcode'][1]] = opcodes.OPCODE_CODE_CRCCALC
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CRC key 1 error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.crcOpcode['source_a'][0]:opcodes.crcOpcode['source_a'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] :
		writeToLst (listfiled,"ERROR : CRC key 2 error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	elif tp[1] != -1:
		codeing[opcodes.crcOpcode['source_b_or_immediate'][0]:opcodes.crcOpcode['source_b_or_immediate'][1]] = tp[1]
	else:
		tp = handle_immediate(line[1])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : CRC key 2 error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		else:
			codeing[opcodes.crcOpcode['immediate_or_register'][0]:opcodes.crcOpcode['immediate_or_register'][1]] = 1
			codeing[opcodes.crcOpcode['source_b_or_immediate'][0]:opcodes.crcOpcode['source_b_or_immediate'][1]] = tp[1]
	tp = handle_register(line[2])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CRC register error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.crcOpcode['source_c'][0]:opcodes.crcOpcode['source_c'][1]] = tp[1]
	if size == ASSEMBLY_CRC_10:
		codeing[opcodes.crcOpcode['type'][0]:opcodes.crcOpcode['type'][1]] = 1
	else:
		codeing[opcodes.crcOpcode['type'][0]:opcodes.crcOpcode['type'][1]] = 0
		if len(line) > 3:
			options = line[3:]
			ether = 0
			last = 0
			common = 0
			if 'ether' in options:
				ether = options.count('ether')
				codeing[opcodes.crcOpcode['eth'][0]:opcodes.crcOpcode['eth'][1]] = 1
			if 'last' in options:
				last = options.count('last')
				codeing[opcodes.crcOpcode['last'][0]:opcodes.crcOpcode['last'][1]] = 1
			if 'common' in options:
				common = options.count('common')
				codeing[opcodes.crcOpcode['common_or_private'][0]:opcodes.crcOpcode['common_or_private'][1]] = 1
			if ether > 1 or  last > 1 or common > 1 :
				writeToLst (listfiled,"ERROR : CRC option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)	
			if common < 1 and  ether < 1 and last < 1 :
				writeToLst (listfiled,"ERROR : CRC unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)

	return (True,codeing)

def crccalc32(listfiled,line,tf):
	return assembly_crc(listfiled,line,tf,ASSEMBLY_CRC_32)		
	
def crccalc10(listfiled,line,tf):
	return assembly_crc(listfiled,line,tf,ASSEMBLY_CRC_10)		
#################################################
#              ffi
################################################
def assembly_ffi (listfiled,line,tf,size):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	codeing[opcodes.ffiOpcode['opcode'][0]:opcodes.ffiOpcode['opcode'][1]] = opcodes.OPCODE_CODE_FFI
	codeing[opcodes.ffiOpcode['size'][0]:opcodes.ffiOpcode['size'][1]] = size
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : FFI - wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : FFI register error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.ffiOpcode['destination_register'][0]:opcodes.ffiOpcode['destination_register'][1]] = tp[1] # dest
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : FFI register error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.ffiOpcode['source_a'][0]:opcodes.ffiOpcode['source_a'][1]] = tp[1] # dest
	if size == opcodes.OPCODE_FFI8 and len(line) < 3:	
		writeToLst (listfiled,"ERROR : FFI - wrong number of parameters, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	tp = handle_register(line[2])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : FFI register error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	elif tp[1] != -1:
		codeing[opcodes.ffiOpcode['source_b_or_immediate'][0]:opcodes.ffiOpcode['source_b_or_immediate'][1]] = tp[1]
	else:
		tp = handle_immediate(line[2])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : FFI immediate value error(1) : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeing)
		if tp[1] > 0x1f:
			writeToLst (listfiled,"ERROR : FFI immediate value  error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeing)
		codeing[opcodes.ffiOpcode['immediate_or_register'][0]:opcodes.ffiOpcode['immediate_or_register'][1]] = 1 # immediate
		codeing[opcodes.ffiOpcode['source_b_or_immediate'][0]:opcodes.ffiOpcode['source_b_or_immediate'][1]] = tp[1] # immediate
	return (True,codeing)

def ffi8(listfiled,line,tf):
	return assembly_ffi (listfiled,line,tf,opcodes.OPCODE_FFI8)
	
def ffi16(listfiled,line,tf):
	return assembly_ffi (listfiled,line,tf,opcodes.OPCODE_FFI16)
	
def dmaalu(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : DMA_LKP wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.dmaaluOpcode['opcode'][0]:opcodes.dmaaluOpcode['opcode'][1]] = opcodes.OPCODE_CODE_DMALU >> 2
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : DMA_LKP register  error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.dmaaluOpcode['source_a'][0]:opcodes.dmaaluOpcode['source_a'][1]] = tp[1] 
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : DMA_LKP register  error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.dmaaluOpcode['source_c'][0]:opcodes.dmaaluOpcode['source_c'][1]] = tp[1] 
	tp = handle_register(line[2])
	if not tp[0] :
		writeToLst (listfiled,"ERROR : DMA_LKP register  error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	if tp[1] == -1:
		tp = handle_immediate(line[2])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : DMA_LKP value error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeing)
		codeing[opcodes.dmaaluOpcode['immediate_or_register'][0]:opcodes.dmaaluOpcode['immediate_or_register'][1]] = 1 
		codeing[opcodes.dmaaluOpcode['source_b_or_immediate'][0]:opcodes.dmaaluOpcode['source_b_or_immediate'][1]] = tp[1] 
	else:
		codeing[opcodes.dmaaluOpcode['source_b_or_immediate'][0]:opcodes.dmaaluOpcode['source_b_or_immediate'][1]] = tp[1] 
	tp = handle_immediate(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : DMA_LKP value error : %s, in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.dmaaluOpcode['res_slot'][0]:opcodes.dmaaluOpcode['res_slot'][1]] = tp[1]
	if len(line) > 4:
		options = line[4:]
		invoke = 0
		update = 0
		mask = 0
		sram = 0
		common = 0
		ctx_swap = 0
		async_en = 0
		if 'invoke' in options:
			invoke = options.count('invoke')
			codeing[opcodes.dmaaluOpcode['invoke'][0]:opcodes.dmaaluOpcode['invoke'][1]] = 1
		if 'update' in options:
			addr_calc = options.count('update')
			codeing[opcodes.dmaaluOpcode['update_r16'][0]:opcodes.dmaaluOpcode['update_r16'][1]] = 1
		if 'mask' in options:
			mask = options.count('mask')
			codeing[opcodes.dmaaluOpcode['mask'][0]:opcodes.dmaaluOpcode['mask'][1]] = 1
		if 'ctx_swap' in options:
			ctx_swap = options.count('ctx_swap')
			codeing[opcodes.dmaaluOpcode['context_swap'][0]:opcodes.dmaaluOpcode['context_swap'][1]] = 1
		if 'async_en' in options:
			async_en = options.count('async_en')
			codeing[opcodes.dmaaluOpcode['async_enable'][0]:opcodes.dmaaluOpcode['async_enable'][1]] = 1
		if 'common' in options:
			common = options.count('common')
			codeing[opcodes.dmaaluOpcode['common_or_private'][0]:opcodes.dmaOpcode['common_or_private'][1]] = 1
		if 'sram' in options:
			sram = options.count('sram')
			codeing[opcodes.dmaaluOpcode['mem'][0]:opcodes.dmaaluOpcode['mem'][1]] = 1
		if invoke > 1 or async_en > 1 or mask > 1 or update > 1 or \
			ctx_swap > 1 or common > 1 or sram > 1 :
			writeToLst (listfiled,"ERROR : DMA LKP option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if invoke < 1 and async_en < 1 and mask < 1 and update < 1 and \
				ctx_swap < 1 and common < 1 and sram < 1 :
			writeToLst (listfiled,"ERROR : DMA LKP unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)		
	
def camlkp(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : CAM_LKP wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.camOpcode['opcode'][0]:opcodes.camOpcode['opcode'][1]] = opcodes.OPCODE_CODE_CRCCALC
	codeing[opcodes.camOpcode['type'][0]:opcodes.camOpcode['type'][1]] = 1
	codeing[opcodes.camOpcode['immediate_or_register'][0]:opcodes.camOpcode['immediate_or_register'][1]] = 1
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CAM_LKP register error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.camOpcode['source_a'][0]:opcodes.camOpcode['source_a'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CAM_LKP register error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.camOpcode['source_c'][0]:opcodes.camOpcode['source_c'][1]] = tp[1]	
	if line[2] == '16bit':
		codeing[opcodes.camOpcode['key_size'][0]:opcodes.camOpcode['key_size'][1]] = 0
	elif line[2] == '32bit':
		codeing[opcodes.camOpcode['key_size'][0]:opcodes.camOpcode['key_size'][1]] = 1
	elif line[2] == '64bit':
		codeing[opcodes.camOpcode['key_size'][0]:opcodes.camOpcode['key_size'][1]] = 2
		if tp[1] & 0x01 == 0x01:
			writeToLst (listfiled,"ERROR : CAM_LKP key register should be even, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
	elif line[2] == '128bit':
		codeing[opcodes.camOpcode['key_size'][0]:opcodes.camOpcode['key_size'][1]] = 3
		codeing[opcodes.camOpcode['use_128'][0]:opcodes.camOpcode['use_128'][1]] = 1
		if tp[1] & 0x03 != 0:
			writeToLst (listfiled,"ERROR : CAM_LKP key register should be modulo 4, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
	else:
		writeToLst (listfiled,"ERROR : CAM_LKP option error : '%s', in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	tp = handle_immediate(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : CAM_LKP immediate value expected '%s', in file %s line %d" % (line[3],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.camOpcode['res_slot'][0]:opcodes.camOpcode['res_slot'][1]] = tp[1]
	if len(line) > 4:
		invoke = 0
		mask = 0
		common = 0
		options = line[4:]
		if 'invoke' in options:
			invoke = options.count('invoke')
			codeing[opcodes.camOpcode['invoke'][0]:opcodes.camOpcode['invoke'][1]] = 1	
		if 'mask' in options:
			mask = options.count('mask')
			codeing[opcodes.camOpcode['mask'][0]:opcodes.camOpcode['mask'][1]] = 1		
		if 'common' in options:
			common = options.count('common')
			codeing[opcodes.camOpcode['common_or_private'][0]:opcodes.camOpcode['common_or_private'][1]] = 1
		if invoke > 1 or mask > 1 or common > 1 :
			writeToLst (listfiled,"ERROR : CAM LKP option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if invoke < 1 and mask < 1 and common < 1 :
			writeToLst (listfiled,"ERROR : CAM LKP unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
		if mask == 1 and line[2] == '64bit':
			writeToLst (listfiled,"ERROR : CAM LKP mask can't be used with 64 bit key, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)		
	
def bbtx(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 3:
		writeToLst (listfiled,"ERROR : BBTX wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.bbtxOpcode['opcode'][0]:opcodes.bbtxOpcode['opcode'][1]] = opcodes.OPCODE_CODE_BBTX
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : BBTX register error : %s, in file %s line %d" % (line[0],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.bbtxOpcode['source_c'][0]:opcodes.bbtxOpcode['source_c'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : BBTX register error : %s, in file %s line %d" % (line[1],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.bbtxOpcode['source_a'][0]:opcodes.bbtxOpcode['source_a'][1]] = tp[1]
	tp = handle_register(line[2])
	if not tp[0] :
		writeToLst (listfiled,"ERROR : BBTX register error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
		return (False,codeing)
	elif tp[1] != -1:
		codeing[opcodes.bbtxOpcode['source_b_or_immediate'][0]:opcodes.bbtxOpcode['source_b_or_immediate'][1]] = tp[1]
	else:
		tp = handle_immediate(line[2])
		if not tp[0] :
			writeToLst (listfiled,"ERROR : BBTX value error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeing)
		if tp[1] > 0xff:
			writeToLst (listfiled,"ERROR : BBTX value error : %s, in file %s line %d" % (line[2],tf[0]+tf[1],tf[2]))
			return (False,codeing)
		else:
			codeing[opcodes.bbtxOpcode['immediate_or_register'][0]:opcodes.bbtxOpcode['immediate_or_register'][1]] = 1 
			codeing[opcodes.bbtxOpcode['source_b_or_immediate'][0]:opcodes.bbtxOpcode['source_b_or_immediate'][1]] = tp[1]
	if len(line) > 3:		
		options = line[3:]
		last = 0
		incr = 0
		common = 0
		wait = 0
		if 'last' in options:
			last = options.count('last')
			codeing[opcodes.bbtxOpcode['last'][0]:opcodes.bbtxOpcode['last'][1]] = 1	
		if 'incremental' in options:
			incr = options.count('incremental')
			codeing[opcodes.bbtxOpcode['inc'][0]:opcodes.bbtxOpcode['inc'][1]] = 1
		if 'common' in options:
			common = options.count('common')
			codeing[opcodes.bbtxOpcode['common_or_private'][0]:opcodes.bbtxOpcode['common_or_private'][1]] = 1
		if 'wait' in options:
			wait = options.count('wait')
			codeing[opcodes.bbtxOpcode['wait'][0]:opcodes.bbtxOpcode['wait'][1]] = 1
		if last > 1 or incr > 1 or common > 1 or wait > 1:
			writeToLst (listfiled,"ERROR : BBTX option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if last < 1 and incr < 1 and common < 1 and wait < 1:
			writeToLst (listfiled,"ERROR : BBTX unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
	return (True,codeing)		
	
def bbmsg(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : BBTX wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.bbmsgOpcode['opcode'][0]:opcodes.bbmsgOpcode['opcode'][1]] = opcodes.OPCODE_CODE_BBMSG
	codeing[opcodes.bbmsgOpcode['source_a'][0]:opcodes.bbmsgOpcode['source_a'][1]] = 31
	tp = handle_immediate(line[0])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : BBMSG immediate value error, in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	if tp[1] > 3:
		writeToLst (listfiled,"ERROR : BBMSG immediate value overflow , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	srcb = 0
	codeing[opcodes.bbmsgOpcode['type'][0]:opcodes.bbmsgOpcode['type'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : BBMSG register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeingdef)
	codeing[opcodes.bbmsgOpcode['source_a'][0]:opcodes.bbmsgOpcode['source_a'][1]] = tp[1]
	if len(line) > 2:
		if line[2] == '32bit':
			codeing[opcodes.bbmsgOpcode['size'][0]:opcodes.bbmsgOpcode['size'][1]] = 0
		elif line[2] == '64bit':
			codeing[opcodes.bbmsgOpcode['size'][0]:opcodes.bbmsgOpcode['size'][1]] = 1
		else:
			tp = handle_register(line[2])
			if not tp[0]:
				writeToLst (listfiled,"ERROR : BBMSG register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			elif tp[1] != -1:
				srcb = tp[1]
				codeing[opcodes.bbmsgOpcode['source_b_or_immediate'][0]:opcodes.bbmsgOpcode['source_b_or_immediate'][1]] = tp[1]
			else:
				tp = handle_immediate(line[2])
				if not tp[0]:
					writeToLst (listfiled,"ERROR : BBMSG immediate value error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
					return (False,codeingdef)
				codeing[opcodes.bbmsgOpcode['source_b_or_immediate'][0]:opcodes.bbmsgOpcode['source_b_or_immediate'][1]] = tp[1]
				codeing[opcodes.bbmsgOpcode['immediate_or_register'][0]:opcodes.bbmsgOpcode['immediate_or_register'][1]] = 1
				srcb = tp[1]
		if len(line) > 3:
			if line[3] == '32bit':
				codeing[opcodes.bbmsgOpcode['size'][0]:opcodes.bbmsgOpcode['size'][1]] = 0
			elif line[3] == '64bit':
				codeing[opcodes.bbmsgOpcode['size'][0]:opcodes.bbmsgOpcode['size'][1]] = 1
			else:
				writeToLst (listfiled,"ERROR : BBMSG option error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
			if srcb & 1 == 1 and line[3] == '64bit':
				writeToLst (listfiled,"ERROR : BBMSG message register should be even, in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
		if len(line) > 4:
			if line[4] == 'wait':
				codeing[opcodes.bbmsgOpcode['wait'][0]:opcodes.bbmsgOpcode['wait'][1]] = 1
			else:
				writeToLst (listfiled,"ERROR : BBMSG option error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
				return (False,codeingdef)
	return (True,codeing)

def chksm(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : CHKSM wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.icheckOpcode['opcode'][0]:opcodes.icheckOpcode['opcode'][1]] = opcodes.OPCODE_CODE_ICHECK
	codeing[opcodes.icheckOpcode['reverse'][0]:opcodes.icheckOpcode['reverse'][1]] = 1
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CHKSM register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.icheckOpcode['destination_register'][0]:opcodes.icheckOpcode['destination_register'][1]] = tp[1]
	tp = handle_register(line[2])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CHKSM register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.icheckOpcode['source_b'][0]:opcodes.icheckOpcode['source_b'][1]] = tp[1]
	tp = handle_register(line[3])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CHKSM register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.icheckOpcode['source_a'][0]:opcodes.icheckOpcode['source_a'][1]] = tp[1]
	if len(line) > 4:
		options = line[4:]
		high = 0
		last = 0
		if 'high' in options:
			high += options.count('high')
			codeing[opcodes.icheckOpcode['high_or_low'][0]:opcodes.icheckOpcode['high_or_low'][1]] = 1
			codeing[opcodes.icheckOpcode['byte_shift'][0]:opcodes.icheckOpcode['byte_shift'][1]] = 6
		elif 'low' in options:
			high += options.count('low')
			codeing[opcodes.icheckOpcode['high_or_low'][0]:opcodes.icheckOpcode['high_or_low'][1]] = 0
			codeing[opcodes.icheckOpcode['byte_shift'][0]:opcodes.icheckOpcode['byte_shift'][1]] = 0
		elif 'last' in options:
			last += options.count('last')
			codeing[opcodes.icheckOpcode['last'][0]:opcodes.icheckOpcode['last'][1]] = 1
		else:
			writeToLst (listfiled,"ERROR : CHKSM option error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
		if last > 1 or high > 1:
			writeToLst (listfiled,"ERROR : CHKSM option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if last < 1 and high < 1 :
			writeToLst (listfiled,"ERROR : CHKSM unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
	return (True,codeing)		
	
def assembly_crypt(listfiled,line,tf,hash):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 2:
		writeToLst (listfiled,"ERROR : CRYPT/AUTH wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.cryptOpcode['opcode'][0]:opcodes.cryptOpcode['opcode'][1]] = opcodes.OPCODE_CODE_CRYPT
	codeing[opcodes.cryptOpcode['hash'][0]:opcodes.cryptOpcode['hash'][1]] = hash
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : CRYPT/AUTH register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.cryptOpcode['source_a'][0]:opcodes.cryptOpcode['source_a'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : CRYPT/AUTH register error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	if tp[1] != -1:
		codeing[opcodes.cryptOpcode['source_b'][0]:opcodes.cryptOpcode['source_b'][1]] = tp[1]
	else:
		tp = handle_immediate(line[1])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : CRYPT/AUTH value error , in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
		codeing[opcodes.cryptOpcode['source_b'][0]:opcodes.cryptOpcode['source_b'][1]] = tp[1]
		codeing[opcodes.cryptOpcode['immediate_or_register'][0]:opcodes.cryptOpcode['immediate_or_register'][1]] = 1
	if len(line) > 2:
		if line[2] == 'first':
			codeing[opcodes.cryptOpcode['first'][0]:opcodes.cryptOpcode['first'][1]] = 1
			codeing[opcodes.cryptOpcode['last'][0]:opcodes.cryptOpcode['last'][1]] = 0
		elif line[2] == 'last':
			codeing[opcodes.cryptOpcode['first'][0]:opcodes.cryptOpcode['first'][1]] = 0
			codeing[opcodes.cryptOpcode['last'][0]:opcodes.cryptOpcode['last'][1]] = 1
		elif line[2] == 'middle':
			codeing[opcodes.cryptOpcode['first'][0]:opcodes.cryptOpcode['first'][1]] = 0
			codeing[opcodes.cryptOpcode['last'][0]:opcodes.cryptOpcode['last'][1]] = 0
		elif line[2] == 'single':
			codeing[opcodes.cryptOpcode['first'][0]:opcodes.cryptOpcode['first'][1]] = 1
			codeing[opcodes.cryptOpcode['last'][0]:opcodes.cryptOpcode['last'][1]] = 1
		elif line[2] == 'invoke':
			codeing[opcodes.cryptOpcode['invoke'][0]:opcodes.cryptOpcode['invoke'][1]] = 1
	return (True,codeing)		
	
	
def crypt(listfiled,line,tf):
	return assembly_crypt(listfiled,line,tf,False)
	
def auth(listfiled,line,tf):
	return assembly_crypt(listfiled,line,tf,True)
	
def counter(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	if len(line) < 4:
		writeToLst (listfiled,"ERROR : COUNTER wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.counterOpcode['opcode'][0]:opcodes.counterOpcode['opcode'][1]] = opcodes.OPCODE_CODE_CNTUP
	codeing[opcodes.counterOpcode['mode'][0]:opcodes.counterOpcode['mode'][1]] = 1
	if line[0] == 'increment':
		codeing[opcodes.counterOpcode['operation'][0]:opcodes.counterOpcode['operation'][1]] = 0
	elif line[0] == 'decrement':
		codeing[opcodes.counterOpcode['operation'][0]:opcodes.counterOpcode['operation'][1]] = 1
	else:
		writeToLst (listfiled,"ERROR : COUNTER wrong parameter , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	tp = handle_register(line[1])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : COUNTER wrong register , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	elif tp[1] != -1:
		codeing[opcodes.counterOpcode['source_a'][0]:opcodes.counterOpcode['source_a'][1]] = tp[1]
	else:
		tp = handle_immediate(line[1])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : COUNTER wrong value , in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
		else:
			codeing[opcodes.counterOpcode['source_a'][0]:opcodes.counterOpcode['source_a'][1]] = tp[1]
			codeing[opcodes.counterOpcode['imm_or_reg_a'][0]:opcodes.counterOpcode['imm_or_reg_a'][1]] = 1
	tp = handle_register(line[2])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : COUNTER wrong register , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.counterOpcode['source_c'][0]:opcodes.counterOpcode['source_c'][1]] = tp[1]
	tp = handle_register(line[3])
	if not tp[0]:
		writeToLst (listfiled,"ERROR : COUNTER wrong register , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	elif tp[1] != -1:
		codeing[opcodes.counterOpcode['source_b'][0]:opcodes.counterOpcode['source_b'][1]] = tp[1]
	else:
		tp = handle_immediate(line[3])
		if not tp[0]:
			writeToLst (listfiled,"ERROR : COUNTER wrong value , in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
		else:
			codeing[opcodes.counterOpcode['source_b'][0]:opcodes.counterOpcode['source_b'][1]] = tp[1]
			codeing[opcodes.counterOpcode['imm_or_reg_b'][0]:opcodes.counterOpcode['imm_or_reg_b'][1]] = 1
	if len(line) > 4:
		options = line[4:]
		size = 0
		mode = 0
		if '2bytes' in options:
			size += options.count('2bytes')
			codeing[opcodes.counterOpcode['size'][0]:opcodes.counterOpcode['size'][1]] = 0
		elif '4bytes' in options:
			size += options.count('4bytes')
			codeing[opcodes.counterOpcode['size'][0]:opcodes.counterOpcode['size'][1]] = 1
		elif 'freeze' in options:
			mode += options.count('freeze')
			codeing[opcodes.counterOpcode['mode'][0]:opcodes.counterOpcode['mode'][1]] = 0
		elif 'wrap' in options:
			mode += options.count('wrap')
			codeing[opcodes.counterOpcode['mode'][0]:opcodes.counterOpcode['mode'][1]] = 1
		else:
			writeToLst (listfiled,"ERROR : COUNTER wrong option , in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
		if size > 1 or mode > 1 :
			writeToLst (listfiled,"ERROR : COUNTER option used more than once, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)	
		if size < 1 and mode < 1:
			writeToLst (listfiled,"ERROR : COUNTER unknown option, in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeingdef)
	return (True,codeing)		
			
def signext(listfiled,line,tf):

	codeingdef = BitString('0x00000000')
	codeing = codeingdef
	codeing[opcodes.signextOpcode['opcode'][0]:opcodes.signextOpcode['opcode'][1]] = opcodes.OPCODE_CODE_SIGNEXT
	codeing[opcodes.signextOpcode['update_flags'][0]:opcodes.signextOpcode['update_flags'][1]] = 1
	if len(line) < 3:
		writeToLst (listfiled,"ERROR : SIGNEXT wrong number of parameters , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	tp = handle_register(line[0])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : SIGNEXT wrong register , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.signextOpcode['destination_register'][0]:opcodes.signextOpcode['destination_register'][1]] = tp[1]
	tp = handle_register(line[1])
	if not tp[0] or tp[1] == -1:
		writeToLst (listfiled,"ERROR : SIGNEXT wrong register , in file %s line %d" % (tf[0]+tf[1],tf[2]))
		return (False,codeing)
	codeing[opcodes.signextOpcode['source_a'][0]:opcodes.signextOpcode['source_a'][1]] = tp[1]
	if line[2] == '8bit':
		codeing[opcodes.signextOpcode['immediate_or_register'][0]:opcodes.signextOpcode['immediate_or_register'][1]] = 1
		codeing[opcodes.signextOpcode['source_b_or_immediate'][0]:opcodes.signextOpcode['source_b_or_immediate'][1]] = 0
	elif line[2] == '16bit':
		codeing[opcodes.signextOpcode['immediate_or_register'][0]:opcodes.signextOpcode['immediate_or_register'][1]] = 1
		codeing[opcodes.signextOpcode['source_b_or_immediate'][0]:opcodes.signextOpcode['source_b_or_immediate'][1]] = 1
	else:
		tp = handle_register(line[2])
		if not tp[0] or tp[1] == -1:
			writeToLst (listfiled,"ERROR : SIGNEXT wrong register , in file %s line %d" % (tf[0]+tf[1],tf[2]))
			return (False,codeing)
		codeing[opcodes.signextOpcode['source_b_or_immediate'][0]:opcodes.signextOpcode['source_b_or_immediate'][1]] = tp[1]
	return (True,codeing)

def nop(listfiled,line,tf):
	codeing = BitString('0x00000000')
	codeing[opcodes.nopOpcode['opcode'][0]:opcodes.nopOpcode['opcode'][1]] = opcodes.OPCODE_CODE_NOP
 	return (True,codeing)		
	

