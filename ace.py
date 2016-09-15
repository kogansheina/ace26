#!/usr/bin/env python
import os
import struct
from datetime import datetime
import opcodes

#################
# Miscellaneous
#################

ACE_NAME = "ace"
ACE_VERSION = "3.0.0"

def writeToLst(listfile,line):
	""" print current line to list file,
	 if it is an error or warning message print it to stdout also """ 
	if listfile != 0:		
		listfile.write(line)
		if not line.endswith('\n'):
			listfile.write('\n')
		if line.startswith("ERROR") or line.startswith("WARNING"):
			print line
	else:
		print line
		
def transformBinary(pos,e):
	""" receives a start position in a string,
	transform the string('0' and '1') to a binary value
	"""
	pose = pos+1
	for y in e[pos+1:]:
		if y == '0' or y == '1':
			pose += 1
		else: break
	nn = e[pos+1:pose]
	if pose != pos+1:
		val = 0
		for c in nn:
			d = eval(c)
			val = val*2 + d	
	else: val = -1
	return (val,pose)

def evaluateExpression(e):
	""" returns a string, as Python like to evaluate
	the expression is in 'ace' format
	"""
	e = e.lower()
	pos = e.find('b.') #remove binary constants
	while pos != -1:
		valt = transformBinary(pos+1,e)
		val = valt[0]
		pose = valt[1]
		if val != -1:
			e = e.replace(e[pos:pose],str(val),1)
		pos = e.find('b.',pos+1)
	#transform all other funny notations
	e = e.replace('h.','0x')
	e = e.replace('o.','o')
	e = e.replace('d.','')
	
	return e
	  
import aceCode
#list of directories to look for files - given as '-I' option
includes = []
#key id the defined symbol, value(if exists) is the value to be used instead
define_symbol = {}
registers_symbol = {}
#key is the macro name, value is a list
#first element is a list of parameters
#next elements are the code line to be placed instead the macro
macro_symbol = {}
macroname = ''
#stack for nested '#if'
ifStack = []
#state of the parser - is the key into state machine dictionary
state = 'empty'
warnings = [0,0]
correct = True

##########################
# Preprocessor directives
##########################
def messageProc(listfiled,line,com,tf):
	print "Message: %s %d: %s" %(tf[0]+tf[1],tf[2],line)
	#writeToLst (listfiled,"Message: %s %d: %s\t; %s" %(tf[0]+tf[1],tf[2],line,com))

def warningProc(listfiled,line,com,tf):
	print "Warning: %s %d: %s" %(tf[0]+tf[1],tf[2],line)
	#writeToLst (listfiled,"Warning: %s %d: %s\t; %s" %(tf[0]+tf[1],tf[2],line,com))

def errorProc(listfiled,line,com,tf):
	print "Error: %s %d: %s" %(tf[0]+tf[1],tf[2],line)
	#writeToLst (listfiled,"Error: %s %d: %s\t; %s" %(tf[0]+tf[1],tf[2],line,com))

def warnProc(listfiled,current,com,tf):
	line = current.split()
	#writeToLst(listfiled,tf[0]+tf[1]+' '+str(tf[2])+':\t'+current+'\t '+com)
	if len(line) > 1:
		if line[1].lower() == "r0_as_destination":
			if line[2].lower() == 'on':
				warnings[0] = 1
			else:
				if line[2].lower() == 'off':
					warnings[0] = 0
				else:
					writeToLst (listfiled,"ERROR : unknown warning control (on or off expected) in file %s, line %d" % (tf[0]+tf[1],tf[2]))
		else:
			if line[1].lower() == "r1_as_destination":
				if line[2].lower() == 'on':
					warnings[1] = 1
				else:
					if line[2].lower() == 'off':
						warnings[1] = 0
					else:
						writeToLst (listfiled,"ERROR : unknown warning control (on or off expected) in file %s, line %d" % (tf[0]+tf[1],tf[2]))
			else:
				writeToLst (listfiled,"ERROR : #warn in file %s, line %d" % (tf[0]+tf[1],tf[2]))
	else:
		writeToLst (listfiled,"ERROR : #warn in file %s, line %d" %(tf[0]+tf[1],tf[2]))

######################				
## REGISTER directives
#######################
def registerProc(listfiled,current,com,tf):
	"""
	Receives a list of parameters : rx symbol
	Build an entry into symbols : key is the symbol and value is the first list argument evalueted to register number 
	"""
	global registers_symbol
	line = current.split()
	if len(line) < 3:
		if len(line) < 2:
			writeToLst (listfiled,"ERROR : in register %s definition - alias name not defined at line %d in file %s" % (line[1],tf[2],tf[0]+tf[1]))
		else:
			writeToLst (listfiled,"ERROR : error in register definition at line %d, in file %s" % (tf[2],tf[0]+tf[1]))
	else:
		if line[2] in registers_symbol:
			writeToLst (listfiled,"WARNING : symbol redefinition '%s', previously defined as %s , at line %d in file %s" %(line[2],registers_symbol[line[1]],tf[2],tf[0]+tf[1]))
		if line[1].lower().startswith ('r'):
			y = eval(line[1][1:])
			if y < 0 or y > 31 :
				writeToLst (listfiled,"ERROR : register out of range '%s' at line %d, in file %s" %(line[1],tf[2],tf[0]+tf[1]))
			# add symbol : register is the key
			if line[2] in registers_symbol:
				writeToLst (listfiled,"WARNING : symbol %s redefinition, previously defined as %s , at line %d in file %s" %(line[2],registers_symbol[line[2]],tf[2],tf[0]+tf[1]))
			else:
				registers_symbol[line[2]] = line[1]
		else:
			writeToLst (listfiled,"ERROR : register name does not begin with 'r' at line %d, in file %s" % (tf[2],tf[0]+tf[1]))

def unregisterProc(listfiled,current,com,tf):
	"""
	Receives a list of parameters : rx or nothing
	Remove from symbols the register alias or for all 
	"""
	global registers_symbol
	line = current.split()
	if len(line) == 1: # remove all registers
		registers_symbol.clear()
	else:
		if line[1].lower().startswith ('r'):
			y = eval(line[1][1:])
			if y < 0 or y > 31 :
				writeToLst (listfiled,"ERROR : register out of range '%s' at line %d in file %s" %(line[1],tf[2],tf[0]+tf[1]))
			else: # remove symbol : register is the key
				if line[1].lower() in registers_symbol:
					del registers_symbol[line[1].lower()]
				else:
					writeToLst (listfiled,"WARNING : register %s  is not defined as symbol, at line %d, in file %s" % ( line[1] ,tf[2],tf[0]+tf[1]))

######################				
## DEFINE directives
#######################
def lookForDefineSymbol(alias):
	"""
	Check if alias is as value in define table
	If found returns the alias' key
	otherwise returns an empty string
	"""	
	for t in define_symbol:
		if define_symbol[t] == alias:
			return t
	return ''
																	
def defineProc(listfiled,current,com,tf):
	"""
	Receives a list of parameters : symbol value 
	Build an entry into symbols : key is the symbol  
	"""
	global define_symbol
	line = current.split()
	if len(line) > 2:
		k = lookForDefineSymbol(line[1]) 
		if k:
			writeToLst (listfiled,"WARNING : symbol %s is re-defined from %s as symbol %s, file %s line " %( line[1] , k , line[1], tf[0]+tf[1], tf[2]))
		if '(' in line[2:]:
			s = ''.join(line[2:])
			for i in define_symbol:
				if i in s:
					k = ''.join(str(define_symbol[i]))
					s = s.replace(i,k)
			s = evaluateExpression(s)			
			try:
				define_symbol[line[1]] = eval(s)
			except NameError:
				define_symbol[line[1]] = s
		else:
			s = ''
			for t in line[2:]:
				t = evaluateExpression(t)
				s += t + ' '
			define_symbol[line[1]] = s
	else:
		define_symbol[line[1]] = ''	
		
def undefProc(listfiled,current,com,tf):
	"""
	Receives a list with only one parameter
	"""
	global define_symbol
	line = current.split()
	if line[1] in define_symbol:
		del define_symbol[line[1]]	
			
def includeProc(listfiled,current,com,tf):
	""" Look for the file into the current directory,
	if not, then look into each given directory with the '-I' option
	call recursive the handle_file procedure
	"""
	pathname = tf[0]
	filename = tf[1]
	linenumber = tf[2]
	line = current.split()
	if len(line) > 1:
		if (line[1].startswith('"') and line[1].endswith('"')) or (line[1].startswith('<') and line[1].endswith('>')):
			ff = line[1][1:len(line[1])-1]
			if os.path.exists(pathname+ff):
				handle_file(listfiled,pathname,ff)
			else:
				go = False
				for p in includes:
					if os.path.exists(p+ff):
						go = True
						handle_file(listfiled,p ,ff)
						writetolst = False
						break
				if not go:
					writeToLst (listfiled,"ERROR : file %s not found, from #include at line %d in file %s" %(ff,linenumber,filename))
		else:
			writeToLst (listfiled,"ERROR : unbalanced #include at line %d in file %s" %(linenumber,filename))
	else:
		writeToLst (listfiled,"ERROR : unknown #include at line %d in file %s" %(linenumber,filename))

def handle_preprocessor_line(listfile,line,com,tf):
	""" handle preprocessor directives, besides the if and macro family"""
	dict = {
		"#register":registerProc,
		"#unregister":unregisterProc,
		"#define":defineProc,
		"#undef":undefProc,
		"#include":includeProc,
		"#message":messageProc,
		"#warning":warningProc,
		"#error":errorProc,
		"#warn":warnProc,
		}
	function = line.split()
	if function[0].strip() in dict:
		functionToCall = dict[function[0].strip()]
		functionToCall(listfile,line,com,tf)
	else:
		writeToLst (listfile,"ERROR : unknown preprocessor directive '%s', in file %s line %d" % (function[0],tf[0]+tf[1],tf[2]))

##########################
# State machine procedures
##########################
def printLine (listfile,current,com,tf):
	""" print current line( comments ) to list file""" 
	if listfile != 0:
		listfile.write("%s %d:\t%s" % (tf[0]+tf[1],tf[2],current+com))
	return state

def ignoreLine(listfiled,line,com,tf):
	""" do nothing """
	return state
	
def ignoreFLine(listfiled,line,com,tf):
	""" do nothing, but change state - 'else' case """
	return 'iffalse'

def errorLine(listfiled,line,com,tf):
	writeToLst (listfiled,"ERROR: illegal directive : %s %d: %s" %(tf[0]+tf[1],tf[2],line))
	return state

def removeSpaces(line,pos0):
	ind = 1
	ll = []
	pos = pos0	
	for i in range(pos+1,len(line)):
		if line[i] == '(':
			if ind == 0:
				pos = i
			ind += 1
		elif line[i] == ')':
			ind -= 1
			if ind == 0:
				ind = 0
				le = i+1
				ll.append((pos,le))
				pos = le 
	
	if ind == 0:
		# take the first portion
		newline = line[0:pos0]
		for t in range(len(ll)):
			# ll is the list of stat,end of a paranthesis
			#tt is a tuple : start, end -1
			tt = ll[t]
			#add a replaced portion
			newline.append(''.join(line[tt[0]:tt[1]]))
			# add the portion between replaced, if exists
			if t == len(ll) - 1:
				s=''.join(line[tt[1]:len(line)])
			else:
				s=''.join(line[tt[1]:ll[t+1][0]])
			if s:
				newline.append(s)
		#print newline
		return newline
	else :
		print "error in expression "
		print line
		return ''
		
def compile_line(listfile,line,tf): 
	""" the line is a code line """
	ac = ('','')
	current = line.split()
	#replace defines
	newline = []
	for r in current:
		if r in define_symbol:	
			s = str(define_symbol[r])
			ls = s.split()
			for j in ls:
				newline.append(j)
		else:
			newline.append(r)
	# replace register definition
	current = newline
	newline = []
	for r in current:
		if r in registers_symbol:
			newline.append(registers_symbol[r])
		else:
			newline.append(r)
	current = newline
	# remove spaces after '(' and before ')', to use Python's eval function
	try:
		i = current.index('(')
		if i != -1:		
			current = removeSpaces(current,i)
	except ValueError:
		pass
	for r in range(len(current)) :
		current[r] = current[r].lower()
	
	ac = aceCode.handle_assembly_line(listfile,current,tf)
	return ac

def regularLine(listfile,line,com,path):
	global correct

	ac = (True,('','',''))
	if line.startswith('#'):
		handle_preprocessor_line(listfile,line,com,path)
	else:
		current = line.split()
		#replace macros
		if len(macro_symbol) > 0:
			for r in current:
				if r in macro_symbol:				
					pos = current.index(r)
					a = macro_symbol[r][0] # macro parameters
					if current.count("(") != 1 or current.count(")") != 1:
						writeToLst (listfile,"ERROR : wrong parameter list for macro, must begin with '(' and end with ')', at line %d in file %s" %(tf[2],tf[0]+tf[1]))
					elif current[pos + 1] != '(' or current[pos + len(a) +1] != ')':
						writeToLst (listfile,"ERROR : wrong parameter list for macro, must begin with '(' and end with ')', at line %d in file %s" %(tf[2],tf[0]+tf[1]))
					else:
						m = macro_symbol[r][1:] # macro body
						#replace macro's arguments with actual values
						for arg in a:
							for macroline in m:
								if arg in macroline:
									argpos = a.index(arg)
									macroline.replace(arg,current[pos + 2 + argpos])
									ac = compile_line(listfile,macroline.split(),path)     
				else:
					ac = compile_line(listfile,line,path)
		else:
			ac = compile_line(listfile,line,path)
	if correct and not ac[0] :
			correct = False
	acc = ac[1]
	if not acc[1]:
		writeToLst(listfile,path[0]+path[1]+' '+str(path[2])+':\t'+line+'\t'+com)
	else:
		if acc[2] == 2:
			writeToLst(listfile,"%s %d 0x%08x : 0x%08x\t%s\t%s" % (path[0]+path[1],path[2],acc[0],acc[1],line,com))
		elif acc[2] == 1:
			writeToLst(listfile,"%s %d 0x%08x : 0x%04x\t%s\t%s" % (path[0]+path[1],path[2],acc[0],acc[1],line,com))
		elif acc[2] == 0:	
			writeToLst(listfile,"%s %d 0x%08x : 0x%02x\t%s\t%s" % (path[0]+path[1],path[2],acc[0],acc[1],line,com))
	return state
	
####################				
## IF procedures
####################
def ifLine(listfiled,current,com,tf):
	global ifStack
	line = current.split()
	retvalue = 'empty'
	if line[0] == '#ifdef':
		if line[1] in define_symbol:
			retvalue = 'iftrue'
		else:
			retvalue = 'iffalse'
	elif line[0] == '#ifndef':
		if line[1] in define_symbol:
			retvalue = 'iffalse'
		else:
			retvalue = 'iftrue'
	else:
		if line[1] == '(':
			if len(line) >= 4:
				if line[3] == ')':
					# form : #if ( name )
					if line[2] in define_symbol:
						retvalue = 'iftrue'
					else:
						retvalue = 'iffalse'
				else:
					if len(line) >= 6:
						# form : #if ( name op value )
						if line[5] == ')':
							if line[2] in define_symbol:
								if line[3] == '==':
									if define_symbol[line[2]] == line[4]:
										retvalue = 'iftrue'
									else:
										retvalue = 'iffalse'
								else:
									if line[3] == '!=':
										if define_symbol[line[1]] != line[4]:
											retvalue = 'iftrue'
										else:
											retvalue = 'iffalse'
									else:
										writeToLst (listfiled,"ERROR : unknown operator '%s' , at line %d in file %s" % (line[2],tf[2],tf[0]+tf[1]))
							else:
								writeToLst (listfiled,"ERROR : unknown symbol '%s' , at line %d in file %s" % (line[1],line[2],tf[2],tf[0]+tf[1]))
						else:
							writeToLst (listfiled,"ERROR : unmatched paranthesis at line %d in file %s" % (line[2],tf[2],tf[0]+tf[1]))
					else:
						writeToLst (listfiled,"ERROR : not enough parameters at line %d in file %s" % (line[2],tf[2],tf[0]+tf[1]))
			else:
				writeToLst (listfiled,"ERROR : not enough parameters at line %d in file %s" % (line[2],tf[2],tf[0]+tf[1]))
		else: # form : #if name
			if line[1] in define_symbol:
				retvalue = 'iftrue'
			else:
				retvalue = 'iffalse'
	if retvalue == 'empty':
		writeToLst(listfiled,tf[0]+tf[1]+' '+str(tf[2])+':\t'+current+'\t '+com)
	else:
		ifStack.append(retvalue)
	
	return retvalue
	
def endifLine(listfiled,line,com,tf):
	global ifStack
	if len(ifStack) > 0:
		ifStack.pop()
	else:
		writeToLst (listfiled,"ERROR : unbanlced #if .. #endif , too many endif, file %s, line %d" % (tf[0]+tf[1], tf[2]))
	return 'empty'

def elseLine(listfiled,line,com,tf):
	global ifStack
	try:
		last = ifStack.pop()
		if last == 'iftrue':
			last = 'iffalse'
		else:
			last = 'iftrue'
		ifStack.append(last)
		return last
	except IndexError:
		writeToLst (listfiled,"ERROR: 'else' without 'if' in file %s, line %d" %(tf[0]+tf[1],tf[2]))
		return 'empty'

def elseifLine(listfile,line,com,tf):
	last = elseLine(listfile,line,com,tf)
	if last != 'empty':
		last = ifLine(listfile,line,com,tf)
	return last

####################				
## MACRO procedures
####################
def lookForMacroSymbol(alias):
	"""
	If macro defined, returns the parameters list
	otherwise returns an empty string
	"""	
	if alias in macro_symbol:
		return macro_symbol[alias][0]
	return ''
	
def macroLine(listfiled,line,com,tf):
	global macroname
	global macro_symbol
	if line.count("(") != 1 or line.count(")") != 1:
		writeToLst (listfiled,"ERROR : wrong parameter list for macro, must begin with '(' and end with ')', at line %d in file %s" %(tf[2],tf[0]+tf[1]))
	elif line[1] != '(' or line[len(line) - 1] != ')':
		writeToLst (listfiled,"ERROR : wrong parameter list for macro, must begin with '(' and end with ')', at line %d in file %s" %(tf[2],tf[0]+tf[1]))
	else:
		if len(line) >= 3:
			macroname = line[0]
			if macroname in macro_symbol:
				writeToLst (listfiled,"ERROR : macro already defined, line %d in file %s" %(tf[2],tf[0]+tf[1]))
			else:
				macro_symbol[macroname] = line[2:len(line) - 2]	
		else:
			writeToLst (listfiled,"ERROR : unknown #macro at line %d in file %s" %(tf[2],tf[0]+tf[1]))
	return 'macro'
	
def endmacroLine(listfile,line,com,tf):
	return 'empty'
	
def macroBodyLine(listfiled,line,com,tf):
	"""
	add macro's lines to its list
	"""
	global macro_symbol
	macro_symbol[macroname].append(line)
	return 'macro'

############################
# Line parser state machine
# each state has a list of substates, according to received line type
# the specific callback is called
############################
SM = {'empty'  :{'empty':printLine, 'regular':regularLine,  'if':ifLine,     'else':errorLine,  'elseif':errorLine,  'endif':errorLine,'macro':macroLine,'endmacro':errorLine},
	  'iftrue' :{'empty':printLine, 'regular':regularLine,  'if':regularLine,'else':ignoreFLine,'elseif':ignoreFLine,'endif':endifLine,'macro':errorLine,'endmacro':errorLine},
	  'iffalse':{'empty':ignoreLine,'regular':ignoreLine,   'if':ignoreLine, 'else':elseLine,   'elseif':elseifLine, 'endif':endifLine,'macro':errorLine,'endmacro':errorLine},
	  'macro'  :{'empty':printLine, 'regular':macroBodyLine,'if':errorLine,  'else':errorLine,  'elseif':errorLine,  'endif':errorLine,'macro':errorLine,'endmacro':endmacroLine}}

def handle_file(listfile,pathname,filename):
	""" read all the line of a file, and process them """
	global state
	ff = pathname + filename
	print "Handle file : " + ff
	linenumber = 0
	try:
		f = open(ff,'r')
		for line in f:
			linenumber += 1
			line = line.replace('\t',' ')
			line = line.replace('(',' ( ')
			line = line.replace(')',' ) ')
			ntf = (pathname,filename,linenumber)
			gtl = get_line_type(listfile,line,ntf)
			state = SM[state][gtl[2]](listfile,gtl[0],gtl[1],ntf)
			#print "returned " + state
		f.close()
	except IOError:
		print 'File (handle_file) ',ff,' does not exist'

def get_line_type(listfile,line,tf):
	""" return the read line type, according to the beginning of the line
	strip the in line comments"""
	
	if len(line.strip()) <= 2:
		return (line,'','empty')
	else:
		if line.strip().startswith(';') or line.strip().startswith('/*'):
			return (line,'','empty')		
		codeline = line
		comment = ''
		pos = line.find(';')
		if pos != -1:
			if line[pos-1:pos] != ' ':
				writeToLst (listfile,"WARNING : comment must have a space before ';', in file %s, line %d" % (tf[0]+tf[1],tf[2]))
				line = line.replace(';',' ;',1)
				pos += 1
			comment = line[pos:].strip()
			codeline = line[0:pos-1]
		else:
			pos = line.find('/*')
			if pos != -1:
				if line[pos-1:pos] != ' ':
					writeToLst (listfile,"WARNING : comment must have a space before '/*', in file %s, line %d" % (tf[0]+tf[1],tf[2]))
					line = line.replace('/*',' /*',1)
					pos += 1
				comment = line[pos:].strip()
				codeline = line[0:pos-1]
		codeline = codeline.strip()			
		if codeline.startswith('#if') or codeline.startswith('#ifdef') or codeline.startswith('#ifndef') :
			return (codeline,comment,'if')		
		elif codeline.startswith('#endif') :
			return (codeline,comment,'endif')
		elif codeline.startswith('#elseif') :
			return (codeline,comment,'elseif')
		elif codeline.startswith('#else') :
			return (codeline,comment,'else')
		elif codeline.startswith('#endmacro') :
			return (codeline,comment,'endmacro')
		elif codeline.startswith('#macro') :
			return (codeline,comment,'macro')		
		return (codeline,comment,'regular') 

#-------------
#	Main
#-------------
def main(argv):
	global includes
	objectFile = False
	firmwareFile = 'BL234x_firmware'
	runner = 'A'
	if len(argv) < 2:
		print     "\n" \
                "Syntax: [-option ...] [file | directory] [file  | directory ...]\n" \
                "\n" \
                "Options:\n" \
                "    -Ipath			Directory of include files\n" \
                "    -Dmacro		Define preprocessor macro\n" \
				"    -O				Create '.o' file - binay unified\n" \
				"    -Ffile			Firmware file name\n" \
				"    -[A | B | D | C | U]	Runner name\n"
	else:
		print "Start at : "
		print datetime.now()
		fileslist = []
		pathname = ''
		for i in range (1,len(argv)):
			if argv[i].startswith ('-I'):
				includes.append(argv[i][2:]+os.sep)
			elif argv[i].startswith ('-D'):
				defineProc(0,"#define "+argv[i][2:],'',(pathname,'',0))
			elif argv[i].startswith('-O'):
				objectFile = True
			elif argv[i].startswith('-F'):
				firmwareFile = argv[i][2:]
			elif argv[i] == '-D':
				runner = 'D'
			elif argv[i] == '-U':
				runner = 'U'	
			else:
				if not os.path.exists(argv[i]):
					print argv[i] + ' does not exists'
				elif os.path.isfile(argv[i]):
					if argv[i].endswith(".uc"):
						fileslist.append(argv[i])
 				else:
					if not argv[i].endswith(os.sep):
						pathname = argv[i]+os.sep
					else:
						pathname = argv[i]
					if os.path.isdir(pathname):	
						for root, dirs, files in os.walk(pathname):
							if len(root) > 0 :
								if not '.svn' in root:
									if len(files) > 0:
										for j in files:
											if j.endswith(".uc"):
												fileslist.append(pathname+j)
											else:
												continue
					else:
						print 'Parameter must be a file or a directory'
		if len(fileslist) > 0:
			firstfile = fileslist[0]
			pathname = os.path.dirname(firstfile)
			if pathname.find('/') != -1:
				if '/' != os.sep:
					pathname = pathname.replace('/',os.sep)
			elif pathname.find('\\') != -1:
				if "\\" != os.sep:
					pathname = pathname.replace('\\',os.sep)
				pathname = pathname + os.sep
			if not pathname.endswith(os.sep):
				pathname = pathname + os.sep
			fl = 0
			firmwareFile += "_%c.c" % (runner)
			try:	
				os.remove(firstfile.replace('.uc','.lst'))
				os.remove(firstfile.replace('.uc','.map'))
				os.remove(firstfile.replace('.uc','_sym.h'))
				os.remove(firstfile.replace('.uc','_code.mem'))
				os.remove(firstfile.replace('.uc','_code_lo.mem'))
				os.remove(firstfile.replace('.uc','_code_hi.mem'))
				os.remove(firstfile.replace('.uc','_data.mem'))
				os.remove(firstfile.replace('.uc','_context.mem'))
				os.remove(firstfile.replace('.uc','_predict.bin'))
				os.remove(pathname+firmwareFile)
				os.remove(firstfile.replace('.uc','.o'))
			except OSError:
				pass
			try:
				fl = open(firstfile.replace('.uc','.lst'),'w+')			
			except IOError:
				print "Cannot open list file for " + firstfile			
				if fl:
					fl.close()
				return
			for i in fileslist:
				pathname = os.path.dirname(i) 
				filename = i.replace(pathname,'') 
				filename = filename.replace(os.sep,'')
				if pathname.find('/') != -1:
					if '/' != os.sep:
						pathname = pathname.replace('/',os.sep)
				elif pathname.find('\\') != -1:
					if "\\" != os.sep:
						pathname = pathname.replace('\\',os.sep)
					pathname = pathname + os.sep
				if not pathname.endswith(os.sep):
					pathname = pathname + os.sep
				handle_file(fl,pathname,filename)
			
			aceCode.checkUnresolved()
			if fl:
				fl.close()
			if correct:
				try:
					fmap = open(firstfile.replace('.uc','.map'),'w+')
					fsym = open(firstfile.replace('.uc','_sym.h'),'w+')
				except IOError:
					print "Cannot open result files for " + firstfile
					return
				fmap.write("----------------------------------------------------------------------------\n")
				fmap.write("Symbol%24.24s  Segment   Address                Note\n" % (' '))
				fmap.write("----------------------------------------------------------------------------\n\n")
				for l in aceCode.labels:
					ll = aceCode.labels[l]
					if ll[0] == 0:
						seg = 'DATA'
					elif ll[0] == 1:
						seg = 'CONTEXT'
					else: seg = 'CODE'
					fmap.write(":%-30.30s  %s   0x%08X   %20.20s %d\n"% (l,seg,ll[1],ll[2][0]+ll[2][1],ll[2][2]))
					fsym.write("#define %-30.30s\t0x%08X\n" % (l,ll[1]))
				if len(aceCode.unresolved) > 0:
					fmap.write("\n------------------------------------------------------------\n")
					fmap.write("Unresolved Symbol%13.13s    Address        Value\n" % (' '))
					fmap.write("------------------------------------------------------------\n\n")
					for l in aceCode.unresolved:
						if l[1] and l[0]:
							fmap.write(":%-30.30s  0x%08X => 0x%08X\n" % (l[1],l[0],aceCode.codeSegment[l[0]]))
				fmap.close()
				fsym.close()
				try:
					fcode = open(firstfile.replace('.uc','_code.mem'),'w+')
					fcode_lo = open(firstfile.replace('.uc','_code_lo.mem'),'w+')
					fcode_hi = open(firstfile.replace('.uc','_code_hi.mem'),'w+')
					fdata = open(firstfile.replace('.uc','_data.mem'),'w+')
					fctx = open(firstfile.replace('.uc','_context.mem'),'w+')
					fp = open(firstfile.replace('.uc','_predict.bin'),'wb')					
				except IOError:
					print "Cannot open result files for " + firstfile
					return
				write_code(fcode,0,opcodes.CODE_SEGMENT_SIZE)
				write_code(fcode_lo,0,opcodes.CODE_0_SEGMENT_SIZE)
				write_code(fcode_hi,opcodes.CODE_0_SEGMENT_SIZE,opcodes.CODE_SEGMENT_SIZE)
				fcode.close()
				fcode_lo.close()
				fcode_hi.close()
				write_data(fdata,True)
				write_data(fctx,False)
				fdata.close()
				fctx.close()
				for i in range(0,opcodes.CODE_SEGMENT_SIZE/32):
					data = 0
					for j in range(0,8):
						data += aceCode.prediction[i*8+j] << j
						d = struct.pack('I',data)
						#sd = '0x%08X\n' % (d)
						fp.write(d)				
				fp.close()
				try:
					ffw = open(pathname+firmwareFile,'w+')
					write_firmware(ffw,runner)
				except IOError:
					print "Cannot open firmware file : " +  pathname + firmwareFile
				if objectFile:
					try:
						fobj = open(firstfile.replace('.uc','.o'),'wb')
						write_obj_file(fobj)
					except IOError:
						print "Cannot open object file for " + firstfile
						return
			else:
				print 'Compilation failed !!!'
		else:
			print 'Parameter must be an existing file or a directory'

	print "Stop at : "
	print datetime.now()

def write_firmware(fobj,r):
	codeNop = aceCode.codedefault
	fobj.write('#include "stt_basic_defs.h"\n\nstt_uint32 firmware_binary_%c[] = {\n' % (r))
	for i in range(0,opcodes.CODE_SEGMENT_SIZE,4):
		if i in aceCode.codeSegment:
			fobj.write("    0x%08X,\n" % (aceCode.codeSegment[i]))
		else:
			fobj.write("    0x%08X,\n" % (codeNop))
	fobj.write('}\n')
	fobj.close()
	
def write_data (fobj,data):
	if data:
		ar = aceCode.dataSegment
		size = opcodes.DATA_SEGMENT_SIZE/8
	else:
		ar = aceCode.contextSegment
		size = opcodes.CONTEXT_SEGMENT_SIZE/8
	write_header(fobj)
	for j in range(0,size):
		xx = []
		i = 0
		while i < 8:
			k = j*8+i
			if k in ar:				
				dt = ar[k]
				if dt[1] == aceCode.DATA_BYTE:
					if i%2 == 0 or i == 7:
						xx.append("%02X" % (dt[0]))
					else:
						xx.append("%02X_" % (dt[0]))
				elif dt[1] == aceCode.DATA_SHORT:
					i += 1
					data = struct.pack('>I',dt[0])
					xx.append("%02X" % ((dt[0] >> 8) & 0xff))
					if i == 7:
						xx.append("%02X" % (dt[0] & 0xff))
					else:
						xx.append("%02X_" % (dt[0] & 0xff))
				else :
					i += 3
					data = struct.pack('>I',dt[0])
					xx.append("%02X" % ((dt[0] >> 24) & 0xff))
					xx.append("%02X_" % ((dt[0] >> 16) & 0xff))
					xx.append("%02X" % ((dt[0] >> 8) & 0xff))
					if i == 7 :
						xx.append("%02X" % (dt[0] & 0xff))
					else:
						xx.append("%02X_" % (dt[0] & 0xff))
			else:
				if i%2 == 0 or i == 7:
					xx.append("xx")
				else:
					xx.append("xx_")
			i += 1
		s = ''.join(xx)
		fobj.write(s+'\n')

def write_header (fobj):
	fobj.write("// ")
	fobj.write("%s object file created on %s by %s version %s\n\n" % (ACE_NAME,datetime.now(),ACE_NAME,ACE_VERSION))
	fobj.write("// Following data should be loaded to beginning of the segment\n@0\n\n")

def write_code (fobj,start,end):

	write_header(fobj)
	codeNop = aceCode.codedefault
	for i in range(start,end,4):
		if i in aceCode.codeSegment:
			fobj.write("%08X\n" % (aceCode.codeSegment[i]))
		else:
			fobj.write("%08X\n" % (codeNop))

def write_obj_file (fobj):

	#fobj.write("%s object file created on %s by %s version %s\n\n" % (ACE_NAME,datetime.now(),ACE_NAME,ACE_VERSION))
	#fobj.write("DATA:    %08X\nCODE:    %08X\nCONTEXT: %08X\n" % (opcodes.DATA_SEGMENT_SIZE,opcodes.CODE_SEGMENT_SIZE,opcodes.CONTEXT_SEGMENT_SIZE))
	codeNop = aceCode.codedefault
	dataZero = 0
	for i in range(0,opcodes.DATA_SEGMENT_SIZE,4):
		if i in aceCode.dataSegment:
			data = struct.pack('>L',aceCode.dataSegment[i][0])
		else:
			data = struct.pack('>L',dataZero)
		fobj.write(data)

	for i in range(0,opcodes.CODE_SEGMENT_SIZE,4):
		if i in aceCode.codeSegment:
			data = struct.pack('>L',aceCode.codeSegment[i])
		else:
			data = struct.pack('>L',codeNop)
		fobj.write(data)

	for i in range(0,opcodes.CONTEXT_SEGMENT_SIZE,4):
		if i in aceCode.contextSegment:
			data = struct.pack('>L',aceCode.contextSegment[i][1])
		else:
			data = struct.pack('>L',dataZero)
		fobj.write(data)
	fobj.close()

if __name__ == '__main__':
	from sys import argv
	main(argv)

