#!/usr/bin/env python
NUMBER_OF_THREADS = 32 
NUMBER_OF_GLOBAL_REGISTERS  = 8 
NUMBER_OF_PRIVATE_REGISTERS = 24 
DATA_SEGMENT_SIZE  = 48 * 1024
CODE_SEGMENT_SIZE  = 32 * 1024
CODE_SEG_SIZE = CODE_SEGMENT_SIZE / 4
CONTEXT_SEGMENT_SIZE = NUMBER_OF_THREADS * NUMBER_OF_PRIVATE_REGISTERS * 4 
MAX_RELATIVE_JMP_DISTANCE = 0xFFF 
CODE_0_SEGMENT_SIZE = 16 * 1024
 
OPCODE_CODE_JMP      = 0x00 
OPCODE_CODE_JMPREG   = 0x01 
OPCODE_CODE_BEZ      = 0x02 
OPCODE_CODE_CMPJMP   = 0x03 
OPCODE_CODE_LJMP     = 0x04 
OPCODE_CODE_RET      = 0x05 
OPCODE_CODE_CSSVR    = 0x06 
OPCODE_CODE_LD       = 0x08 
OPCODE_CODE_LDC      = 0x09 
OPCODE_CODE_ST       = 0x0A 
OPCODE_CODE_STC      = 0x0B 
OPCODE_CODE_ADD      = 0x20 
OPCODE_CODE_SUB      = 0x21 
OPCODE_CODE_AND      = 0x22 
OPCODE_CODE_OR       = 0x23 
OPCODE_CODE_XOR      = 0x24 
OPCODE_CODE_SHIFT    = 0x25 
OPCODE_CODE_SIGNEXT  = 0x26 
OPCODE_CODE_FFI      = 0x27 
OPCODE_CODE_EXTRACT  = 0x28 
OPCODE_CODE_INSERT   = 0x29 
OPCODE_CODE_MULT     = 0x2A 
OPCODE_CODE_CALCJBIT = 0x2B 
OPCODE_CODE_ICHECK   = 0x2C  
OPCODE_CODE_MOVEIMM  = 0x2F 
OPCODE_CODE_LDIO     = 0x31 
OPCODE_CODE_STIO     = 0x30 
OPCODE_CODE_CNTUP    = 0x32 
OPCODE_CODE_BBTX     = 0x33 
OPCODE_CODE_BBMSG    = 0x34 
OPCODE_CODE_CRCCALC  = 0x35 
OPCODE_CODE_RAMMAN   = 0x35 
OPCODE_CODE_HASH     = 0x37 
OPCODE_CODE_DMALU    = 0x18 
OPCODE_CODE_DMALU1   = 0x19 
OPCODE_CODE_DMALU2   = 0x1A 
OPCODE_CODE_DMALU3   = 0x1B 
OPCODE_CODE_DMARD    = 0x10 
OPCODE_CODE_DMARD1   = 0x12 
OPCODE_CODE_DMAWR    = 0x14 
OPCODE_CODE_CRYPT    = 0x3C 
OPCODE_CODE_NOP      = 0x3F

OPCODE_BYTE_SHIFT_LEFT_1  = 1
OPCODE_BYTE_SHIFT_LEFT_2  = 2
OPCODE_BYTE_SHIFT_LEFT_3  = 3
OPCODE_BYTE_SHIFT_RIGHT_1 = 7 
OPCODE_BYTE_SHIFT_RIGHT_2 = 6
OPCODE_BYTE_SHIFT_RIGHT_3 = 5

OPCODE_SIZE_8  = 0
OPCODE_SIZE_16 = 1
OPCODE_SIZE_32 = 2
OPCODE_SIZE_64 = 3

OPCODE_SHIFT_MODE_ASL    = 0
OPCODE_SHIFT_MODE_ASR    = 1
OPCODE_SHIFT_MODE_RSR    = 2
OPCODE_SHIFT_MODE_RSR16  = 3

ASSEMBLY_CONDITION_NONE = 0
ASSEMBLY_CONDITION_ZERO = 1
ASSEMBLY_CONDITION_NOT_ZERO = 2
ASSEMBLY_CONDITION_LESS = 3
ASSEMBLY_CONDITION_LESS_EQUAL = 4
ASSEMBLY_CONDITION_GREATER = 5
ASSEMBLY_CONDITION_GREATER_EQUAL = 6
ASSEMBLY_CONDITION_SET = 7
ASSEMBLY_CONDITION_CLEAR = 8
SIGN_FLAG = 0x200

OPCODE_CONDITION_ALWAYS   = 0
OPCODE_CONDITION_EQUAL    = 1
OPCODE_CONDITION_LESS     = 2
OPCODE_CONDITION_GREATER  = 3

OPCODE_OPERATION_EQUAL    = 0
OPCODE_OPERATION_GREATER  = 1
OPCODE_OPERATION_BIT_OR   = 2
OPCODE_OPERATION_BIT_AND  = 3

OPCODE_32BIT = 3
OPCODE_16LSB = 1
OPCODE_16MSB = 2
OPCODE_FFI8 = 0
OPCODE_FFI16 = 1
 
# the tuple has : start bit, end bit
signextOpcode = {'opcode':(0,6),                                                          
	'immediate_or_register':(6,7),	
	'destination_register':(7,12),	
	'source_a':(13,18),				
	'update_flags':(18,19),
	'source_b_or_immediate':(23,28)}

icheckOpcode = {'opcode':(0,6),                                                           
	'last':(6,7),
	'destination_register':(7,12),
	'source_a':(12,18),
	'high_or_low':(18,19),
	'reverse':(19,20),
	'source_b':(20,28),
	'byte_shift':(29,32)}

counterOpcode = {'opcode':(0,6),                                                           
	'imm_or_reg_b':(6,7),
	'source_c':(7,12),
	'source_a':(12,20),
	'source_b':(20,28),
	'imm_or_reg_a':(28,29),
	'mode':(29,30),
	'size':(30,31),
	'operation':(31,32)}

cmpjmpOpcode = {'opcode':(0,6),                                                           
	'immediate_or_register':(6,7),
	'source_b':(7,12),
	'bsel':(12,13),
	'source_a':(13,18),
	'operation':(18,20),
	'invert_condition':(20,21),
	'update':(21,22),
	'address_register':(27,32),
	'immediate_value':(22,32)}

bezOpcode = {'opcode':(0,6),                                                           
	'immediate_or_register':(6,7),
	'size':(10,12),
	'call':(12,13),
	'source_a':(13,18),
	'execute_delay_slot':(18,20),
	'invert_condition':(20,21),
	'update':(21,22),
	'address_register':(27,32),
	'immediate_value':(22,32)}

jmplngOpcode = {'opcode':(0,6),                
	'call':(12,13),
	'immediate_value':(18,32)}

jmpOpcode = {'opcode':(0,5),                
	'jmp_register':(5,6),                                           
	'immediate_or_register':(6,7),
	'condition_bit_offset':(7,12),
	'call':(12,13),
	'condition':(13,18),
	'execute_delay_slot':(18,20),
	'invert_condition':(20,21),
	'update':(21,22),
	'address_register':(27,32),
	'immediate_value':(22,32)}

nopOpcode = {'opcode':(0,6)}

ldOpcode = {'opcode':(0,6),                
	 'immediate_or_register':(6,7),    
	 'destination_register':(7,12),     
	 'high_or_low':(12,13),              
	 'base_address':(13,18),              
	 'offset':(18,29),                   
	 'direct_or_index':(29,30),          
	 'size':(30,32),
	 'immediate':(12,28)}

movOpcode = {'opcode':(0,6),                
	'destination_register':(7,12),     
	'immediate_value':(12,28),    
	'high_or_low':(28,29),              
	'clear':(29,30)}

insertOpcode = {'opcode':(0,6),                    
	'destination_register':(7,12),     
	'source_a':(13,18),              
	'width':(18,23),              
	'offset':(23,28)}

shiftOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),    
	'destination_register':(7,12),     
	'source_a':(13,18),              
	'update_flags':(18,19),              
	'source_b_or_immediate':(23,28),                   
	'mode':(30,32)}

aluOpcode = {'opcode':(0,6),
	 'immediate_or_register':(6,7),
	 'destination_register':(7,12),
	 'source_a':(13,18),
	 'update_flags':(18,19),
	 'source_b_or_immediate':(20,28),
	 'invert_source':(28,29),
	 'byte_shift':(29,32)}

ldioOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),    
	'destination_register':(7,12),     
	'high_or_low':(12,13),
        'source_address':(13,18),              
	'address':(23,28),                      
	'size':(30,32),
	'immediate':(18,28)} # instead address !!!

ctxswapOpcode = {'opcode':(0,6),                
	'immediate_value':(12,28),    
	'save':(29,30),     
	'update_r16':(30,31),              
	'async_en':(31,32)}

dmaaluOpcode = {'opcode':(0,4),
	'global_mask':(4,6),
	'immediate_or_register':(6,7),    
	'source_c':(7,12),     
	'common_or_private':(12,13),                                  
	'source_a':(13,18),
	'mem':(18,19),
	'mask':(19,20),
	'res_slot':(20,23),
	'source_b_or_immediate':(23,28),
	'async_enable':(28,29),
	'invoke':(29,30),
	'update_r16':(30,31),
	'context_swap':(31,32)}

dmaOpcode = {'opcode':(0,4),
	'stall':(4,5),
	'addr_calc':(5,6),
	'immediate_or_register':(6,7),    
	'source_c':(7,12),     
	'common_or_private':(12,13),                                  
	'source_a':(13,18),
	'mem':(18,19),
	'mask':(19,20),
	'source_b_or_immediate':(20,28),
	'async_enable':(28,29),
	'invoke':(29,30),
	'update_r16':(30,31),
	'context_swap':(31,32)}

hashOpcode = {'opcode':(0,6),                
	'source_c':(7,12),    
	'source_a':(13,18),     
	'res_slot':(18,21),              
	'table':(23,25),                      
	'rq':(25,26),
	'sa':(26,27),
	'ks':(27,28),
	'invoke':(29,30),
	'update_r16':(30,31),
	'cs':(31,32)}

crcOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),    
	'source_c':(7,12),     
	'common_or_private':(12,13),              
	'source_a':(13,18),
	'type':(18,19),
	'source_b_or_immediate':(20,28),
	'eth':(30,31),
	'last':(31,32)}

camOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),    
	'source_c':(7,12),     
	'common_or_private':(12,13),                                    
	'source_a':(13,18),
	'type':(18,19),
	'invoke':(25,26),
	'res_slot':(26,28),
	'use_128':(28,29),
	'key_size':(29,31),
	'mask':(31,32)}

ffiOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),    
	'destination_register':(7,12),     
	'source_a':(13,18),
	'source_b_or_immediate':(23,28),
	'size':(30,32)}

bbtxOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),    
	'source_c':(7,12),     
	'common_or_private':(12,13),                                    
	'source_a':(13,18),
	'wait':(19,20),
	'source_b_or_immediate':(20,28),
	'invoke':(29,30),
	'last':(30,31),
	'inc':(31,32)}

bbmsgOpcode = {'opcode':(0,6),                
	'immediate_or_register':(6,7),                                            
	'source_a':(13,18),
	'wait':(19,20),
	'source_b_or_immediate':(20,28),
	'type':(28,31),
	'size':(31,32)}

cryptOpcode = {'opcode':(0,6),                
	'hash':(6,7),                                           
	'source_a':(12,18),
	'ext':(19,20),
	'source_b':(20,28),
	'immediate_or_register':(28,29),
	'invoke':(29,30),
	'last':(30,31),
	'first':(31,32)}

retOpcode = {'opcode':(0,6)}
																																			

