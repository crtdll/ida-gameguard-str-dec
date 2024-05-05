import idaapi
import ida_name
import ida_allins
import ida_idaapi
import idc
import ida_search
import ida_bytes

def find_signature(sig):
  if idaapi.IDA_SDK_VERSION <= 750:
    return ida_search.find_binary(idc.get_inf_attr(idc.INF_MIN_EA) + 1, ida_idaapi.BADADDR, sig, 16, idc.SEARCH_DOWN)
  else:
    match_ea = idc.get_inf_attr(idc.INF_MIN_EA)
    binpat = ida_bytes.compiled_binpat_vec_t()
    ida_bytes.parse_binpat_str(binpat, match_ea, sig, 16)
    return ida_bytes.bin_search(match_ea + 1, idaapi.BADADDR, binpat, idaapi.BIN_SEARCH_FORWARD)

def get_previous_instruction(ea):
  insn = idaapi.insn_t()
  idaapi.decode_prev_insn(insn, ea)
  return insn

def get_previous_instructions(address, count):
  previous_list = []
  for i in range(count):
    prev_instructions = get_previous_instruction(address)
    previous_list.append(prev_instructions)
    address = prev_instructions.ea
  return previous_list

def decrypt_string(data: bytearray):
  if data[0] != 0x1:
    try:
      return '[[used]]' + data.split(b'\x00', 1)[0].decode('utf-8') # If it's already decrypted, add [[used]] to the output
    except:
      return None
  
  shift_factor = 3 * data[1]
  data[2] ^= (shift_factor + 101) & 0xFF
  next_shift_factor = 3 * (shift_factor + 1)
  data[3] ^= (next_shift_factor + 101) & 0xFF
  current_shift = next_shift_factor + 1
  combined_data = data[3] | data[2] << 8
  
  if combined_data:
    index = 0
    while index < combined_data:
      current_shift_value = 3 * current_shift
      current_shift_value_plus_101 = current_shift_value + 101
      current_shift = current_shift_value + 1
      data[index] = (data[index + 4] ^ current_shift_value_plus_101) & 0xFF
      index += 1

  return data[:combined_data].decode('utf-8')

def process_dec(address):
  prev_instructions = get_previous_instructions(address, 140)
  lea_instruction = None
  
  for i in prev_instructions:
    if i.itype == ida_allins.NN_lea and i.ops[0].reg == 1:
      lea_instruction = i
      break
    
  if lea_instruction is None:
    return None
  
  string_address = lea_instruction.ops[1].addr
  result = decrypt_string(bytearray(get_bytes(string_address, 0x200)))
  
  if result is None:
    return None
  
  return [address, result] 

def dump():
  output = []
  
  decrypt_func_ea = find_signature('8D 0C 49 8D 41 65 FF C1 32 42 04 88 02 48 FF C2 48 8B C2 48 2B C3 49 3B C0 7C E5 33 FF 41 C6 04 18 ? FF 15 ? ? ? ? 44 8B C0 8D 4F 01 48 8D 15 ? ? ? ? 8D 6F 04 4C 8D 0D ? ? ? ? 44 39 02 74 13 FF C1 48 8D 05 ? ? ? ? 48 03 D5 48 3B D0 7C E3 EB 06')
  if decrypt_func_ea == idaapi.BADADDR:
    return
  
  decrypt_func_ea -= 0x73 # This is valid as of 05/05/2024 for all of their modules

  for xref in XrefsTo(decrypt_func_ea, flags=0):
    result = process_dec(xref.frm)
    if result is None:
      continue
    
    # Set a comment in the asm
    idc.set_cmt(xref.frm, result[1], 0)
    
    # Attempt to decompile the function and set a comment in F5
    try:
      cfunc = idaapi.decompile(xref.frm)
      if cfunc:
        tl = idaapi.treeloc_t()
        tl.ea = xref.frm
        tl.itp = idaapi.ITP_SEMI
        cfunc.set_user_cmt(tl, result[1])
        cfunc.save_user_cmts()
    except:
      pass
    
    # Add it to the output
    output.append(f'[{hex(result[0])}] = {result[1]}')
  return output

output = dump()
if not output:
  exit()
  
with open('D:\\decryped_strings.txt', 'w') as out:
  for i in output:
    out.write(i + '\n')
