# pip install pytest
# pytest test_rebuild_iat.py
import pytest
from unittest.mock import patch, MagicMock

def rebuild_iat(data_vr_address, data, mode, start_limit, end_limit, iat_ptrs):
    reg_redirect = {}
    modified_regions = set()  # Track modified code regions

    for op in distorm3.DecomposeGenerator(data_vr_address, data, mode):
        if not op.valid:
            continue
        
        iat_loc = None

        # Handle direct calls and jumps
        if _call_or_unc_jmp(op) and op.operands[0].type == 'AbsoluteMemoryAddress':
            iat_loc = (op.operands[0].disp) & 0xffffffff

        # Handle indirect calls through registers (for stolen bytes technique)
        elif op.mnemonic == "CALL" and op.operands[0].type == 'Register':
            reg = str(op.operands[0])
            if reg in reg_redirect:
                iat_loc = reg_redirect[reg]

        # Track register values for indirect calls and memory redirections
        elif op.mnemonic == "MOV" and op.operands[0].type == 'Register' and op.operands[1].type == 'AbsoluteMemoryAddress':
            reg_redirect[str(op.operands[0])] = op.operands[1].disp

        # Handle push-ret sequences (obfuscated calls)
        elif op.mnemonic == "PUSH" and op.operands[0].type == 'AbsoluteMemoryAddress':
            next_op = next(distorm3.DecomposeGenerator(op.address + op.size, data[op.address - data_vr_address + op.size:], mode), None)
            if next_op and next_op.mnemonic == "RET":
                iat_loc = (op.operands[0].disp) & 0xffffffff

        # Handle SEH-based redirection by checking PUSH and RET sequences
        elif op.mnemonic == "PUSH" and op.operands[0].type == 'Immediate':
            next_op = next(distorm3.DecomposeGenerator(op.address + op.size, data[op.address - data_vr_address + op.size:], mode), None)
            if next_op and next_op.mnemonic == "RET":
                iat_loc = (op.operands[0].imm) & 0xffffffff
        
        # Handle indirect jump and redirection through ROP gadgets
        elif op.mnemonic == "JMP" and op.operands[0].type == 'Register':
            reg = str(op.operands[0])
            if reg in reg_redirect:
                iat_loc = reg_redirect[reg]

        # Handle potential ROP redirection sequences (like POP RET)
        elif op.mnemonic == "POP" and op.operands[0].type == 'Register':
            reg = str(op.operands[0])
            next_op = next(distorm3.DecomposeGenerator(op.address + op.size, data[op.address - data_vr_address + op.size:], mode), None)
            if next_op and next_op.mnemonic == "RET" and reg in reg_redirect:
                iat_loc = reg_redirect[reg]
        
        # Check for self-modifying code patterns (MOV into the code segment)
        handle_self_modifying_code(op, (data_vr_address, data_vr_address + len(data)), modified_regions)
        
        if iat_loc and start_limit <= iat_loc <= end_limit and iat_loc not in iat_ptrs:
            iat_ptrs.append(iat_loc)

    # If modified regions were detected, rescan the code in those regions
    if modified_regions:
        for modified_addr in modified_regions:
            new_ops = distorm3.DecomposeGenerator(modified_addr, data[modified_addr - data_vr_address:], mode)
            rebuild_iat(modified_addr, data, mode, start_limit, end_limit, iat_ptrs)
    
    return iat_ptrs

def handle_self_modifying_code(op, code_segment_address_range, modified_regions):
    # Track modifications to the code segment memory
    if op.mnemonic == "MOV" and op.operands[0].type == 'MemoryAddress':
        addr = op.operands[0].disp
        if code_segment_address_range[0] <= addr <= code_segment_address_range[1]:
            modified_regions.add(addr)


@patch('distorm3.DecomposeGenerator')
def test_direct_call(mock_decompose):
    # Simulate a direct CALL with an AbsoluteMemoryAddress
    op_mock = MagicMock()
    op_mock.valid = True
    op_mock.mnemonic = "CALL"
    op_mock.operands = [MagicMock(type='AbsoluteMemoryAddress', disp=0x1000)]
    
    mock_decompose.return_value = [op_mock]
    
    iat_ptrs = []
    result = rebuild_iat(0, b'\x00'*100, 32, 0x1000, 0x2000, iat_ptrs)
    assert 0x1000 in result

@patch('distorm3.DecomposeGenerator')
def test_indirect_register_call(mock_decompose):
    # Simulate a CALL through a register (stolen bytes technique)
    reg_op = MagicMock(type='Register')
    reg_op_str = "EAX"
    
    call_op = MagicMock(valid=True, mnemonic="CALL", operands=[reg_op])
    mov_op = MagicMock(valid=True, mnemonic="MOV", operands=[MagicMock(type='Register', disp=0), MagicMock(type='AbsoluteMemoryAddress', disp=0x1200)])
    
    mock_decompose.side_effect = [[mov_op], [call_op]]
    
    iat_ptrs = []
    result = rebuild_iat(0, b'\x00'*100, 32, 0x1000, 0x2000, iat_ptrs)
    assert 0x1200 in result

@patch('distorm3.DecomposeGenerator')
def test_push_ret_obfuscation(mock_decompose):
    # Simulate PUSH followed by RET (push-ret obfuscation)
    push_op = MagicMock(valid=True, mnemonic="PUSH", operands=[MagicMock(type='AbsoluteMemoryAddress', disp=0x1300)])
    ret_op = MagicMock(valid=True, mnemonic="RET")
    
    mock_decompose.side_effect = [[push_op], [ret_op]]
    
    iat_ptrs = []
    result = rebuild_iat(0, b'\x00'*100, 32, 0x1000, 0x2000, iat_ptrs)
    assert 0x1300 in result

@patch('distorm3.DecomposeGenerator')
def test_seh_based_redirection(mock_decompose):
    # Simulate SEH-based obfuscation using PUSH followed by RET
    push_op = MagicMock(valid=True, mnemonic="PUSH", operands=[MagicMock(type='Immediate', imm=0x1400)])
    ret_op = MagicMock(valid=True, mnemonic="RET")
    
    mock_decompose.side_effect = [[push_op], [ret_op]]
    
    iat_ptrs = []
    result = rebuild_iat(0, b'\x00'*100, 32, 0x1000, 0x2000, iat_ptrs)
    assert 0x1400 in result

@patch('distorm3.DecomposeGenerator')
def test_rop_redirection(mock_decompose):
    # Simulate ROP redirection (POP RET sequence)
    pop_op = MagicMock(valid=True, mnemonic="POP", operands=[MagicMock(type='Register')])
    ret_op = MagicMock(valid=True, mnemonic="RET")
    mov_op = MagicMock(valid=True, mnemonic="MOV", operands=[MagicMock(type='Register', disp=0), MagicMock(type='AbsoluteMemoryAddress', disp=0x1500)])
    
    mock_decompose.side_effect = [[mov_op], [pop_op], [ret_op]]
    
    iat_ptrs = []
    result = rebuild_iat(0, b'\x00'*100, 32, 0x1000, 0x2000, iat_ptrs)
    assert 0x1500 in result

