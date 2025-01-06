"""
@license:      Donated under Volatility Foundation, Inc. Individual Contributor Licensing Agreement
@authors:      Kartik N. Iyer | Parag H. Rughani 
@contact:      kartikiyerr23@proton.me | parag.rughani@gmail.com
"""

import logging
import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
import argparse
import contextlib
import datetime
import logging
import ntpath
import struct
import glob
import yara
import re
import os
from typing import List, Optional, Type

from volatility3.framework import constants, exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import conversion, format_hints
from volatility3.framework.symbols import intermed
from volatility3.framework.symbols.windows.extensions import pe
from volatility3.plugins import timeliner
from volatility3.plugins.windows import info, pslist, psscan

vollog = logging.getLogger(__name__)

class TLSCheck(interfaces.plugins.PluginInterface):
    
    _required_framework_version = (2, 0, 0)
    _version = (2, 0, 1)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel",
                description="Windows kernel",
                architectures=["Intel32", "Intel64"],
            ),
            requirements.VersionRequirement(
                name="pslist", component=pslist.PsList, version=(2, 0, 0)
            ),
            requirements.VersionRequirement(
                name="info", component=info.Info, version=(1, 0, 0)
            ),
            requirements.ListRequirement(
                name="pid",
                element_type=int,
                description="Process IDs to include (all other processes are excluded)",
                optional=True,
            ),
            requirements.IntRequirement(
                name="disasm-bytes",
                description="Bytes to disassemble (Default: 64)",
                default=64,
                optional=True
            ),
            requirements.BooleanRequirement(
                name="scan-suspicious",
                description="Displays suspicious TLS Callback instruction(s) along with the disassembly",
                default=False,
                optional=True
            ),
            requirements.StringRequirement(
                name="regex",
                description="Custom regex pattern to match against disassembled instructions",
                optional=True
            ),
            requirements.StringRequirement(
                name="yara-file",
                description="Path to custom YARA rule file",
                optional=True
            )
        ]

    #-----------------------------------------------
    #              TLSCheck._generator                            
    #-----------------------------------------------

    def _generator(self, procs):
        pe_table_name = intermed.IntermediateSymbolTable.create(
            self.context, self.config_path, "windows", "pe", class_types=pe.class_types
        )

        kernel = self.context.modules[self.config["kernel"]]

        kuser = info.Info.get_kuser_structure(
            self.context, kernel.layer_name, kernel.symbol_table_name
        )
        nt_major_version = int(kuser.NtMajorVersion)
        nt_minor_version = int(kuser.NtMinorVersion)
        dll_load_time_field = (nt_major_version > 6) or (
            nt_major_version == 6 and nt_minor_version >= 1
        )

        for proc in procs:
            try:
                proc_id = proc.UniqueProcessId
                parent_proc_id = proc.InheritedFromUniqueProcessId
                proc_name = proc.ImageFileName.cast("string", max_length=proc.ImageFileName.vol.count, errors="replace")
                proc_layer_name = proc.add_process_layer()
                passed_id = self.config["pid"]
                proc_offset = proc.vol.offset
                proc_offset_hex = hex(proc_offset)

                # Initialize status flag
                status = True

                exe_file_obj = self.process_dump(
                    self.context,
                    kernel.symbol_table_name,
                    pe_table_name,
                    proc,
                    self.open,
                )

                # Adding file existence and validity check
                if not exe_file_obj or not os.path.exists(exe_file_obj):
                    self.cleanup_dump_files(proc_name, proc_id)
                    continue

                exe_file = exe_file_obj
                
                try:
                    # Open PE file
                    pe1 = pefile.PE(exe_file, fast_load=True)
                    pe1.parse_data_directories()

                    # Determine address size based on PE characteristics
                    is_64bit = pe1.FILE_HEADER.Machine == 0x8664  # IMAGE_FILE_MACHINE_AMD64
                    architecture = "x64" if is_64bit else "x86"

                    # Load the PE file
                    vollog.info(f"[INFO] Loading the PE file: {exe_file}")
                    
                    pe_obj = pefile.PE(exe_file)

                    try:
                        # Access the Process Environment Block (PEB)
                        peb = self.context.object(
                            kernel.symbol_table_name + constants.BANG + "_PEB",
                            layer_name=proc_layer_name,
                            offset=proc.Peb
                        )
                        
                        # Retrieve the full path from ProcessParameters
                        full_path = peb.ProcessParameters.ImagePathName.get_string()
                    except Exception:
                        full_path = "Unable to retrieve path"

                    # Fetch NT Header address and Image Base address
                    nt_header_address = pe_obj.DOS_HEADER.e_lfanew
                    image_base = pe_obj.OPTIONAL_HEADER.ImageBase

                    # Access Data Directory from Optional Header
                    data_directory = pe_obj.OPTIONAL_HEADER.DATA_DIRECTORY

                    # Check for TLS Directory (10th entry)
                    if len(data_directory) < 10:
                        self.cleanup_dump_files(proc_name, proc_id)
                        continue

                    tls_directory_entry = data_directory[9]  # TLS Directory entry is at index 9
                    tls_rva = tls_directory_entry.VirtualAddress
                    tls_rva_hex = hex(tls_rva)

                    # checking if the rva of tls is 0 (non-existing TLS)
                    if tls_rva == 0:
                        status = False

                    if not status:
                        self.cleanup_dump_files(proc_name, proc_id)
                        continue

                    yield(
                        0,
                        (
                            proc_id,
                            parent_proc_id,
                            proc_name,
                            proc_offset_hex,
                            tls_rva_hex,
                            architecture,
                            full_path,
                        ),
                    )
                    
                    if is_64bit:
                        self.tls_for_64(exe_file, pe1, proc_name, proc_id)
                    else:
                        self.tls_for_32(tls_rva, pe_obj, exe_file, image_base, proc_name, proc_id)

                except Exception as e:
                    vollog.error(f"Error processing PE file: {str(e)}")
                finally:
                    self.cleanup_dump_files(proc_name, proc_id)

            except Exception as e:
                vollog.error(f"Error processing process {getattr(proc, 'UniqueProcessId', 'Unknown')}: {str(e)}")
                if 'proc_name' in locals() and 'proc_id' in locals():
                    self.cleanup_dump_files(proc_name, proc_id)

        # Final cleanup after all processing
        self.cleanup_dump_files()

    #-----------------------------------------------
    #             TLSCheck.process_dump                            
    #-----------------------------------------------

    def process_dump(
        cls,
        context: interfaces.context.ContextInterface,
        kernel_table_name: str,
        pe_table_name: str,
        proc: interfaces.objects.ObjectInterface,
        open_method: Type[interfaces.plugins.FileHandlerInterface],
    ) -> interfaces.plugins.FileHandlerInterface:
        """Extracts the complete data for a process as a FileHandlerInterface"""
        file_handle = None
        proc_id = "Invalid process object"
        process_name = None
        try:
            proc_id = proc.UniqueProcessId
            proc_layer_name = proc.add_process_layer()
            
            # Sanitize process name more rigorously
            process_name = re.sub(r'[^a-zA-Z0-9_.-]', '', 
                proc.ImageFileName.cast(
                    "string",
                    max_length=proc.ImageFileName.vol.count,
                    errors="replace",
                )[:20])
            
            peb = context.object(
                kernel_table_name + constants.BANG + "_PEB",
                layer_name=proc_layer_name,
                offset=proc.Peb,
            )

            dos_header = context.object(
                pe_table_name + constants.BANG + "_IMAGE_DOS_HEADER",
                offset=peb.ImageBaseAddress,
                layer_name=proc_layer_name,
            )

            filename = f"{proc_id}.{process_name}.{peb.ImageBaseAddress:#x}.dmp"
            sanitized_filename = open_method.sanitize_filename(filename)
            
            if not sanitized_filename:
                vollog.error(f"Could not generate valid filename for process {proc_id}")
                cls.cleanup_dump_files(process_name, proc_id)
                return None

            file_handle = open_method(sanitized_filename)

            for offset, data in dos_header.reconstruct():
                file_handle.seek(offset)
                file_handle.write(data)

            return sanitized_filename
                
        except Exception as excp:
            vollog.debug(f"Unable to dump PE with pid {proc_id}: {excp}")
            if process_name:
                cls.cleanup_dump_files(process_name, proc_id)
            return None

    #-----------------------------------------------
    #          TLSCheck.cleanup_dump_files                            
    #-----------------------------------------------

    def cleanup_dump_files(self, process_name=None, pid=None):
        """Centralized cleanup function for .dmp files"""
        try:
            # Pattern to match dump files
            pattern = f"{pid}.{process_name}.*" if pid and process_name else "*.*.*.*"
            dump_files = glob.glob(pattern)
            
            if dump_files:
                vollog.info(f"Cleaning up dump files matching pattern: {pattern}")
                for file in dump_files:
                    try:
                        if os.path.exists(file):
                            os.remove(file)
                            vollog.debug(f"Successfully removed: {file}")
                    except (PermissionError, OSError) as e:
                        vollog.warning(f"Failed to remove {file}: {str(e)}")
        except Exception as e:
            vollog.error(f"Error during cleanup: {str(e)}")

    #-----------------------------------------------
    #                     YARA                            
    #-----------------------------------------------

    def compile_yara_rules(self, rule_path):
        """Compile YARA rules from the given file."""
        try:
            if not os.path.exists(rule_path):
                vollog.error(f"YARA rule file not found: {rule_path}")
                return None
            return yara.compile(filepath=rule_path)
        except Exception as e:
            vollog.error(f"Error compiling YARA rules: {str(e)}")
            return None

    def scan_with_yara(self, rules, data, offset=0):
        """Scan data with compiled YARA rules."""
        try:
            matches = rules.match(data=data)
            results = []
            
            # Read the original YARA rule file to extract matching lines
            with open(self.config.get("yara-file"), 'r') as rule_file:
                rule_lines = rule_file.readlines()
                
            for match in matches:
                # Find and extract the rule definition line
                rule_line = ""
                for i, line in enumerate(rule_lines):
                    if f"rule {match.rule}" in line:
                        rule_line = line.strip()
                        break
                        
                results.append({
                    'rule': match.rule,
                    'rule_line': rule_line
                })
            return results
        except Exception as e:
            vollog.error(f"Error during YARA scan: {str(e)}")
            return []

    def process_yara_matches(self, matches, current_address):
        """Process and format YARA matches."""
        suspicious_instructions = []
        for rule_name, strings in matches:
            for _, offset, string in strings:
                suspicious_instructions.append({
                    'address': hex(current_address + offset),
                    'rule': rule_name,
                    'matched_bytes': string.hex() if isinstance(string, bytes) else string
                })
        return suspicious_instructions

    #-----------------------------------------------
    #             DETECTING SUSPICIONS                            
    #-----------------------------------------------

    def match_instruction_patterns(self, instructions, custom_regex=None):
        class InstructionContext:
            def __init__(self, instruction, index, instructions):
                self.instruction = instruction
                self.index = index
                self.full_text = f"{instruction.mnemonic} {instruction.op_str}"
                # Extend context window
                self.prev = instructions[index - 1] if index > 0 else None
                self.next = instructions[index + 1] if index < len(instructions) - 1 else None
                self.prev2 = instructions[index - 2] if index > 1 else None
                self.next2 = instructions[index + 2] if index < len(instructions) - 2 else None
                # Track instruction block context
                self.block_start = self._find_block_start(instructions, index)
                
            def _find_block_start(self, instructions, current_idx):
                """Find the start of current code block by looking for branch targets"""
                for i in range(current_idx - 1, max(-1, current_idx - 20), -1):
                    if instructions[i].mnemonic in ['ret', 'jmp', 'je', 'jne', 'ja', 'jb']:
                        return i + 1
                return current_idx

        def is_tls_callback_context(ctx):
            """Detect if we're in a TLS callback context"""
            if not ctx.prev2 or not ctx.prev:
                return False
                
            # Look for TLS callback patterns
            prev2_text = f"{ctx.prev2.mnemonic} {ctx.prev2.op_str}".lower()
            prev_text = f"{ctx.prev.mnemonic} {ctx.prev.op_str}".lower()
            
            return (
                # Common TLS callback start patterns
                (prev2_text.startswith('cmp') and 'edx' in prev2_text and
                 prev_text.startswith(('je', 'jne'))) or
                # Check for gs:[0x58] access (TEB access)
                ('gs:[0x58]' in prev_text) or
                # Look for TLS reason code checks
                (prev2_text.startswith('cmp') and '2' in prev2_text)
            )

        def is_legitimate_memory_context(ctx):
            """Check if memory access is in a legitimate context"""
            curr_text = ctx.full_text.lower()
            
            # Skip if in TLS callback
            if is_tls_callback_context(ctx):
                return True
                
            # Check for legitimate memory access patterns
            legitimate_patterns = [
                # Standard string operations
                lambda t: any(x in t for x in ['movs', 'cmps', 'scas', 'stos']),
                # Array indexing with known offsets
                lambda t: re.match(r'mov.*\[(e|r)[abcd]x\s*\+\s*(e|r)[abcd]x\s*\*\s*[1248]\s*\+\s*[0-9a-fx]+\]', t),
                # Structured exception handling
                lambda t: 'fs:[0x0]' in t or 'fs:[0x30]' in t,
                # Stack frame access
                lambda t: re.search(r'\[(e|r)bp\s*[+-]\s*[0-9a-fx]+\]', t)
            ]
            
            return any(pattern(curr_text) for pattern in legitimate_patterns)

        def is_legitimate_control_flow(ctx):
            """Check if control flow modification is legitimate"""
            curr_text = ctx.full_text.lower()
            
            # Function return checks
            if curr_text.startswith('ret'):
                # Verify we're at the end of a function
                if ctx.prev and ctx.prev.mnemonic.startswith(('pop', 'leave')):
                    return True
                    
            # Indirect calls/jumps
            if curr_text.startswith(('call', 'jmp')):
                # Check if it's a jump table implementation
                if ctx.prev and 'lea' in f"{ctx.prev.mnemonic} {ctx.prev.op_str}".lower():
                    return True
                # Check if it's a virtual function call
                if re.search(r'(call|jmp)\s+qword\s+ptr\s+\[(e|r)[abcd]x\s*\+\s*[0-9a-fx]+\]', curr_text):
                    return True
                    
            return False

        def detect_nop_sled(instructions, start_idx, min_length=5):
            """Detect NOP sleds and other padding instructions used for exploit payload alignment"""
            nop_equivalents = {
                'nop',
                'xchg eax, eax',
                'mov edi, edi',
                'lea nop',
                'data16 nop'
            }
            
            count = 0
            idx = start_idx
            
            while idx < len(instructions):
                instr = instructions[idx]
                if (f"{instr.mnemonic} {instr.op_str}".lower() in nop_equivalents or
                    instr.mnemonic == 'nop'):
                    count += 1
                else:
                    break
                idx += 1
                
            return count >= min_length

        def detect_stack_string(ctx, window_size=5):
            """Detect stack string construction - common in obfuscated malware"""
            if not ctx.prev or not ctx.next:
                return False
                
            push_count = 0
            for i in range(max(0, ctx.index - window_size), min(len(instructions), ctx.index + window_size)):
                instr = instructions[i]
                if instr.mnemonic == 'push' and any(x in instr.op_str for x in ['0x', 'h']):
                    push_count += 1
                    
            return push_count >= 3

        def detect_api_hashing(ctx):
            """Detect potential API hashing techniques used to obscure imports"""
            if not ctx.prev or not ctx.next:
                return False
                
            # Look for patterns like: xor/rol/ror operations followed by function pointer dereferencing
            hashing_sequence = (
                ctx.prev and ctx.prev.mnemonic in ('xor', 'rol', 'ror') and
                ctx.instruction.mnemonic in ('call', 'jmp') and
                '[' in ctx.instruction.op_str
            )
            
            return hashing_sequence

        def analyze_instruction(ctx):
            """Enhanced instruction analysis with better context awareness and additional checks"""
            curr_text = ctx.full_text.lower()
            
            # Skip legitimate contexts
            if is_legitimate_memory_context(ctx) or is_legitimate_control_flow(ctx):
                return None

            # Enhanced suspicious pattern detection
            suspicious_patterns = [
                # Existing patterns
                (r'mov.*\[(e|r)[abcd]x\s*\+\s*(e|r)[abcd]x\]', 
                 'Suspicious dynamic memory access',
                 lambda ctx: not is_legitimate_memory_context(ctx)),
                
                (r'(call|jmp)\s+(e|r)[abcd]x',
                 'Direct register control flow',
                 lambda ctx: not is_legitimate_control_flow(ctx)),
                
                (r'(add|sub)\s+(esp|rsp),\s*0x[0-9a-f]{3,}',
                 'Large stack adjustment',
                 lambda ctx: int(re.search(r'0x([0-9a-f]+)', curr_text).group(1), 16) > 0x1000),
                
                # New patterns for additional suspicious activities
                (r'int\s+3',
                 'Debugger detection (int 3)',
                 lambda ctx: True),
                
                (r'(in|out)\s+',
                 'Direct port access',
                 lambda ctx: True),
                
                (r'pushf|popf',
                 'Flag register manipulation',
                 lambda ctx: not is_legitimate_control_flow(ctx)),
                
                (r'(str|sldt|sgdt|sidt|smsw)',
                 'System table register access',
                 lambda ctx: True),
                
                (r'(rdtsc|rdtscp|rdrand|rdseed)',
                 'Hardware-based anti-debug/VM detection',
                 lambda ctx: True),
                
                (r'(aaa|aad|aam|aas|daa|das)',
                 'Rare arithmetic instructions (possible obfuscation)',
                 lambda ctx: True),
                
                (r'(fld|fst|fstp)\s+',
                 'FPU instructions in non-math context',
                 lambda ctx: not any(x in curr_text for x in ['float', 'double', 'real'])),
                
                (r'(prefetch|prefetchw|prefetchnta)',
                 'Cache manipulation instructions',
                 lambda ctx: True),
                
                (r'(lock|rep|repe|repne|repz|repnz)\s+',
                 'Instruction prefix abuse',
                 lambda ctx: not any(x in curr_text for x in ['movs', 'stos', 'cmps', 'scas'])),
                
                (r'(and|or|xor)\s+byte\s+ptr',
                 'Byte-level manipulation of memory',
                 lambda ctx: not is_legitimate_memory_context(ctx)),
                
                (r'(shl|shr|rol|ror)\s+.*,\s*cl',
                 'Dynamic bit shifting',
                 lambda ctx: True)
            ]

            results = []
            
            # Check all suspicious patterns
            for pattern, description, condition in suspicious_patterns:
                if re.search(pattern, curr_text) and condition(ctx):
                    results.append(f"{curr_text} - {description}")
            
            # Check for NOP sled
            if detect_nop_sled(instructions, ctx.index):
                results.append(f"NOP sled detected starting at: {curr_text}")
            
            # Check for stack string construction
            if detect_stack_string(ctx):
                results.append(f"Possible stack string construction at: {curr_text}")
            
            # Check for API hashing
            if detect_api_hashing(ctx):
                results.append(f"Possible API hashing technique at: {curr_text}")

            return results[0] if results else None

        results = {
            'suspicious_instructions': [],
            'detection_context': {}
        }

        # Analyze each instruction
        for idx, instruction in enumerate(instructions):
            ctx = InstructionContext(instruction, idx, instructions)
            
            # Main analysis
            result = analyze_instruction(ctx)
            if result:
                # Store additional context for analysis
                results['detection_context'][idx] = {
                    'is_tls_callback': is_tls_callback_context(ctx),
                    'is_legitimate_memory': is_legitimate_memory_context(ctx),
                    'is_legitimate_control_flow': is_legitimate_control_flow(ctx),
                    'instruction_block_start': ctx.block_start
                }
                results['suspicious_instructions'].append(result)
            
            # Custom regex matching with context
            if custom_regex:
                try:
                    if re.search(custom_regex, ctx.full_text, re.IGNORECASE):
                        # Only add if not in legitimate context
                        if not is_tls_callback_context(ctx) and not is_legitimate_memory_context(ctx):
                            results['suspicious_instructions'].append(f"Custom match: {ctx.full_text}")
                except re.error:
                    vollog.error(f"Invalid regex pattern: {custom_regex}")

        return results

    #-----------------------------------------------
    #              TLSCheck.tls_for_64                            
    #-----------------------------------------------

    def tls_for_64(self, exe_file_64, pe1, proc_name, proc_id):
        try:
            # Getting Image Base
            image_base = pe1.OPTIONAL_HEADER.ImageBase
            
            # Check for TLS Directory
            if not hasattr(pe1, 'DIRECTORY_ENTRY_TLS'):
                vollog.info("No TLS directory found.")
                self.cleanup_dump_files(proc_name, proc_id)
                return None
            
            tls_struct = pe1.DIRECTORY_ENTRY_TLS
            
            # Safely get AddressOfCallBacks
            if not hasattr(tls_struct.struct, 'AddressOfCallBacks'):
                print()
                vollog.info("----> No AddressOfCallBacks found.")
                self.cleanup_dump_files(proc_name, proc_id)
                return None
            
            tls_aoc = tls_struct.struct.AddressOfCallBacks
            
            # More robust RVA calculation
            last_rva = tls_aoc - image_base
            
            # Find the section containing the RVA
            closest_section = None
            for section in pe1.sections:
                if (section.VirtualAddress <= last_rva < 
                    section.VirtualAddress + section.Misc_VirtualSize):
                    closest_section = section
                    break
            
            if not closest_section:
                print("\n----> The process has a non-empty TLS callback table, but no TLS callback procedures could be located within the process.")
                self.cleanup_dump_files(proc_name, proc_id)
                return None
            
            # Calculating file offset
            file_offset = (last_rva - closest_section.VirtualAddress) + closest_section.PointerToRawData
            
            # Read callbacks
            with open(exe_file_64, "rb") as f:
                f.seek(file_offset)
                callback_address_bytes = f.read(8)
                callback_address = int.from_bytes(callback_address_bytes, "little")
                
                if callback_address == 0:
                    vollog.info("----> No valid TLS callback found.")
                    self.cleanup_dump_files(proc_name, proc_id)
                    return None
                
                callback_rva = callback_address - image_base
                
                callback_section = None
                for section in pe1.sections:
                    if (section.VirtualAddress <= callback_rva < 
                        section.VirtualAddress + section.Misc_VirtualSize):
                        callback_section = section
                        break
                
                if not callback_section:
                    vollog.error("----> Could not find section for callback.")
                    self.cleanup_dump_files(proc_name, proc_id)
                    return None
                
                self.disassemble_bytes_at_address64(
                    exe_file_64, 
                    callback_address,
                    image_base,
                    proc_name,
                    callback_rva,
                    proc_id
                )
                
                self.cleanup_dump_files(proc_name, proc_id)
        
        except Exception as e:
            vollog.error(f"----> Error processing 64-bit TLS: {str(e)}")
            self.cleanup_dump_files(proc_name, proc_id)
            return None

    #-----------------------------------------------
    #             TLSCheck.tls_for_32                            
    #-----------------------------------------------

    def tls_for_32(self, tls_rva, pe, exe_file, image_base, proc_name, pid):
        """Process the PE file and fetch TLS last address with disassembly."""
        try:
            hex_tls_rva = hex(tls_rva)
            tls_offset = self.rva_to_file_offset(pe, tls_rva)

            if tls_offset is not None:
                vollog.info(f"[INFO] TLS Directory File Offset: 0x{tls_offset:X}")

                with open(exe_file, "rb") as f:
                    f.seek(tls_offset + 12)  
                    address_bytes = f.read(4)

                    last_address = int.from_bytes(address_bytes, "little")
                    last_rva = last_address - image_base

                    closest_section = self.find_closest_section(pe, last_rva)
                    if closest_section:
                        pointer_to_raw_data = closest_section.PointerToRawData
                        file_offset = last_rva - closest_section.VirtualAddress + pointer_to_raw_data
                        file_offset = abs(file_offset)

                        with open(exe_file, "rb") as f2:
                            f2.seek(file_offset)
                            disassembled_bytes = f2.read(16)
                            first_4_bytes = disassembled_bytes[:4]
                            first_4_bytes_value = int.from_bytes(first_4_bytes, "little")

                            self.disassemble_bytes_at_address32(
                                exe_file, 
                                first_4_bytes_value, 
                                image_base, 
                                proc_name,
                                pid
                            )
                        
                        self.cleanup_dump_files(proc_name, pid)
                        return True
                    else:
                        print("\n----> The process has a non-empty TLS callback table, but no TLS callback procedures could be located within the process.")
                        self.cleanup_dump_files(proc_name, pid)
                        return False
            else:
                print("\n\n----> No TLS exists for this process.")
                self.cleanup_dump_files(proc_name, pid)
                return False

        except Exception as e:
            vollog.error(f"\n[ERROR] Error during PE file processing: {str(e)}")
            self.cleanup_dump_files(proc_name, pid)
            return False

    #-----------------------------------------------
    #              RVA-TO-FILE-OFFSET                            
    #-----------------------------------------------

    def rva_to_file_offset(self, pe, rva):
        """Convert RVA to File Offset."""
        for section in pe.sections:
            vollog.debug(f"[DEBUG] Checking section: {section.Name.decode().strip()} - "
                         f"VirtualAddress: 0x{section.VirtualAddress:X}, Size: 0x{section.Misc_VirtualSize:X}")
            if section.VirtualAddress <= rva < (section.VirtualAddress + section.Misc_VirtualSize):
                file_offset = section.PointerToRawData + (rva - section.VirtualAddress)
                vollog.debug(f"[DEBUG] PointerToRawData: 0x{section.PointerToRawData:X}")
                return file_offset
        return None

    def find_closest_section(self, pe, rva):
        """Find the closest section to the given RVA."""
        closest_section = None
        min_diff = float('inf') 
        for section in pe.sections:
            section_rva = section.VirtualAddress
            diff = abs(rva - section_rva)
            if diff < min_diff:
                min_diff = diff
                closest_section = section
        return closest_section

    def format_hex_dump(self, code_bytes, width=16):
        """Format bytes as hex dump with ASCII representation."""
        result = []
        for i in range(0, len(code_bytes), width):
            chunk = code_bytes[i:i + width]
            # Hex part
            hex_line = ' '.join(f'{b:02x}' for b in chunk)
            # ASCII part
            ascii_line = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            # Pad hex part if needed
            hex_line = hex_line.ljust(width * 3 - 1)
            result.append(f"{hex_line} {ascii_line}")
        return result

    #-----------------------------------------------
    #           DISASSEMBLER FOR 32-BIT                            
    #-----------------------------------------------

    def disassemble_bytes_at_address32(self, exe_file, address, image_base, proc_name, pid):
        cyan = "\033[36m"
        yellow = "\033[93m"
        red = "\033[31m"
        blue = "\033[34m"
        green = "\033[32m"
        disable = "\033[0m"

        bytes_to_disassemble = self.config.get("disasm-bytes", 64)
        custom_regex = self.config.get("regex", None)
        show_suspicious = self.config.get("scan-suspicious", False)
        yara_rule_path = self.config.get("yara-file", None)
        
        rva_address = address - image_base

        try:
            with open(exe_file, "rb") as f:
                pe = pefile.PE(exe_file)
                offset = self.rva_to_file_offset(pe, rva_address)
                
                if offset is None:
                    return

                f.seek(offset)
                code_bytes = f.read(bytes_to_disassemble)
                
                # Print process information
                print("\n\n----------------------------------------------------------------")
                print(f"{cyan}TLS-Callback Found in Process: {proc_name} (PID: {pid}){disable}")
                print(f"Address range: {hex(address)} - {hex(address + bytes_to_disassemble)}")
                print("----------------------------------------------------------------")
                
                # Print hex dump
                hex_dump = self.format_hex_dump(code_bytes)
                for line in hex_dump:
                    print(line)

                # Disassemble and print instructions
                disassembler = Cs(CS_ARCH_X86, CS_MODE_32)
                current_address = address
                
                print("Disassembly:")
                for insn in disassembler.disasm(code_bytes, rva_address):
                    if insn.mnemonic == 'ret' and bytes_to_disassemble == 64:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                        break
                    print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                    current_address += insn.size

                # Existing suspicious instruction detection
                detection_results = self.match_instruction_patterns(
                    list(disassembler.disasm(code_bytes, rva_address)), 
                    custom_regex
                )
                
                if show_suspicious and detection_results['suspicious_instructions']:
                    print("----------------------------------------------------------------")
                    print(f"{yellow}[*] Potentially Suspicious Instruction(s) Identified:{disable}\n")
                    for susp_inst in detection_results['suspicious_instructions']:
                        print(f"{red}[SUSPICIOUS]:{disable} {susp_inst}")
                
                if custom_regex and detection_results.get('custom_matched_instructions'):
                    print("----------------------------------------------------------------")
                    print(f"{yellow}[*] Found matching instruction(s):{disable}")
                    for matched_inst in detection_results['custom_matched_instructions']:
                        print(f"{green}[SUSPICIOUS]: {matched_inst}{disable}")

                # YARA scanning
                if yara_rule_path:
                    rules = self.compile_yara_rules(yara_rule_path)
                    if rules:
                        yara_matches = self.scan_with_yara(rules, code_bytes)
                        if yara_matches:
                            print("----------------------------------------------------------------")
                            print("\n" + yellow + "[*] YARA Rule Matches:" + disable)
                            for match in yara_matches:
                                print(f"{red}[YARA Match] Rule: {match['rule']}{disable}")
                                # print(f"Rule definition: {match['rule_line']}")
                
                print("----------------------------------------------------------------")

        except Exception as e:
            vollog.error(f"[ERROR] Disassembly error: {str(e)}")

    #-----------------------------------------------
    #            DISASSEMBLER FOR 64-BIT                             
    #-----------------------------------------------

    def disassemble_bytes_at_address64(self, exe_file, address, image_base, proc_name, callback_rva, pid):
        cyan = "\033[36m"
        yellow = "\033[93m"
        green = "\033[32m"
        blue = "\033[34m"
        red = "\033[31m"
        disable = "\033[0m"

        bytes_to_disassemble = self.config.get("disasm-bytes", 64)
        custom_regex = self.config.get("regex", None)
        show_suspicious = self.config.get("scan-suspicious", False)
        yara_rule_path = self.config.get("yara-file", None)
        
        rva_address = address - image_base

        try:
            with open(exe_file, "rb") as f:
                pe = pefile.PE(exe_file)
                offset = self.rva_to_file_offset(pe, rva_address)
                
                if offset is None:
                    vollog.error("[ERROR] Could not convert RVA to offset for disassembly.")
                    return

                f.seek(offset)
                code_bytes = f.read(bytes_to_disassemble or 256)
                
                # Print process information
                print("\n\n----------------------------------------------------------------")
                print(f"{cyan}TLS-Callback Found in Process: {proc_name} (PID: {pid}){disable}")
                print(f"Address range: {hex(address)} - {hex(address + (bytes_to_disassemble or 256))}")
                print("----------------------------------------------------------------")
                
                # Print hex dump
                hex_dump = self.format_hex_dump(code_bytes)
                for line in hex_dump:
                    print(line)
                
                # Disassemble and print instructions
                disassembler = Cs(CS_ARCH_X86, CS_MODE_64)
                disassembler.detail = True
                current_address = address
                
                print("Disassembly:")
                collected_instructions = []
                for insn in disassembler.disasm(code_bytes, callback_rva):
                    if insn.mnemonic == 'ret' and bytes_to_disassemble == 64:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                        collected_instructions.append(insn)
                        break
                    print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                    collected_instructions.append(insn)
                    current_address += insn.size

                # Existing suspicious instruction detection
                detection_results = self.match_instruction_patterns(collected_instructions, custom_regex)
                
                if show_suspicious and detection_results['suspicious_instructions']:
                    print("----------------------------------------------------------------")
                    print(f"{yellow}[*] Potentially Suspicious Instruction(s) Identified:{disable}\n")
                    for susp_inst in detection_results['suspicious_instructions']:
                        print(f"{green}[SUSPICIOUS]:{disable} {susp_inst}")
                
                if custom_regex and detection_results.get('custom_matched_instructions'):
                    print("----------------------------------------------------------------")
                    print(f"{yellow}[*] Found matching instruction(s):{disable}")
                    for matched_inst in detection_results['custom_matched_instructions']:
                        print(f"{green}[SUSPICIOUS]: {matched_inst}{disable}")

                # YARA scanning
                if yara_rule_path:
                    rules = self.compile_yara_rules(yara_rule_path)
                    if rules:
                        yara_matches = self.scan_with_yara(rules, code_bytes)
                        if yara_matches:
                            print("----------------------------------------------------------------")
                            print(f"{yellow}[*] YARA Rule Matches:{disable}")
                            for match in yara_matches:
                                print(f"{red}[YARA Match] Rule: {match['rule']}{disable}")
                                # print(f"Rule definition: {match['rule_line']}")
                
                print("----------------------------------------------------------------")

        except Exception as e:
            vollog.error(f"[ERROR] Disassembly error: {str(e)}")

    def run(self):
        filter_func = pslist.PsList.create_pid_filter(self.config.get("pid", None))
        kernel = self.context.modules[self.config["kernel"]]

        procs = pslist.PsList.list_processes(
            context=self.context,
            layer_name=kernel.layer_name,
            symbol_table=kernel.symbol_table_name,
            filter_func=filter_func,
        )

        return renderers.TreeGrid(
            [
                ("PID", int),
                ("PPID", int),
                ("Process Name", str),
                ("Offset(V)", str),
                ("TLS RVA(V)", str),
                ("Architecture", str),
                ("Path", str),
            ],
            self._generator(procs=procs),
        )

# Register the plugin
__all__ = ["TLSCheck"]
