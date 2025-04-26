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

    def match_instruction_patterns(self, instructions, pe=None, custom_regex=None):
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

        def detect_api_hashing(ctx):
            """Detect potential API hashing techniques used to obscure imports."""
            if not ctx.prev or not ctx.next:
                return False

            # Look for more specific hash calculation patterns
            # XOR/ROL/ROR operations followed by complex call/jmp patterns
            hashing_sequence = (
                ctx.prev and ctx.prev.mnemonic in ('xor', 'rol', 'ror', 'add', 'mul') and
                ctx.instruction.mnemonic in ('call', 'jmp') and
                '[' in ctx.instruction.op_str and
                not ('rip' in ctx.instruction.op_str)  # Exclude simple rip-relative calls
            )

            # More complex hashing sequence with multiple operations
            if not hashing_sequence and ctx.prev and ctx.prev2:
                # Look for hash calculation sequence: multiple arithmetic ops followed by call
                arithmetic_ops = ('xor', 'rol', 'ror', 'add', 'mul', 'sub', 'shl', 'shr')
                hashing_sequence = (
                    ctx.prev2.mnemonic in arithmetic_ops and
                    ctx.prev.mnemonic in arithmetic_ops and
                    ctx.instruction.mnemonic in ('call', 'jmp') and
                    not ctx.instruction.op_str.startswith('0x')  # Not a direct address
                )

            return hashing_sequence

        def calculate_crc32(api_name):
            """Calculate CRC32 hash for a given API name."""
            import zlib
            return zlib.crc32(api_name.encode()) & 0xFFFFFFFF

        def resolve_hashed_api(pe, target_hash):
            """Resolve a hashed API name from the DLL export table."""
            if not pe or not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                return None

            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                api_name = exp.name.decode() if exp.name else f"Ordinal_{exp.ordinal}"
                api_hash = calculate_crc32(api_name)
                if api_hash == target_hash:
                    return api_name
            return None

        def is_tls_callback_context(ctx):
            """Detect if we're in a TLS callback context with much higher accuracy"""
            if not ctx.prev2 or not ctx.prev:
                return False
                
            # Get full context - we need to analyze multiple instructions
            prev2_text = f"{ctx.prev2.mnemonic} {ctx.prev2.op_str}".lower()
            prev_text = f"{ctx.prev.mnemonic} {ctx.prev.op_str}".lower()
            curr_text = ctx.full_text.lower()
            
            # Build a complete context string for pattern matching
            context_text = f"{prev2_text} | {prev_text} | {curr_text}"
            
            # Define specific patterns for TLS callback detection
            tls_patterns = [
                # TLS reason code check (most reliable)
                r"cmp\s+edx,\s+(1|2|3).*jne",
                
                # TEB access with specific TLS patterns
                r"mov\s+.*gs:\[0x58\].*mov\s+r.d,\s+0x64",
                
                # Common TLS structure access pattern
                r"cmp\s+byte\s+ptr\s+\[.*\],\s+1.*je",
                
                # Thread data storage pattern specific to TLS
                r"gs:\[0x58\].*\[.*\+.*\*8\]",
            ]
            
            for pattern in tls_patterns:
                if re.search(pattern, context_text):
                    return True
                    
            # Check for TLS initialization pattern
            if ("cmp" in prev2_text and 
                ("edx, 1" in prev2_text or "edx, 2" in prev2_text or "edx, 3" in prev2_text) and
                "jne" in prev_text):
                return True
                
            # More specific TEB access pattern that's common in TLS callbacks
            if "gs:[0x58]" in context_text and "mov" in prev_text and re.search(r"jmp|je|jne", curr_text):
                return True
                
            return False

        def is_suspicious_memory_access(ctx):
            """Check if memory access is suspicious"""
            curr_text = ctx.full_text.lower()
            
            # Skip if in TLS callback context - this is expected
            if is_tls_callback_context(ctx):
                return False
                
            # Check for suspicious memory access patterns
            suspicious_patterns = [
                # Self-modifying code patterns - more specific
                lambda t: re.search(r'mov\s+byte\s+ptr\s+\[(e|r)ip.*\],\s+[^\]]+', t),
                
                # Writing specific opcodes that might indicate shellcode
                lambda t: re.search(r'mov.*\[.*\],\s*(0x90|0xcc|0xcd20|0xfeeb)', t),
                
                # Non-standard TEB access outside expected context
                lambda t: 'fs:[' in t and not any(addr in t for addr in ['0x30', '0x18', '0x0', '0x58']),
                
                # Stack spray patterns
                lambda t: re.search(r'mov\s+dword\s+ptr\s+\[(e|r)sp\s*\+\s*(e|r).*\],\s+0x[0-9a-f]{8}', t) and 
                          not re.search(r'mov\s+dword\s+ptr\s+\[(e|r)bp', t)
            ]
            
            # Exclude common legitimate patterns
            legitimate_patterns = [
                # Standard stack frame setup
                r"mov\s+\[rsp.*\],\s+r(bx|bp|di)",
                # String operation setup
                r"mov\s+byte\s+ptr\s+\[r(di|si|cx).*\]"
            ]
            
            for pattern in legitimate_patterns:
                if re.search(pattern, curr_text):
                    return False
                    
            return any(pattern(curr_text) for pattern in suspicious_patterns)

        def is_suspicious_control_flow(ctx):
            """Check if control flow modification is suspicious with better accuracy"""
            curr_text = ctx.full_text.lower()
            
            # Standard return from function is not suspicious
            if ctx.instruction.mnemonic == 'ret':
                # Skip flagging standard returns
                if ctx.prev and (
                    ctx.prev.mnemonic in ('pop', 'leave') or
                    (ctx.prev.mnemonic == 'add' and 'rsp' in ctx.prev.op_str) or
                    (ctx.prev.mnemonic == 'jne' and ctx.index > 0)  # Conditional return is normal
                ):
                    return False
                    
                # If there's nothing before the return, don't flag
                if not ctx.prev:
                    return False
                    
                # Check if this is an early return pattern (common in error handling)
                if ctx.prev and ctx.prev.mnemonic in ('xor', 'mov') and 'eax' in ctx.prev.op_str:
                    return False
                    
                # Only suspicious if it's an unexpected return
                return True
                
            # Indirect calls/jumps with suspicious patterns
            if ctx.instruction.mnemonic in ('call', 'jmp'):
                # JMP/CALL to register value without table context
                if re.match(r'(call|jmp)\s+(e|r)[abcdsi][xip]', curr_text):
                    # Check if we have a table index setup before this
                    if not (ctx.prev and 'lea' in f"{ctx.prev.mnemonic} {ctx.prev.op_str}".lower()):
                        return True
                
                # Suspicious memory location jumps
                if "[" in ctx.instruction.op_str:
                    # Skip well-known patterns like virtual function calls
                    if re.search(r'\[(e|r)[abcdsi][xip]\s*\+\s*(0x)?[0-9a-f]+\]', ctx.instruction.op_str):
                        return False
                        
                    # Skip import table calls
                    if "rip" in ctx.instruction.op_str:
                        return False
                        
                    # Flag other indirect jumps
                    if "*" in ctx.instruction.op_str or "+" in ctx.instruction.op_str:
                        return True
            
            return False

        def detect_stack_string_construction(ctx):
            """Detect stack string construction techniques"""
            if not ctx.prev or not ctx.next:
                return False
                
            curr_text = ctx.full_text.lower()
            prev_text = f"{ctx.prev.mnemonic} {ctx.prev.op_str}".lower()
            
            # Check for consecutive push/mov patterns that construct strings
            
            # Pattern 1: Direct push of ASCII/UTF values
            if (ctx.instruction.mnemonic == 'push' and 
                ctx.prev.mnemonic == 'push' and
                re.match(r'push\s+(0x[0-9a-f]{2,8}|\'.\')$', curr_text)):
                
                # Try to extract printable characters from push value
                try:
                    if ctx.instruction.op_str.startswith('0x'):
                        value = int(ctx.instruction.op_str, 16)
                        # Convert to bytes in little-endian and check for printable chars
                        bytes_val = value.to_bytes((value.bit_length() + 7) // 8, 'little')
                        if any(chr(b).isprintable() and chr(b) not in '\x00\xff' for b in bytes_val):
                            return True
                except (ValueError, OverflowError):
                    pass
            
            # Pattern 2: Byte-by-byte construction with mov
            if (ctx.instruction.mnemonic == 'mov' and 'byte ptr' in curr_text and
                ctx.prev.mnemonic == 'mov' and 'byte ptr' in prev_text):
                
                # Extract offsets to detect sequential byte writes
                curr_offset_match = re.search(r'\[(r[bs]p|esp|ebp)([+-]0x[0-9a-f]+)\]', curr_text)
                prev_offset_match = re.search(r'\[(r[bs]p|esp|ebp)([+-]0x[0-9a-f]+)\]', prev_text)
                
                if curr_offset_match and prev_offset_match:
                    # Check if using same base register
                    if curr_offset_match.group(1) == prev_offset_match.group(1):
                        curr_offset = int(curr_offset_match.group(2), 16) if curr_offset_match.group(2).startswith('+') else int(curr_offset_match.group(2), 16)
                        prev_offset = int(prev_offset_match.group(2), 16) if prev_offset_match.group(2).startswith('+') else int(prev_offset_match.group(2), 16)
                        
                        # Look for sequential or nearby offsets (allow small gaps)
                        if abs(curr_offset - prev_offset) <= 4:
                            # Check if immediate values are printable ASCII
                            value_match = re.search(r',\s*(0x[0-9a-f]+|\'.\')(\s|$)', curr_text)
                            if value_match:
                                value = value_match.group(1)
                                if value.startswith("'"):  # Character literal
                                    return True
                                else:
                                    try:
                                        byte_val = int(value, 16) & 0xFF
                                        if byte_val >= 0x20 and byte_val <= 0x7E:  # Printable ASCII
                                            return True
                                    except ValueError:
                                        pass
            
            # Pattern 3: Stack string constructed with xor obfuscation
            if (ctx.instruction.mnemonic == 'xor' and 
                'byte ptr' in curr_text and 
                re.match(r'xor\s+byte\s+ptr\s+\[(r[bs]p|esp|ebp)([+-]0x[0-9a-f]+)\]', curr_text) and
                ctx.prev.mnemonic in ('mov', 'xor') and 
                'byte ptr' in prev_text):
                
                # Check that we're working with the same region of stack memory
                curr_offset_match = re.search(r'\[(r[bs]p|esp|ebp)([+-]0x[0-9a-f]+)\]', curr_text)
                prev_offset_match = re.search(r'\[(r[bs]p|esp|ebp)([+-]0x[0-9a-f]+)\]', prev_text)
                
                if curr_offset_match and prev_offset_match:
                    if curr_offset_match.group(1) == prev_offset_match.group(1):
                        return True
            
            return False
            
        def detect_nop_sled(instructions, start_idx, min_length=5):
            """Detect NOP sleds with improved accuracy, excluding function alignment NOPs"""
            nop_equivalents = {
                'nop',
                'xchg eax, eax',
                'mov edi, edi',
                'lea nop',
                'data16 nop',
                'nop dword ptr [rax]' 
            }
            
            # First check: is this part of a function alignment sequence?
            # Look backward for a ret instruction
            i = start_idx - 1
            found_ret = False
            while i >= 0 and i >= start_idx - 10:  # Look up to 10 instructions back
                if instructions[i].mnemonic == 'ret':
                    found_ret = True
                    break
                i -= 1
            
            # If we found a ret before this NOP sequence, look ahead for a function prologue
            if found_ret:
                # Count how many NOPs we have
                nop_count = 0
                i = start_idx
                while i < len(instructions):
                    instr = instructions[i]
                    instr_text = f"{instr.mnemonic} {instr.op_str}".lower()
                    
                    if instr.mnemonic == 'nop' or instr_text in nop_equivalents:
                        nop_count += 1
                        i += 1
                    else:
                        break
                
                # Check if the next instruction after NOPs looks like a function prologue
                if i < len(instructions):
                    if instructions[i].mnemonic == 'push' and instructions[i].op_str in ('rbp', 'ebp', 'rsi', 'rbx', 'rdi', 'r15'):
                        # This is almost certainly alignment padding between functions
                        return False
            
            # Regular NOP sled detection
            count = 0
            idx = start_idx
            max_length = len(instructions) - start_idx
            
            while idx < len(instructions):
                instr = instructions[idx]
                instr_text = f"{instr.mnemonic} {instr.op_str}".lower()
                
                if instr.mnemonic == 'ret' or instr.mnemonic == 'jmp':
                    break
                    
                if instr.mnemonic == 'nop' or instr_text in nop_equivalents:
                    count += 1
                else:
                    break
                    
                idx += 1
            
            # Use a more aggressive threshold for actual malicious NOP sleds
            if count >= min_length:
                # For alignment NOPs that weren't caught by the previous checks,
                # use size and context to determine suspiciousness
                
                # Check if this might be just standard alignment padding
                # that wasn't caught by the function boundary detection
                if count <= 16:  # Standard alignment is usually 16 bytes or less
                    # For small NOP sequences, require that they make up a significant portion
                    # of the visible code to be considered suspicious
                    if count <= max_length * 0.5:
                        return False
                
                return True
            
            return False

        def detect_anti_debugging_checks(ctx):
            """Detect common anti-debugging techniques with context analysis."""
            curr_text = ctx.full_text.lower()
            prev_text = f"{ctx.prev.mnemonic} {ctx.prev.op_str}".lower() if ctx.prev else ""
            next_text = f"{ctx.next.mnemonic} {ctx.next.op_str}".lower() if ctx.next else ""

            # 1. Detect IsDebuggerPresent checks (even without conditional jumps)
            if "call" in curr_text and "isdebuggerpresent" in curr_text:
                return "IsDebuggerPresent check"

            # 2. Detect int3 (software breakpoint) usage
            if "int3" in curr_text or "int 3" in curr_text:
                # Check if this is part of a larger anti-debugging routine
                if ctx.prev and "mov" in prev_text and "rbp" in prev_text:
                    return "int3 (software breakpoint) usage in anti-debugging routine"

            # 3. Detect TLS callback reason code checks
            if "cmp" in curr_text and ("1" in curr_text or "2" in curr_text or "3" in curr_text):
                # Check if this is part of a TLS callback
                if ctx.next and ctx.next.mnemonic in ('je', 'jne', 'jz', 'jnz'):
                    return "TLS callback anti-debugging check (reason code)"

            # 4. Detect NtQueryInformationProcess checks (anti-debugging via ProcessDebugPort)
            if "call" in curr_text and "ntqueryinformationprocess" in curr_text:
                # Check if the ProcessDebugPort (0x7) is being queried
                if ctx.prev and "mov" in prev_text and "0x7" in prev_text:
                    return "NtQueryInformationProcess (ProcessDebugPort) check"

            # 5. Detect CheckRemoteDebuggerPresent checks
            if "call" in curr_text and "checkremotedebuggerpresent" in curr_text:
                return "CheckRemoteDebuggerPresent check"

            # 6. Detect DebugObjectHandle checks (anti-debugging via ProcessDebugObjectHandle)
            if "call" in curr_text and "ntqueryinformationprocess" in curr_text:
                # Check if the ProcessDebugObjectHandle (0x1E) is being queried
                if ctx.prev and "mov" in prev_text and "0x1e" in prev_text:
                    return "NtQueryInformationProcess (ProcessDebugObjectHandle) check"

            # 7. Detect TEB access for anti-debugging (e.g., checking BeingDebugged flag)
            if "gs:" in curr_text or "fs:" in curr_text:
                # Check if accessing the BeingDebugged flag (offset 0x30 in TEB)
                if "0x30" in curr_text and ("mov" in curr_text or "cmp" in curr_text):
                    return "TEB access (BeingDebugged flag) for anti-debugging"

            # 8. Detect self-modifying code (common in anti-debugging routines)
            if "mov" in curr_text and "byte ptr" in curr_text and "[" in curr_text:
                # Check if writing to code sections
                if ctx.next and "jmp" in next_text:
                    return "Self-modifying code (anti-debugging)"

            # 9. Detect timing-based anti-debugging (e.g., RDTSC)
            if "rdtsc" in curr_text:
                # Check if the result is used in a suspicious way
                if ctx.next and "cmp" in next_text:
                    return "Timing-based anti-debugging (RDTSC)"

            # 10. Detect API hooking checks (e.g., checking for hooked functions)
            if "call" in curr_text and "getprocaddress" in curr_text:
                # Check if the result is compared or used in a suspicious way
                if ctx.next and "cmp" in next_text:
                    return "API hooking check (GetProcAddress)"

            return None

        results = {
            'suspicious_instructions': [],
            'detection_context': {},
            'custom_matched_instructions': []
        }

        # Analyze each instruction
        string_construction_start = None
        nop_sled_detected = False
        for idx, instruction in enumerate(instructions):
            ctx = InstructionContext(instruction, idx, instructions)

            # 1. Detect API hashing
            if detect_api_hashing(ctx):
                # Extract the target hash (if available)
                target_hash = None
                if ctx.prev and ctx.prev.mnemonic in ('xor', 'rol', 'ror', 'add', 'mul'):
                    # Attempt to extract the hash value from the previous instruction
                    if ctx.prev.op_str.startswith('0x'):
                        try:
                            target_hash = int(ctx.prev.op_str.split(',')[-1].strip(), 16)
                        except ValueError:
                            try:
                                target_hash = int(ctx.prev.op_str, 16)
                            except ValueError:
                                pass

                if target_hash and pe:
                    # Resolve the hashed API
                    api_name = resolve_hashed_api(pe, target_hash)
                    if api_name:
                        results['suspicious_instructions'].append(
                            f"API Hashing Detected: Resolved hash {hex(target_hash)} to {api_name}"
                        )
                    else:
                        results['suspicious_instructions'].append(
                            f"API Hashing Detected: Unresolved hash {hex(target_hash)}"
                        )
                else:
                    results['suspicious_instructions'].append(
                        "API Hashing Detected: Unable to extract hash value"
                    )

            # 2. Add the stack string detection check
            if detect_stack_string_construction(ctx):
                # Start or continue tracking string construction sequence
                if string_construction_start is None:
                    string_construction_start = idx - 1  # Include previous instruction
                
                # If we've accumulated enough instructions, it's likely a stack string
                if idx - string_construction_start >= 3:
                    # Report only the beginning of the sequence to avoid too many alerts
                    if idx - string_construction_start == 3:
                        results['suspicious_instructions'].append(
                            f"Stack String Construction Detected: {ctx.full_text}"
                        )
                        if 'obfuscation_techniques' not in results['detection_context']:
                            results['detection_context']['obfuscation_techniques'] = []
                        results['detection_context']['obfuscation_techniques'].append('stack_string')
            else:
                # Reset tracking if the pattern breaks
                string_construction_start = None

            # 3. Detect TLS callback patterns
            if is_tls_callback_context(ctx):
                # Only report the initial TLS check, not all instructions in the callback
                if ctx.instruction.mnemonic == 'cmp' and 'edx' in ctx.instruction.op_str:
                    results['suspicious_instructions'].append(
                        f"TLS Callback Entry Point: {ctx.full_text}"
                    )
                    results['detection_context']['tls_callback'] = True

            # 4. Detect suspicious memory access
            if is_suspicious_memory_access(ctx):
                results['suspicious_instructions'].append(
                    f"Suspicious Memory Access: {ctx.full_text}"
                )

            # 5. Detect suspicious control flow
            if is_suspicious_control_flow(ctx):
                # For returns, provide more context
                if ctx.instruction.mnemonic == 'ret':
                    # # Look at previous instruction to provide context
                    # prev_context = "unknown context"
                    # if ctx.prev:
                    #     prev_context = f"{ctx.prev.mnemonic} {ctx.prev.op_str}"
                    
                    # results['suspicious_instructions'].append(
                    #     f"Unusual Return Instruction: {ctx.full_text} (after {prev_context})"
                    # )
                    pass
                else:
                    results['suspicious_instructions'].append(
                        f"Suspicious Control Flow: {ctx.full_text}"
                    )

            # 6. Detect NOP sleds (only check once)
            if not nop_sled_detected and detect_nop_sled(instructions, idx):
                nop_sled_detected = True
                # Count consecutive NOPs for reporting
                count = 0
                for i in range(idx, len(instructions)):
                    if instructions[i].mnemonic == 'nop':
                        count += 1
                    else:
                        break
                        
                results['suspicious_instructions'].append(
                    f"NOP Sled Detected: {count} consecutive NOPs at offset {idx}"
                )

            # 7. Custom regex matching with context
            if custom_regex:
                try:
                    if re.search(custom_regex, ctx.full_text, re.IGNORECASE):
                        match = f"Custom match: {ctx.full_text}"
                        results['custom_matched_instructions'].append(match)
                except re.error:
                    vollog.error(f"Invalid regex pattern: {custom_regex}")

            # 8. Detect anti-debugging checks
            anti_debug_result = detect_anti_debugging_checks(ctx)
            if anti_debug_result:
                results['suspicious_instructions'].append(
                    f"Anti-Debugging Detected: {anti_debug_result} at {hex(ctx.instruction.address)}"
                )

            # Custom regex matching (if provided)
            if custom_regex:
                try:
                    if re.search(custom_regex, ctx.full_text, re.IGNORECASE):
                        match = f"Custom match: {ctx.full_text}"
                        results['custom_matched_instructions'].append(match)
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
                collected_instructions = []
                for insn in disassembler.disasm(code_bytes, rva_address):
                    if insn.mnemonic == 'ret' and bytes_to_disassemble == 64:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                        collected_instructions.append(insn)
                        break

                    # API Resolution for 32-bit
                    if insn.mnemonic == 'call' or insn.mnemonic == 'jmp':
                        target_address = None
                        if 'dword ptr' in insn.op_str:
                            # Extract the address from the operand
                            target_address = int(insn.op_str.split('[')[1].split(']')[0], 16)
                        elif insn.op_str.startswith('0x'):
                            target_address = int(insn.op_str, 16)

                        if target_address:
                            # Resolve the API name from the IAT
                            api_name = self.resolve_api_from_iat(pe, target_address)
                            if api_name:
                                print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str} \t{blue}[API: {api_name}]{disable}")
                            else:
                                print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                        else:
                            print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                    else:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")

                    collected_instructions.append(insn)
                    current_address += insn.size

                # Detect API hashing and suspicious instructions
                # Detect API hashing and suspicious instructions
                detection_results = self.match_instruction_patterns(collected_instructions, pe, custom_regex)
                
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
                    vollog.error(f"[ERROR] Could not convert RVA to offset for disassembly at address {hex(address)}.")
                    return

                f.seek(offset)
                code_bytes = f.read(bytes_to_disassemble or 256)
                
                # Print process information
                print("\n\n----------------------------------------------------------------")
                print(f"{cyan}Disassembling code at address: {hex(address)} for Process: {proc_name} (PID: {pid}){disable}")
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
                call_targets = []  # To track call targets for one-level disassembly
                
                for insn in disassembler.disasm(code_bytes, callback_rva):
                    if insn.mnemonic == 'ret' and bytes_to_disassemble == 64:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                        collected_instructions.append(insn)
                        break

                    # Track calls for one-level disassembly
                    is_call = insn.mnemonic == 'call'
                    target_address = None
                    api_name = None

                    # Handle rip-relative addressing
                    if 'rip +' in insn.op_str:
                        offset_str = insn.op_str.split('rip + ')[1].split(']')[0]
                        offset = int(offset_str, 16)
                        target_address = current_address + insn.size + offset
                        api_name = self.resolve_api_from_iat(pe, target_address)
                        
                    # Handle direct calls/jumps
                    elif is_call or insn.mnemonic == 'jmp':
                        if 'qword ptr' in insn.op_str:
                            # Extract the address from the operand
                            try:
                                target_address = int(insn.op_str.split('[')[1].split(']')[0], 16)
                            except:
                                pass
                        elif insn.op_str.startswith('0x'):
                            # Direct address
                            target_address = int(insn.op_str, 16)
                            # For direct calls, adjust for relative addressing
                            if '0x' in insn.op_str and len(insn.op_str) <= 10:  # Likely a relative offset
                                target_address = current_address + insn.size + (target_address - (callback_rva + (current_address - address)))

                        # Resolve API and track for one-level disassembly if it's a call
                        if target_address:
                            api_name = self.resolve_api_from_iat(pe, target_address)
                            if is_call and not api_name:  # Only disassemble non-API calls
                                abs_target = image_base + target_address if target_address < image_base else target_address
                                call_targets.append(abs_target)

                    # Print the current instruction with API info if available
                    if api_name:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str} \t{blue}[API: {api_name}]{disable}")
                    else:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")

                    collected_instructions.append(insn)
                    current_address += insn.size

                # Detect API hashing and suspicious instructions
                # Detect API hashing and suspicious instructions
                detection_results = self.match_instruction_patterns(collected_instructions, pe, custom_regex)
                
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
                            print(f"{yellow}[*] YARA Rule Matches:{disable}")
                            for match in yara_matches:
                                print(f"{red}[YARA Match] Rule: {match['rule']}{disable}")
                
                print("----------------------------------------------------------------")

                # Disassemble call targets (one level only)
                for target in call_targets:
                    print(f"\n{yellow}[+] Following call to address: {hex(target)}{disable}")
                    # Call original disassemble function without modifying to avoid recursion
                    self.disassemble_call_target(exe_file, target, image_base, proc_name, pid)

        except Exception as e:
            vollog.error(f"[ERROR] Disassembly error at {hex(address)}: {str(e)}")
            import traceback
            vollog.debug(traceback.format_exc())

    # Add a new helper function to disassemble call targets without recursion
    def disassemble_call_target(self, exe_file, address, image_base, proc_name, pid):
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
                    vollog.error(f"[ERROR] Could not convert RVA to offset for call target at address {hex(address)}.")
                    return

                f.seek(offset)
                code_bytes = f.read(bytes_to_disassemble or 256)
                
                # Print process information
                print("\n----------------------------------------------------------------")
                print(f"{cyan}Disassembling call target at address: {hex(address)} for Process: {proc_name} (PID: {pid}){disable}")
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
                
                for insn in disassembler.disasm(code_bytes, rva_address):
                    if insn.mnemonic == 'ret' and bytes_to_disassemble == 64:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")
                        collected_instructions.append(insn)
                        break

                    # Handle rip-relative addressing for API resolution
                    api_name = None
                    if 'rip +' in insn.op_str:
                        offset_str = insn.op_str.split('rip + ')[1].split(']')[0]
                        offset = int(offset_str, 16)
                        target_address = current_address + insn.size + offset
                        api_name = self.resolve_api_from_iat(pe, target_address)
                        
                    # Handle direct calls/jumps for API resolution
                    elif insn.mnemonic == 'call' or insn.mnemonic == 'jmp':
                        target_address = None
                        if 'qword ptr' in insn.op_str:
                            try:
                                target_address = int(insn.op_str.split('[')[1].split(']')[0], 16)
                            except:
                                pass
                        elif insn.op_str.startswith('0x'):
                            target_address = int(insn.op_str, 16)

                        if target_address:
                            api_name = self.resolve_api_from_iat(pe, target_address)

                    # Print the current instruction with API info if available
                    if api_name:
                        # print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str} \t{blue}[API: {api_name}]{disable}")
                        pass
                    else:
                        print(f"{hex(current_address)}:\t{green}{insn.mnemonic}{disable}\t{insn.op_str}")

                    collected_instructions.append(insn)
                    current_address += insn.size

                # Detect API hashing and suspicious instructions
                detection_results = self.match_instruction_patterns(collected_instructions, custom_regex)
                
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
                            print(f"{yellow}[*] YARA Rule Matches:{disable}")
                            for match in yara_matches:
                                print(f"{red}[YARA Match] Rule: {match['rule']}{disable}")
                
                print("----------------------------------------------------------------")

        except Exception as e:
            vollog.error(f"[ERROR] Disassembly error at call target {hex(address)}: {str(e)}")

    #-----------------------------------------------
    #              API Resolution Function                             
    #-----------------------------------------------

    def resolve_api_from_iat(self, pe, target_address):
        """
        Resolve API name from the Import Address Table (IAT) with enhanced support.
        Handles regular imports, delay-loaded imports, forwarded exports, and provides fallback mechanisms.
        """
        if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT') and not hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            vollog.debug(f"No import table found for target address: {hex(target_address)}")
            return None

        # Helper function to resolve API name from import entries
        def resolve_from_imports(import_entries):
            for entry in import_entries:
                for imp in entry.imports:
                    if imp.address == target_address:
                        api_name = imp.name.decode() if imp.name else f"Ordinal_{imp.ordinal}"
                        vollog.debug(f"Resolved API: {api_name} at address {hex(target_address)}")
                        return api_name
            return None

        # Check regular imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            api_name = resolve_from_imports(pe.DIRECTORY_ENTRY_IMPORT)
            if api_name:
                return api_name

        # Check delay-loaded imports
        if hasattr(pe, 'DIRECTORY_ENTRY_DELAY_IMPORT'):
            api_name = resolve_from_imports(pe.DIRECTORY_ENTRY_DELAY_IMPORT)
            if api_name:
                return api_name

        # Check forwarded exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.address == target_address:
                    api_name = exp.name.decode() if exp.name else f"Ordinal_{exp.ordinal}"
                    vollog.debug(f"Resolved forwarded export: {api_name} at address {hex(target_address)}")
                    return api_name

        # Fallback: Scan the entire address space for potential API pointers
        for section in pe.sections:
            section_start = section.VirtualAddress
            section_end = section_start + section.Misc_VirtualSize
            if section_start <= target_address < section_end:
                # Attempt to resolve the API name based on the section's characteristics
                vollog.debug(f"Unresolved API at address {hex(target_address)} in section {section.Name.decode().strip()}")
                # return f"Unknown_API_{hex(target_address)}"
                return f""

        # If no match is found, return None
        vollog.debug(f"Unable to resolve API at address: {hex(target_address)}")
        return None

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
