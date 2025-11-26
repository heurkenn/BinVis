import logging
import os
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SH_FLAGS
import pefile
from capstone import *
from capstone.x86 import *
from capstone.arm import *
from capstone.arm64 import *
from capstone.mips import *
import networkx as nx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BinaryAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.graph = nx.DiGraph()
        self.functions = {}  # address -> {'name': str, 'size': int}
        self.imports = []    # List of (address, name)
        self.entry_point = None
        self.arch = None
        self.mode = None
        self.md = None # Capstone instance

    def analyze(self):
        """Detects file type and runs specific analysis."""
        try:
            with open(self.filepath, 'rb') as f:
                header = f.read(4)
            
            if header.startswith(b'\x7fELF'):
                self._analyze_elf()
            elif header.startswith(b'MZ'):
                self._analyze_pe()
            else:
                raise ValueError("Unknown or unsupported binary format (Not ELF or PE).")
                
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            raise e
            
        return self.graph

    def _init_capstone(self, arch, mode, endian=None):
        """Initializes Capstone disassembler."""
        try:
            self.md = Cs(arch, mode)
            if endian:
                self.md.mode |= endian
            self.md.detail = True
            self.arch = arch
            self.mode = mode
        except CsError as e:
            logger.error(f"Capstone initialization failed: {e}")
            raise

    # =========================================================================
    # ELF Analysis
    # =========================================================================
    def _analyze_elf(self):
        logger.info("Detected ELF binary.")
        with open(self.filepath, 'rb') as f:
            elf = ELFFile(f)
            self.entry_point = elf.header['e_entry']
            
            # Detect Architecture
            arch = elf.get_machine_arch()
            logger.info(f"ELF Machine Arch: {arch}")
            
            cs_arch = CS_ARCH_X86
            cs_mode = CS_MODE_64
            cs_endian = CS_MODE_LITTLE_ENDIAN if elf.little_endian else CS_MODE_BIG_ENDIAN

            if arch == 'x64':
                cs_arch, cs_mode = CS_ARCH_X86, CS_MODE_64
            elif arch == 'x86':
                cs_arch, cs_mode = CS_ARCH_X86, CS_MODE_32
            elif arch == 'ARM':
                cs_arch, cs_mode = CS_ARCH_ARM, CS_MODE_ARM
            elif arch == 'AArch64':
                cs_arch, cs_mode = CS_ARCH_ARM64, CS_MODE_ARM
            elif arch == 'MIPS':
                cs_arch, cs_mode = CS_ARCH_MIPS, CS_MODE_MIPS32
            else:
                logger.warning(f"Architecture {arch} not fully optimized. Defaulting to x86-64.")

            self._init_capstone(cs_arch, cs_mode, cs_endian)

            # 1. Extract Functions
            symtab = elf.get_section_by_name('.symtab')
            if symtab:
                for sym in symtab.iter_symbols():
                    if sym['st_info']['type'] == 'STT_FUNC' and sym['st_size'] > 0:
                        self.functions[sym['st_value']] = {
                            'name': sym.name,
                            'size': sym['st_size']
                        }
                        self.graph.add_node(sym.name, address=sym['st_value'], size=sym['st_size'])
            
            # 2. Extract Imports (PLT/DynSym)
            self._extract_elf_imports(elf)

            # 3. Disassemble .text
            text = elf.get_section_by_name('.text')
            if text:
                self._disassemble_section(text.data(), text['sh_addr'])

    def _extract_elf_imports(self, elf):
        # Try .rela.plt (usually x64) or .rel.plt (x86)
        for section_name in ['.rela.plt', '.rel.plt']:
            rel_plt = elf.get_section_by_name(section_name)
            if rel_plt:
                symtab = elf.get_section(rel_plt['sh_link'])
                for rel in rel_plt.iter_relocations():
                    symbol = symtab.get_symbol(rel['r_info_sym'])
                    if symbol.name:
                        self.imports.append((rel['r_offset'], symbol.name))
                return

        # Fallback to .dynsym
        dynsym = elf.get_section_by_name('.dynsym')
        if dynsym:
            for sym in dynsym.iter_symbols():
                 if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
                     self.imports.append((0, sym.name)) # Addr unknown/0

    # =========================================================================
    # PE (Windows) Analysis
    # =========================================================================
    def _analyze_pe(self):
        logger.info("Detected PE binary.")
        pe = pefile.PE(self.filepath)
        self.entry_point = pe.OPTIONAL_HEADER.AddressOfEntryPoint + pe.OPTIONAL_HEADER.ImageBase
        
        # Detect Architecture
        machine = pe.FILE_HEADER.Machine
        # Constants from pefile
        if machine == 0x8664: # AMD64
            self._init_capstone(CS_ARCH_X86, CS_MODE_64)
        elif machine == 0x014c: # I386
            self._init_capstone(CS_ARCH_X86, CS_MODE_32)
        elif machine == 0x01c0: # ARM
            self._init_capstone(CS_ARCH_ARM, CS_MODE_ARM)
        elif machine == 0xaa64: # ARM64
            self._init_capstone(CS_ARCH_ARM64, CS_MODE_ARM)
        else:
            logger.warning(f"Unknown PE Machine: {hex(machine)}. Defaulting to x86-64.")
            self._init_capstone(CS_ARCH_X86, CS_MODE_64)

        # 1. Extract Exports (as "Functions" for now) and Imports
        # PE doesn't always have a symbol table like ELF. We rely on Exports and maybe PDB (not implemented).
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    name = exp.name.decode('utf-8', 'ignore')
                    addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
                    # Estimate size? PE symbols don't have size.
                    self.functions[addr] = {'name': name, 'size': 100} # Dummy size
                    self.graph.add_node(name, address=addr, size=100)

        # 2. Extract Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports:
                    if imp.name:
                        name = imp.name.decode('utf-8', 'ignore')
                        self.imports.append((imp.address or 0, name))

        # 3. Disassemble .text section
        for section in pe.sections:
            if b'.text' in section.Name:
                data = section.get_data()
                addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                
                # If we didn't find exported functions, we might want to just scan the whole text
                # Or try to find function prologues.
                # For this V2, if no functions found, add EntryPoint
                if not self.functions:
                    ep = self.entry_point
                    self.functions[ep] = {'name': 'EntryPoint', 'size': len(data)}
                    self.graph.add_node('EntryPoint', address=ep, size=len(data))
                
                self._disassemble_section(data, addr)

    # =========================================================================
    # Generic Disassembly & CFG Build
    # =========================================================================
    def _disassemble_section(self, data, base_addr):
        """
        Disassembles a block of bytes and maps it to the known functions.
        Since functions might be scattered, we iterate through our known function list.
        """
        # Create a map of known function addresses for fast lookup
        addr_to_name = {addr: info['name'] for addr, info in self.functions.items()}
        
        for func_addr, info in self.functions.items():
            name = info['name']
            size = info['size']
            
            # Calculate offset into the data buffer
            start_offset = func_addr - base_addr
            if start_offset < 0 or start_offset >= len(data):
                continue

            # Safe slice
            end_offset = min(start_offset + size, len(data))
            code = data[start_offset:end_offset]
            
            asm_lines = []
            try:
                for insn in self.md.disasm(code, func_addr):
                    asm_lines.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
                    
                    # Handle Calls
                    target_name = self._check_call(insn, addr_to_name)
                    if target_name:
                        self.graph.add_edge(name, target_name)

                # Save Data
                if name in self.graph.nodes:
                    self.graph.nodes[name]['asm'] = "\n".join(asm_lines)
                    # Use simple decompiler
                    self.graph.nodes[name]['decomp'] = self._simple_decompile(asm_lines)

            except Exception as e:
                logger.warning(f"Disassembly warning for {name}: {e}")

    def _check_call(self, insn, addr_to_name):
        """
        Checks if instruction is a call and resolves target.
        Returns target name or None.
        """
        # 1. Is it a call instruction? (Arch specific)
        is_call = False
        target_addr = None
        
        if self.arch == CS_ARCH_X86:
            if insn.mnemonic == 'call':
                is_call = True
                if len(insn.operands) > 0 and insn.operands[0].type == X86_OP_IMM:
                    target_addr = insn.operands[0].imm

        elif self.arch == CS_ARCH_ARM:
            if insn.mnemonic in ['bl', 'blx']:
                is_call = True
                if len(insn.operands) > 0 and insn.operands[0].type == ARM_OP_IMM:
                    target_addr = insn.operands[0].imm
                    
        elif self.arch == CS_ARCH_ARM64:
             if insn.mnemonic in ['bl', 'blr']:
                is_call = True
                if len(insn.operands) > 0 and insn.operands[0].type == ARM64_OP_IMM:
                    target_addr = insn.operands[0].imm

        elif self.arch == CS_ARCH_MIPS:
             if insn.mnemonic in ['jal', 'bal']:
                is_call = True
                if len(insn.operands) > 0 and insn.operands[0].type == MIPS_OP_IMM:
                    target_addr = insn.operands[0].imm

        # 2. Resolve Address
        if is_call and target_addr is not None:
            # Exact match
            if target_addr in addr_to_name:
                return addr_to_name[target_addr]
            
            # If not found, it might be an external import or un-symbolized function
            # For now, create a stub node
            stub_name = f"sub_{target_addr:x}"
            # Only add if it doesn't exist to avoid duplicates
            if stub_name not in self.graph:
                self.graph.add_node(stub_name, address=target_addr, external=True)
            return stub_name
            
        return None

    def _simple_decompile(self, asm_lines):
        """
        Heuristic decompiler.
        """
        c_lines = []
        indent = 1
        
        for line in asm_lines:
            parts = line.split()
            if len(parts) < 2: continue
            mnemonic = parts[1]
            op_str = " ".join(parts[2:]) if len(parts) > 2 else ""
            
            # Basic heuristics for common mnemonics
            if mnemonic.startswith('call') or mnemonic in ['bl', 'jal']:
                c_lines.append("    " * indent + f"{op_str}();")
            elif mnemonic in ['ret', 'bx lr']:
                c_lines.append("    " * indent + "return;")
            elif mnemonic.startswith('j') or mnemonic.startswith('b'): # Jumps / Branches
                 c_lines.append("    " * indent + f"goto {op_str};")
            elif 'mov' in mnemonic:
                 c_lines.append("    " * indent + f"// {mnemonic} {op_str}")
            else:
                 # keep complex math/logic as comment or simplified
                 pass
                
        return "\n".join(c_lines)