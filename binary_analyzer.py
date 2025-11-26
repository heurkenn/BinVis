import logging
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection
from capstone import *
from capstone.x86 import X86_OP_IMM
import networkx as nx

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BinaryAnalyzer:
    def __init__(self, filepath):
        self.filepath = filepath
        self.graph = nx.DiGraph()
        self.functions = {}  # address -> name
        self.imports = [] # List of imported function names
        self.md = Cs(CS_ARCH_X86, CS_MODE_64)
        self.md.detail = True # Enable details to get instruction groups

    def analyze(self):
        """Main analysis loop."""
        with open(self.filepath, 'rb') as f:
            self.elf = ELFFile(f)
            
            # 1. Extract Functions from Symbol Table
            self._extract_functions()
            
            # 2. Extract Imports (PLT)
            self._extract_imports()
            
            # 3. Disassemble and build CFG
            self._build_cfg()
            
        return self.graph

    def _extract_imports(self):
        """Finds imported functions from relocation tables."""
        # This is a simplified approach looking at .dynsym or relocations
        # For standard PLT usage, we can look at .rela.plt
        rel_plt = self.elf.get_section_by_name('.rela.plt')
        if not rel_plt:
            rel_plt = self.elf.get_section_by_name('.rel.plt')
            
        if rel_plt:
            symtab = self.elf.get_section(rel_plt['sh_link'])
            for rel in rel_plt.iter_relocations():
                symbol = symtab.get_symbol(rel['r_info_sym'])
                if symbol.name:
                    # Store (GOT Address, Name)
                    self.imports.append((rel['r_offset'], symbol.name))
        
        # Fallback: Check .dynsym if imports empty (sometimes useful)
        if not self.imports:
            dynsym = self.elf.get_section_by_name('.dynsym')
            if dynsym:
                for sym in dynsym.iter_symbols():
                    if sym['st_shndx'] == 'SHN_UNDEF' and sym.name:
                         self.imports.append((0, sym.name))
                         
        self.imports = list(set(self.imports)) # Deduplicate
        self.imports.sort(key=lambda x: x[0]) # Sort by address

    def _simple_decompile(self, asm_lines, resolver=None):
        """
        Very basic heuristic decompiler.
        Converts ASM lines to Pseudo-C.
        """
        c_lines = []
        indent = 1
        
        for line in asm_lines:
            parts = line.split()
            if len(parts) < 2: continue
            
            mnemonic = parts[1]
            op_str = " ".join(parts[2:]) if len(parts) > 2 else ""
            
            # Heuristics
            if mnemonic == 'call':
                target_name = op_str
                if resolver and op_str.startswith('0x'):
                    try:
                        addr = int(op_str, 16)
                        res = resolver(addr)
                        if res: target_name = res
                    except: pass
                c_lines.append("    " * indent + f"{target_name}();")
            elif mnemonic == 'ret':
                c_lines.append("    " * indent + "return;")
            elif mnemonic == 'cmp':
                c_lines.append("    " * indent + f"// check {op_str}")
            elif mnemonic.startswith('j'): # Jumps
                if mnemonic == 'jmp':
                     c_lines.append("    " * indent + f"goto {op_str};")
                else:
                     c_lines.append("    " * indent + f"if (...) goto {op_str}; // {mnemonic}")
            elif mnemonic == 'mov':
                 if ',' in op_str:
                    dst, src = op_str.split(',', 1)
                    c_lines.append("    " * indent + f"{dst} = {src};")
            elif mnemonic == 'lea':
                 if ',' in op_str:
                    dst, src = op_str.split(',', 1)
                    c_lines.append("    " * indent + f"{dst} = &{src};")
            elif mnemonic in ['add', 'sub', 'imul', 'idiv', 'xor', 'or', 'and']:
                 if ',' in op_str:
                    # add eax, 1 -> eax += 1
                    dst, src = op_str.split(',', 1)
                    c_lines.append("    " * indent + f"{dst} {mnemonic}= {src};")
                
        return "\n".join(c_lines)

    def _extract_functions(self):
        """Finds all function symbols in the ELF."""
        symbol_section = self.elf.get_section_by_name('.symtab')
        if not symbol_section:
            logger.warning("No symbol table found. Stripped binary?")
            return

        for symbol in symbol_section.iter_symbols():
            if symbol['st_info']['type'] == 'STT_FUNC' and symbol['st_size'] > 0:
                addr = symbol['st_value']
                name = symbol.name
                size = symbol['st_size']
                self.functions[addr] = {'name': name, 'size': size}
                self.graph.add_node(name, address=addr, size=size)
        
        logger.info(f"Found {len(self.functions)} functions.")

    def _build_cfg(self):
        """Disassembles functions to find calls."""
        text_section = self.elf.get_section_by_name('.text')
        if not text_section:
            logger.error("No .text section found.")
            return

        text_addr = text_section['sh_addr']
        text_data = text_section.data()

        for addr, func_info in self.functions.items():
            name = func_info['name']
            size = func_info['size']
            
            # Calculate offset in .text section
            offset = addr - text_addr
            if offset < 0 or offset >= len(text_data):
                continue # Symbol might be in plt or elsewhere
            
            func_code = text_data[offset : offset + size]
            
            asm_lines = []
            try:
                for insn in self.md.disasm(func_code, addr):
                    asm_lines.append(f"0x{insn.address:x}:\t{insn.mnemonic}\t{insn.op_str}")
                    
                    # Check if it's a CALL instruction
                    if insn.mnemonic == 'call':
                        # Attempt to resolve target
                        # Capstone gives us the operand.
                        # For x86 call, operand is often an immediate address (relative)
                        if len(insn.operands) > 0:
                            op = insn.operands[0]
                            if op.type == X86_OP_IMM:
                                target_addr = op.imm
                                target_name = self._resolve_name(target_addr)
                                
                                # Add edge
                                if target_name:
                                    self.graph.add_edge(name, target_name)
                                else:
                                    # Call to unknown/external address (e.g., dynamic linked)
                                    # For now, maybe add a node for it?
                                    uniq_name = f"sub_{target_addr:x}"
                                    self.graph.add_node(uniq_name, address=target_addr, external=True)
                                    self.graph.add_edge(name, uniq_name)
                
                # Store assembly in graph node
                self.graph.nodes[name]['asm'] = "\n".join(asm_lines)
                
                # Store pseudo-C
                self.graph.nodes[name]['decomp'] = self._simple_decompile(asm_lines, self._resolve_name)
                
            except Exception as e:
                logger.error(f"Error disassembling {name}: {e}")

    def _resolve_name(self, addr):
        """Finds function name by address."""
        if addr in self.functions:
            return self.functions[addr]['name']
        # Check if it's close to a known function (sometimes symbols are off?)
        # Or check PLT entries (omitted for simplicity in v1)
        return None
