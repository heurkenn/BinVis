import logging
import re
from pygdbmi.gdbcontroller import GdbController
from PyQt6.QtCore import QObject, pyqtSignal
import time

logger = logging.getLogger(__name__)

class DebuggerBackend(QObject):
    # Signals to UI
    stopped_at = pyqtSignal(dict) # {func, addr, line, file}
    registers_updated = pyqtSignal(dict) # {reg: val}
    stack_updated = pyqtSignal(list) # List of (addr, val)
    disassembly_updated = pyqtSignal(list, int) # (lines, active_index)
    console_output = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    process_started = pyqtSignal()
    process_exited = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.gdb = None
        self.is_running = False
        self.reg_names = []
        self.reg_cache = {}
        self.last_stack_pointer = None
        self.stack_dirty = True
        
        # Caching Disassembly
        self.disasm_cache = {'func': None, 'lines': [], 'addrs': []}
        self.current_func = None
        self.current_addr = None

    def start_session(self, binary_path, args=[], flavor="intel"):
        """Starts GDB with the binary and optional arguments."""
        try:
            self.gdb = GdbController()
            self.gdb.write(f'-file-exec-and-symbols "{binary_path}"')
            
            # Set Flavor Immediately
            self.gdb.write(f"set disassembly-flavor {flavor}")
            
            # Disable pagination to prevent hanging on long outputs
            self.gdb.write("set pagination off")
            self.gdb.write("set confirm off")
            
            # Init Maps
            self._init_register_map()

            # Set args if provided
            if args:
                args_str = " ".join(args)
                self.gdb.write(f'-exec-arguments {args_str}')
                self.console_output.emit(f"Arguments set: {args_str}")

            # Enable async mode? pygdbmi handles this but we need to be careful.
            self.console_output.emit(f"debugger started on {binary_path}")
            
            # Run to main (optional, but good for users)
            self.gdb.write('-break-insert main')
            self.run_command('-exec-run')
            self.process_started.emit()
            
            # Force full update on start
            self._update_registers(full=True)
            self._update_stack(force=True)
            
        except Exception as e:
            self.error_occurred.emit(str(e))

    def stop_session(self):
        if self.gdb:
            try:
                self.gdb.exit()
            except: pass
            self.gdb = None
            self.process_exited.emit()

    # Step / Continue Slots (Called from Thread)
    def step_over(self):
        self.run_command('-exec-next-instruction', timeout=1)

    def step_into(self):
        self.run_command('-exec-step-instruction', timeout=1)
        
    def step_instruction(self):
        self.run_command('-exec-next-instruction', timeout=1)

    def continue_exec(self):
        self.run_command('-exec-continue')
        
    def set_flavor(self, flavor):
        if self.gdb:
            self.gdb.write(f"set disassembly-flavor {flavor}")
            # Invalidate cache on flavor change
            self.disasm_cache = {'func': None, 'lines': [], 'addrs': []}
            self._update_disassembly()

    def run_command(self, cmd, timeout=2):
        """Runs a command and processes the immediate response loop."""
        if not self.gdb: return

        try:
            responses = self.gdb.write(cmd, timeout_sec=timeout) 
            self._parse_responses(responses)
        except Exception as e:
            self.error_occurred.emit(str(e))

    def _init_register_map(self):
        try:
            resp = self.gdb.write("-data-list-register-names")
            for r in resp:
                if r['type'] == 'result':
                    self.reg_names = r['payload'].get('register-names', [])
        except Exception as e:
            logger.error(f"Failed to init registers: {e}")

    def _parse_responses(self, responses):
        for resp in responses:
            msg_type = resp.get('type')
            payload = resp.get('payload')
            
            if msg_type == 'console':
                if payload: self.console_output.emit(payload.strip())
                
            elif msg_type == 'notify':
                if payload and 'reason' in payload:
                    reason = payload['reason']
                    if reason in ['breakpoint-hit', 'end-stepping-range', 'function-finished']:
                         self._handle_stop(payload)
                    elif reason == 'exited-normally':
                         self.console_output.emit("Process exited normally.")
                         self.process_exited.emit()
                         
            elif msg_type == 'result':
                 if payload and 'reason' in payload:
                     reason = payload['reason']
                     if reason in ['breakpoint-hit', 'end-stepping-range', 'function-finished']:
                         self._handle_stop(payload)

    def _handle_stop(self, payload):
        """Parsed stop info to update UI."""
        frame = payload.get('frame', {})
        
        self.current_func = frame.get('func', '??')
        self.current_addr = frame.get('addr', '0x0')
        
        info = {
            'func': self.current_func,
            'addr': self.current_addr,
            'line': frame.get('line', '?'),
            'file': frame.get('file', '?')
        }
        
        # 1. Immediate Feedback (Move Cursor)
        self.stopped_at.emit(info)
        
        # 2. Fast Update (Disassembly Cache)
        self._update_disassembly()
        
        # 3. Heavy Updates (Incremental Registers -> Conditional Stack)
        self._update_registers()
        if self.stack_dirty:
            self._update_stack()

    def _update_registers(self, full=False):
        if not self.gdb: return
        try:
            if full:
                cmd = "-data-list-register-values x"
            else:
                # Get changed registers first
                resp_changed = self.gdb.write("-data-list-changed-registers", timeout_sec=0.5)
                changed_indices = []
                for r in resp_changed:
                    if r['type'] == 'result':
                        changed_indices = r['payload'].get('changed-registers', [])
                
                if not changed_indices:
                    return # Nothing changed, nothing to do
                
                cmd = f"-data-list-register-values x {' '.join(changed_indices)}"

            # Fetch values
            resp = self.gdb.write(cmd, timeout_sec=1)
            
            # Parse and Update Cache
            for r in resp:
                if r['type'] == 'result':
                    values = r['payload'].get('register-values', [])
                    for item in values:
                        idx = int(item['number'])
                        val = item['value']
                        if idx < len(self.reg_names):
                            name = self.reg_names[idx]
                            if name: 
                                self.reg_cache[name] = val
            
            # Check Stack Pointer Change
            # Support both 64-bit and 32-bit common names
            sp_val = self.reg_cache.get('rsp') or self.reg_cache.get('esp')
            if sp_val != self.last_stack_pointer:
                self.last_stack_pointer = sp_val
                self.stack_dirty = True
            else:
                self.stack_dirty = False

            self.registers_updated.emit(self.reg_cache)
            
        except Exception as e:
            logger.error(f"Reg update failed: {e}")

    def _update_stack(self, force=False):
        """Fetches stack memory."""
        if not self.gdb: return
        try:
            # -data-read-memory $rsp x 8 20 1
            resp = self.gdb.write("-data-read-memory $rsp x 8 20 1", timeout_sec=1) 
            
            stack_data = []
            for r in resp:
                if r['type'] == 'result':
                    mem = r['payload'].get('memory', [])
                    for row in mem:
                        addr = row['addr']
                        data = row['data'] # list of strings
                        for i, val in enumerate(data):
                            stack_data.append((addr, val))
                            
            self.stack_updated.emit(stack_data)
            self.stack_dirty = False
            
        except Exception as e:
            logger.error(f"Stack update failed: {e}")

    def _update_disassembly(self):
        """Fetches disassembly around current PC using caching."""
        if not self.gdb: return
        
        try:
            # Determine if we need to re-fetch
            need_fetch = True
            active_idx = -1
            
            if self.current_func and self.current_func == self.disasm_cache['func']:
                # Try to find current addr in cache
                try:
                    # Normalize address to int for comparison if needed, or string match
                    # GDB returns '0x...' strings.
                    active_idx = self.disasm_cache['addrs'].index(self.current_addr)
                    need_fetch = False
                except ValueError:
                    # Addr not in cache (jumped outside?), re-fetch
                    need_fetch = True
            
            if need_fetch:
                # Fetch disassembly
                resp = self.gdb.write("disassemble") # Defaults to current function
                
                lines = []
                addrs = []
                
                console_payloads = [r['payload'] for r in resp if r['type'] == 'console']
                raw_text = "".join(console_payloads)
                
                for line in raw_text.splitlines():
                    line = line.strip()
                    if not line: continue
                    if "End of assembler" in line: continue
                    if "Dump of assembler" in line: continue
                    if "No function contains program counter" in line: 
                        # Fallback if we are in unknown territory
                        lines = ["No disassembly available."]
                        break

                    # Remove the '=>' marker to store clean text
                    clean_line = line
                    if line.startswith("=>"):
                        clean_line = line[2:].strip()
                    
                    # Extract Address: start of line '0x...'
                    match = re.match(r'(0x[0-9a-fA-F]+)', clean_line)
                    if match:
                        addr = match.group(1)
                        addrs.append(addr)
                        lines.append(clean_line)
                
                # Update Cache
                self.disasm_cache = {
                    'func': self.current_func,
                    'lines': lines,
                    'addrs': addrs
                }
                
                # Find index again
                try:
                    active_idx = addrs.index(self.current_addr)
                except ValueError:
                    active_idx = -1

            self.disassembly_updated.emit(self.disasm_cache['lines'], active_idx)
            
        except Exception as e:
            logger.error(f"Disas failed: {e}")
