from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from PyQt6.QtCore import QRegularExpression

class AsmHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        
        self.rules = []
        
        # Formats
        f_mnemonic = QTextCharFormat()
        f_mnemonic.setForeground(QColor("#f92672")) # Pink
        f_mnemonic.setFontWeight(QFont.Weight.Bold)
        
        f_reg = QTextCharFormat()
        f_reg.setForeground(QColor("#66d9ef")) # Blue
        
        f_num = QTextCharFormat()
        f_num.setForeground(QColor("#ae81ff")) # Purple
        
        f_comment = QTextCharFormat()
        f_comment.setForeground(QColor("#75715e")) # Grey
        f_comment.setFontItalic(True)
        
        f_address = QTextCharFormat()
        f_address.setForeground(QColor("#e6db74")) # Yellow
        
        # Rules
        # 1. Addresses (0x...) at start
        self.rules.append((QRegularExpression(r"^0x[0-9a-fA-F]+"), f_address))
        
        # 2. Mnemonics (simplified list)
        keywords = [
            "mov", "lea", "push", "pop", "call", "ret", "nop",
            "add", "sub", "xor", "and", "or", "inc", "dec", "imul", "idiv", "cmp", "test",
            "jmp", "je", "jne", "jg", "jge", "jl", "jle", "ja", "jb", "js", "jns",
            "int", "syscall"
        ]
        for kw in keywords:
            # \b matches word boundary
            self.rules.append((QRegularExpression(r"\b" + kw + r"\b"), f_mnemonic))
            
        # 3. Registers (x64)
        regs = [
            "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
            "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
            "rip"
        ]
        for r in regs:
            self.rules.append((QRegularExpression(r"\b" + r + r"\b"), f_reg))
            
        # 4. Hex Numbers
        self.rules.append((QRegularExpression(r"\b0x[0-9a-fA-F]+\b"), f_num))
        # 5. Decimal Numbers
        self.rules.append((QRegularExpression(r"\b\d+\b"), f_num))
        
        # 6. Comments
        self.rules.append((QRegularExpression(r";.*"), f_comment))

    def highlightBlock(self, text):
        for expression, format in self.rules:
            match_iter = expression.globalMatch(text)
            while match_iter.hasNext():
                match = match_iter.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)

class CHighlighter(QSyntaxHighlighter):
    def __init__(self, document):
        super().__init__(document)
        self.rules = []
        
        # Formats
        f_keyword = QTextCharFormat()
        f_keyword.setForeground(QColor("#f92672"))
        f_keyword.setFontWeight(QFont.Weight.Bold)
        
        f_type = QTextCharFormat()
        f_type.setForeground(QColor("#66d9ef"))
        
        f_comment = QTextCharFormat()
        f_comment.setForeground(QColor("#75715e"))
        
        f_func = QTextCharFormat()
        f_func.setForeground(QColor("#a6e22e")) # Green
        
        # Rules
        keywords = ["if", "else", "while", "for", "return", "goto", "break", "continue", "switch", "case"]
        for kw in keywords:
             self.rules.append((QRegularExpression(r"\b" + kw + r"\b"), f_keyword))
             
        types = ["void", "int", "char", "long", "unsigned", "struct", "bool"]
        for t in types:
             self.rules.append((QRegularExpression(r"\b" + t + r"\b"), f_type))
             
        # Function calls (identifier followed by ()
        self.rules.append((QRegularExpression(r"\b[A-Za-z0-9_]+(?=\()"), f_func))
        
        # Comments
        self.rules.append((QRegularExpression(r"//.*"), f_comment))
        
    def highlightBlock(self, text):
        for expression, format in self.rules:
            match_iter = expression.globalMatch(text)
            while match_iter.hasNext():
                match = match_iter.next()
                self.setFormat(match.capturedStart(), match.capturedLength(), format)
