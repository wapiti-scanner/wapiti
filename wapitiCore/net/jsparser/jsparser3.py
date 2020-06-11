#!/usr/bin/python3

# ***** BEGIN LICENSE BLOCK *****
# Version: MPL 1.1/GPL 2.0/LGPL 2.1
#
# The contents of this file are subject to the Mozilla Public License Version
# 1.1 (the "License"); you may not use this file except in compliance with
# the License. You may obtain a copy of the License at
# http://www.mozilla.org/MPL/
#
# Software distributed under the License is distributed on an "AS IS" basis,
# WITHOUT WARRANTY OF ANY KIND, either express or implied. See the License
# for the specific language governing rights and limitations under the
# License.
#
# The Original Code is the Narcissus JavaScript engine, written in Javascript.
#
# The Initial Developer of the Original Code is
# Brendan Eich <brendan@mozilla.org>.
# Portions created by the Initial Developer are Copyright (C) 2004
# the Initial Developer. All Rights Reserved.
#
# The Python version of the code was created by JT Olds <jtolds@xnet5.com>,
# and is a direct translation from the Javascript version.
#
# Alternatively, the contents of this file may be used under the terms of
# either the GNU General Public License Version 2 or later (the "GPL"), or
# the GNU Lesser General Public License Version 2.1 or later (the "LGPL"),
# in which case the provisions of the GPL or the LGPL are applicable instead
# of those above. If you wish to allow use of your version of this file only
# under the terms of either the GPL or the LGPL, and not to allow others to
# use your version of this file under the terms of the MPL, indicate your
# decision by deleting the provisions above and replace them with the notice
# and other provisions required by the GPL or the LGPL. If you do not delete
# the provisions above, a recipient may use your version of this file under
# the terms of any one of the MPL, the GPL or the LGPL.
#
# ***** END LICENSE BLOCK ***** */
"""
 PyNarcissus

 A lexical scanner and parser. JS implemented in JS, ported to Python.
"""
import re
import sys

__author__ = "JT Olds"
__author_email__ = "jtolds@xnet5.com"
__date__ = "2009-03-24"
__all__ = ["ParseError", "parse", "tokens"]


class Object:
    pass


class Error_(Exception):
    pass


class ParseError(Error_):
    pass


tokens = {
    0: 'END', 1: '\n', 2: ';', 3: ',', 4: '=', 5: '?', 6: ':', 7: 'CONDITIONAL', 8: '||', 9: '&&', 10: '|',
    11: '^', 12: '&', 13: '==', 14: '!=', 15: '===', 16: '!==', 17: '<', 18: '<=', 19: '>=', 20: '>',
    21: '<<', 22: '>>', 23: '>>>', 24: '+', 25: '-', 26: '*', 27: '/', 28: '%', 29: '!', 30: '~',
    31: 'UNARY_PLUS', 32: 'UNARY_MINUS', 33: '++', 34: '--', 35: '.', 36: '[', 37: ']', 38: '{', 39: '}',
    40: '(', 41: ')', 42: 'SCRIPT', 43: 'BLOCK', 44: 'LABEL', 45: 'FOR_IN',
    46: 'CALL', 47: 'NEW_WITH_ARGS', 48: 'INDEX', 49: 'ARRAY_INIT', 50: 'OBJECT_INIT',
    51: 'PROPERTY_INIT', 52: 'GETTER', 53: 'SETTER', 54: 'GROUP', 55: 'LIST',
    56: 'IDENTIFIER', 57: 'NUMBER', 58: 'STRING', 59: 'REGEXP',
    60: 'break', 61: 'case', 62: 'catch', 63: 'const', 64: 'continue', 65: 'debugger',
    66: 'default', 67: 'delete', 68: 'do', 69: 'else',
    70: 'enum', 71: 'false', 72: 'finally', 73: 'for', 74: 'function', 75: 'if',
    76: 'in', 77: 'instanceof', 78: 'new', 79: 'null', 80: 'return',
    81: 'switch', 82: 'this', 83: 'throw', 84: 'true', 85: 'try',
    86: 'typeof', 87: 'var', 88: 'void', 89: 'while', 90: 'with'
}

# Operator and punctuator mapping from token to tree node type name.
# NB: superstring tokens (e.g., ++) must come before their substring token
# counterparts (+ in the example), so that the opRegExp regular expression
# synthesized from this list makes the longest possible match.
opTypeNames = [
    ('\n', "NEWLINE"),
    (';', "SEMICOLON"),
    (',', "COMMA"),
    ('?', "HOOK"),
    (':', "COLON"),
    ('||', "OR"),
    ('&&', "AND"),
    ('|', "BITWISE_OR"),
    ('^', "BITWISE_XOR"),
    ('&', "BITWISE_AND"),
    ('===', "STRICT_EQ"),
    ('==', "EQ"),
    ('=', "ASSIGN"),
    ('!==', "STRICT_NE"),
    ('!=', "NE"),
    ('<<', "LSH"),
    ('<=', "LE"),
    ('<', "LT"),
    ('>>>', "URSH"),
    ('>>', "RSH"),
    ('>=', "GE"),
    ('>', "GT"),
    ('++', "INCREMENT"),
    ('--', "DECREMENT"),
    ('+', "PLUS"),
    ('-', "MINUS"),
    ('*', "MUL"),
    ('/', "DIV"),
    ('%', "MOD"),
    ('!', "NOT"),
    ('~', "BITWISE_NOT"),
    ('.', "DOT"),
    ('[', "LEFT_BRACKET"),
    (']', "RIGHT_BRACKET"),
    ('{', "LEFT_CURLY"),
    ('}', "RIGHT_CURLY"),
    ('(', "LEFT_PAREN"),
    (')', "RIGHT_PAREN"),
]

keywords = {}

# Define const END, etc., based on the token names.  Also map name to index.
for i, item_2 in tokens.copy().items():
    if re.match(r'^[a-z]', item_2):
        const_name = item_2.upper()
        keywords[item_2] = i
    elif re.match(r'^\W', item_2):
        const_name = dict(opTypeNames)[item_2]
    else:
        const_name = item_2
    globals()[const_name] = i
    tokens[item_2] = i

assign_ops = {}

# Map assignment operators to their indexes in the tokens array.
for i, item_2 in enumerate(['|', '^', '&', '<<', '>>', '>>>', '+', '-', '*', '/', '%']):
    assign_ops[item_2] = tokens[item_2]
    assign_ops[i] = item_2

# Build a regexp that recognizes operators and punctuators (except newline).
opRegExpSrc = "^"
for i, j in opTypeNames:
    if i == "\n":
        continue
    if opRegExpSrc != "^":
        opRegExpSrc += "|^"
    opRegExpSrc += re.sub(r'[?|^&(){}\[\]+\-*/.]', lambda oper: "\\%s" % oper.group(0), i)
opRegExp = re.compile(opRegExpSrc)

# Convert opTypeNames to an actual dictionary now that we don'item_2 care about ordering
opTypeNames = dict(opTypeNames)

# A regexp to match floating point literals (but not integer literals).
fpRegExp = re.compile(r'^\d+\.\d*(?:[eE][-+]?\d+)?|^\d+(?:\.\d*)?[eE][-+]?\d+|^\.\d+(?:[eE][-+]?\d+)?')

# A regexp to match regexp literals.
reRegExp = re.compile(r'^/((?:\\.|\[(?:\\.|[^\]])*\]|[^/])+)/([gimy]*)')


class SyntaxError_(ParseError):
    def __init__(self, message, filename, lineno):
        ParseError.__init__(self, "Syntax error: %s\n%s:%s" %
                                  (message, filename, lineno))


class Tokenizer(object):
    def __init__(self, s, f, l):
        self.cursor = 0
        self.source = str(s)
        self.tokens = {}
        self.token_index = 0
        self.lookahead = 0
        self.scan_new_lines = False
        self.scan_operand = True
        self.filename = f
        self.lineno = l

    input_ = property(lambda self: self.source[self.cursor:])
    done = property(lambda self: self.peek() == END)
    token = property(lambda self: self.tokens.get(self.token_index))

    def match(self, match_var):
        return self.get() == match_var or self.unget()

    def must_match(self, match_var):
        if not self.match(match_var):
            raise self.new_syntax_error("Missing " + tokens.get(match_var).lower())
        return self.token

    def peek(self):
        if self.lookahead:
            next_one = self.tokens.get((self.token_index + self.lookahead) & 3)
            if self.scan_new_lines and (getattr(next, "lineno", None) != getattr(self, "lineno", None)):
                match_var = NEWLINE
            else:
                match_var = getattr(next_one, "type_", None)
        else:
            match_var = self.get()
            self.unget()
        return match_var

    def peek_on_same_line(self):
        self.scan_new_lines = True
        match_var = self.peek()
        self.scan_new_lines = False
        return match_var

    def get(self):
        while self.lookahead:
            self.lookahead -= 1
            self.token_index = (self.token_index + 1) & 3
            token = self.tokens.get(self.token_index)
            if getattr(token, "type_", None) != NEWLINE or self.scan_new_lines:
                return getattr(token, "type_", None)

        while True:
            input__ = self.input_
            if self.scan_new_lines:
                match = re.match(r'^[ \item_2]+', input__)
            else:
                match = re.match(r'^\s+', input__)
            if match:
                spaces = match.group(0)
                self.cursor += len(spaces)
                newlines = re.findall(r'\n', spaces)
                if newlines:
                    self.lineno += len(newlines)
                input__ = self.input_

            match = re.match(r'^/(?:\*(?:.|\n)*?\*/|/.*)', input__)
            if not match:
                break
            comment = match.group(0)
            self.cursor += len(comment)
            newlines = re.findall(r'\n', comment)
            if newlines:
                self.lineno += len(newlines)

        self.token_index = (self.token_index + 1) & 3
        token = self.tokens.get(self.token_index)
        if not token:
            token = Object()
            self.tokens[self.token_index] = token

        if not input__:
            token.type_ = END
            return END

        def match_input():
            match_result = fpRegExp.match(input__)
            if match_result:
                token.type_ = NUMBER
                token.value = float(match_result.group(0))
                return match_result.group(0)

            match_result = re.match(r'^0[0-7]+', input__)
            if match_result:
                token.type_ = NUMBER
                # octal. 077 does not work in python 3 but 0o77 works in
                # python 2 and 3
                token.value = eval("0o" + match_result.group(0)[1:])
                return match_result.group(0)

            match_result = re.match(r'^0[xX][\da-fA-F]+|^\d+', input__)
            if match_result:
                token.type_ = NUMBER
                token.value = eval(match_result.group(0))
                return match_result.group(0)

            match_result = re.match(r'^[$_\w]+', input__)  # FIXME no ES3 unicode
            if match_result:
                id_ = match_result.group(0)
                token.type_ = keywords.get(id_, IDENTIFIER)
                token.value = id_
                return match_result.group(0)

            match_result = re.match(r'^"(?:\\.|[^"])*"|^\'(?:\\.|[^\'])*\'', input__)
            if match_result:
                token.type_ = STRING
                token.value = eval(match_result.group(0))
                return match_result.group(0)

            if self.scan_operand:
                match_result = reRegExp.match(input__)
                if match_result:
                    token.type_ = REGEXP
                    token.value = {"regexp": match_result.group(1), "modifiers": match_result.group(2)}
                    return match_result.group(0)

            match_result = opRegExp.match(input__)
            if match_result:
                op_value = match_result.group(0)
                if op_value in assign_ops and input__[len(op_value)] == '=':
                    token.type_ = ASSIGN
                    token.assign_op = globals()[opTypeNames[op_value]]
                    token.value = op_value
                    return match_result.group(0) + "="
                token.type_ = globals()[opTypeNames[op_value]]
                if self.scan_operand and (token.type_ in (PLUS, MINUS)):
                    token.type_ += UNARY_PLUS - PLUS
                token.assign_op = None
                token.value = op_value
                return match_result.group(0)

            if self.scan_new_lines:
                match_result = re.match(r'^\n', input__)
                if match_result:
                    token.type_ = NEWLINE
                    return match_result.group(0)

            raise self.new_syntax_error("Illegal token")

        token.start = self.cursor
        self.cursor += len(match_input())
        token.end = self.cursor
        token.lineno = self.lineno
        return getattr(token, "type_", None)

    def unget(self):
        self.lookahead += 1
        if self.lookahead == 4:
            raise Exception("PANIC: too much lookahead!")
        self.token_index = (self.token_index - 1) & 3

    def new_syntax_error(self, msg):
        return SyntaxError_(msg, self.filename, self.lineno)


class CompilerContext(object):
    def __init__(self, in_function):
        self.in_function = in_function
        self.stmt_stack = []
        self.fun_decls = []
        self.var_decls = []
        self.bracket__level = 0
        self.curly_level = 0
        self.paren_level = 0
        self.hook_level = 0
        self.ecma_strict_mode = False
        self.in_for_loop_init = False


def new_script(item_2, oper):
    n_ident = statements(item_2, oper)
    n_ident.type_ = SCRIPT
    n_ident.fun_decls = oper.fun_decls
    n_ident.var_decls = oper.var_decls
    return n_ident


class Node(list):
    def __init__(self, item_2, type_=None, args=[]):
        list.__init__(self)

        token = item_2.token
        if token:
            if type_:
                self.type_ = type_
            else:
                self.type_ = getattr(token, "type_", None)
            self.value = token.value
            self.lineno = token.lineno
            self.start = token.start
            self.end = token.end
        else:
            self.type_ = type_
            self.lineno = item_2.lineno
        self.tokenizer = item_2

        for arg in args:
            self.append(arg)

    type = property(lambda self: tokenstr(self.type_))

    # Always use push to add operands to an expression, to update start and end.
    def append(self, kid, numbers=[]):
        if kid:
            if hasattr(self, "start") and kid.start < self.start:
                self.start = kid.start
            if hasattr(self, "end") and self.end < kid.end:
                self.end = kid.end
        return list.append(self, kid)

    indent_level = 0

    def __str__(self):
        enum_list = list((str(i), v) for i, v in enumerate(self))
        for attr in dir(self):
            if attr[0] == "_":
                continue
            elif attr == "tokenizer":
                enum_list.append((attr, "[object Object]"))
            elif attr in (
                    "append", "count", "extend", "get_source", "index",
                    "insert", "pop", "remove", "reverse", "sort", "type_",
                    "target", "filename", "indent_level", "type"
            ):
                continue
            else:
                enum_list.append((attr, getattr(self, attr)))

        if len(self):
            enum_list.append(("length", len(self)))
        enum_list.sort(key=lambda item: item[0])
        identation = "    "
        Node.indent_level += 1
        n_ident = Node.indent_level
        node_ident = "{\n%stype: %s" % ((identation * n_ident), tokenstr(self.type_))
        for i, value in enum_list:
            node_ident += ",\n%s%s: " % ((identation * n_ident), i)
            if i == "value" and self.type_ == REGEXP:
                node_ident += "/%s/%s" % (value["regexp"], value["modifiers"])
            elif value is None:
                node_ident += "null"
            elif value is False:
                node_ident += "false"
            elif value is True:
                node_ident += "true"
            elif type(value) == list:
                node_ident += ','.join((str(oper) for oper in value))
            else:
                node_ident += str(value)

        Node.indent_level -= 1
        n_ident = Node.indent_level
        node_ident += "\n%s}" % (identation * n_ident)
        return node_ident

    __repr__ = __str__

    def get_source(self):
        if getattr(self, "start", None) is not None:
            if getattr(self, "end", None) is not None:
                return self.tokenizer.source[self.start:self.end]
            return self.tokenizer.source[self.start:]
        if getattr(self, "end", None) is not None:
            return self.tokenizer.source[:self.end]
        return self.tokenizer.source[:]

    filename = property(lambda self: self.tokenizer.filename)

    def __bool__(self):
        return True


# statement stack and nested statement handler.
def nest(item_2, oper, node, func, end=None):
    oper.stmt_stack.append(node)
    n_ident = func(item_2, oper)
    oper.stmt_stack.pop()
    if end:
        item_2.must_match(end)
    return n_ident


def tokenstr(match_var):
    item_2 = tokens[match_var]
    if re.match(r'^\W', item_2):
        return opTypeNames[item_2]
    return item_2.upper()


def statements(item_2, oper):
    n_ident = Node(item_2, BLOCK)
    oper.stmt_stack.append(n_ident)
    while not item_2.done and item_2.peek() != RIGHT_CURLY:
        n_ident.append(statement(item_2, oper))
    oper.stmt_stack.pop()
    return n_ident


def block(item_2, oper):
    item_2.must_match(LEFT_CURLY)
    n_ident = statements(item_2, oper)
    item_2.must_match(RIGHT_CURLY)
    return n_ident


DECLARED_FORM = 0
EXPRESSED_FORM = 1
STATEMENT_FORM = 2


def statement(item_2, oper):
    match_var = item_2.get()

    # Cases for statements ending in a right curly return early, avoiding the
    # common semicolon insertion magic after this switch.
    if match_var == FUNCTION:
        if len(oper.stmt_stack) > 1:
            type_ = STATEMENT_FORM
        else:
            type_ = DECLARED_FORM
        return function_definition(item_2, oper, True, type_)

    elif match_var == LEFT_CURLY:
        n_ident = statements(item_2, oper)
        item_2.must_match(RIGHT_CURLY)
        return n_ident

    elif match_var == IF:
        n_ident = Node(item_2)
        n_ident.condition = paren_expression(item_2, oper)
        oper.stmt_stack.append(n_ident)
        n_ident.then_part = statement(item_2, oper)
        if item_2.match(ELSE):
            n_ident.else_part = statement(item_2, oper)
        else:
            n_ident.else_part = None
        oper.stmt_stack.pop()
        return n_ident

    elif match_var == SWITCH:
        n_ident = Node(item_2)
        item_2.must_match(LEFT_PAREN)
        n_ident.discriminant = expression(item_2, oper)
        item_2.must_match(RIGHT_PAREN)
        n_ident.cases = []
        n_ident.default_index = -1
        oper.stmt_stack.append(n_ident)
        item_2.must_match(LEFT_CURLY)
        while True:
            match_var = item_2.get()
            if match_var == RIGHT_CURLY:
                break

            if match_var in (DEFAULT, CASE):
                if match_var == DEFAULT and n_ident.default_index >= 0:
                    raise item_2.new_syntax_error("More than one switch default")
                node_2 = Node(item_2)
                if match_var == DEFAULT:
                    n_ident.default_index = len(n_ident.cases)
                else:
                    node_2.case_label = expression(item_2, oper, COLON)
            else:
                raise item_2.new_syntax_error("Invalid switch case")
            item_2.must_match(COLON)
            node_2.statements = Node(item_2, BLOCK)
            while True:
                match_var = item_2.peek()
                if match_var == CASE or match_var == DEFAULT or match_var == RIGHT_CURLY:
                    break
                node_2.statements.append(statement(item_2, oper))
            n_ident.cases.append(node_2)
        oper.stmt_stack.pop()
        return n_ident

    elif match_var == FOR:
        n_ident = Node(item_2)
        node_2 = None
        n_ident.is_loop = True
        item_2.must_match(LEFT_PAREN)
        match_var = item_2.peek()
        if match_var != SEMICOLON:
            oper.in_for_loop_init = True
            if match_var == VAR or match_var == CONST:
                item_2.get()
                node_2 = variables(item_2, oper)
            else:
                node_2 = expression(item_2, oper)
            oper.in_for_loop_init = False

        if node_2 and item_2.match(IN):
            n_ident.type_ = FOR_IN
            if node_2.type_ == VAR:
                if len(node_2) != 1:
                    raise SyntaxError("Invalid for..in left-hand side", item_2.filename, node_2.lineno)

                # NB: node_2[0].type_ == INDENTIFIER and node_2[0].value == node_2[0].name
                n_ident.iterator = node_2[0]
                n_ident.var_decl = node_2
            else:
                n_ident.iterator = node_2
                n_ident.var_decl = None
            n_ident.object = expression(item_2, oper)
        else:
            if node_2:
                n_ident.setup = node_2
            else:
                n_ident.setup = None
            item_2.must_match(SEMICOLON)
            if item_2.peek() == SEMICOLON:
                n_ident.condition = None
            else:
                n_ident.condition = expression(item_2, oper)
            item_2.must_match(SEMICOLON)
            if item_2.peek() == RIGHT_PAREN:
                n_ident.update = None
            else:
                n_ident.update = expression(item_2, oper)
        item_2.must_match(RIGHT_PAREN)
        n_ident.body = nest(item_2, oper, n_ident, statement)
        return n_ident

    elif match_var == WHILE:
        n_ident = Node(item_2)
        n_ident.is_loop = True
        n_ident.condition = paren_expression(item_2, oper)
        n_ident.body = nest(item_2, oper, n_ident, statement)
        return n_ident

    elif match_var == DO:
        n_ident = Node(item_2)
        n_ident.is_loop = True
        n_ident.body = nest(item_2, oper, n_ident, statement, WHILE)
        n_ident.condition = paren_expression(item_2, oper)
        if not oper.ecma_strict_mode:
            # <script language="JavaScript"> (without version hints) may need
            # automatic semicolon insertion without a newline after do-while.
            # See http://bugzilla.mozilla.org/show_bug.cgi?id=238945.
            item_2.match(SEMICOLON)
            return n_ident

    elif match_var in (BREAK, CONTINUE):
        n_ident = Node(item_2)
        if item_2.peek_on_same_line() == IDENTIFIER:
            item_2.get()
            n_ident.label = item_2.token.value
        stmt_s = oper.stmt_stack
        i = len(stmt_s)
        label = getattr(n_ident, "label", None)
        if label:
            while True:
                i -= 1
                if i < 0:
                    raise item_2.new_syntax_error("Label not found")
                if getattr(stmt_s[i], "label", None) == label:
                    break
        else:
            while True:
                i -= 1
                if i < 0:
                    if match_var == BREAK:
                        raise item_2.new_syntax_error("Invalid break")
                    else:
                        raise item_2.new_syntax_error("Invalid continue")
                if getattr(stmt_s[i], "is_loop", None) or (match_var == BREAK and stmt_s[i].type_ == SWITCH):
                    break
        n_ident.target = stmt_s[i]

    elif match_var == TRY:
        n_ident = Node(item_2)
        n_ident.try_block = block(item_2, oper)
        n_ident.catch_clauses = []
        while item_2.match(CATCH):
            node_2 = Node(item_2)
            item_2.must_match(LEFT_PAREN)
            node_2.var_name = item_2.must_match(IDENTIFIER).value
            if item_2.match(IF):
                if oper.ecma_strict_mode:
                    raise item_2.new_syntax_error("Illegal catch guard")
                if n_ident.catch_clauses and not n_ident.catch_clauses[-1].guard:
                    raise item_2.new_syntax_error("Gaurded catch after unguarded")
                node_2.guard = expression(item_2, oper)
            else:
                node_2.guard = None
            item_2.must_match(RIGHT_PAREN)
            node_2.block = block(item_2, oper)
            n_ident.catch_clauses.append(node_2)
        if item_2.match(FINALLY):
            n_ident.finally_block = block(item_2, oper)
        if not n_ident.catch_clauses and not getattr(n_ident, "finally_block", None):
            raise item_2.new_syntax_error("Invalid try statement")
        return n_ident

    elif match_var in (CATCH, FINALLY):
        raise item_2.new_syntax_error(tokens[match_var] + " without preceding try")

    elif match_var == THROW:
        n_ident = Node(item_2)
        n_ident.exception = expression(item_2, oper)

    elif match_var == RETURN:
        if not oper.in_function:
            raise item_2.new_syntax_error("Invalid return")
        n_ident = Node(item_2)
        match_var = item_2.peek_on_same_line()
        if match_var not in (END, NEWLINE, SEMICOLON, RIGHT_CURLY):
            n_ident.value = expression(item_2, oper)

    elif match_var == WITH:
        n_ident = Node(item_2)
        n_ident.object = paren_expression(item_2, oper)
        n_ident.body = nest(item_2, oper, n_ident, statement)
        return n_ident

    elif match_var in (VAR, CONST):
        n_ident = variables(item_2, oper)

    elif match_var == DEBUGGER:
        n_ident = Node(item_2)

    elif match_var in (NEWLINE, SEMICOLON):
        n_ident = Node(item_2, SEMICOLON)
        n_ident.expression = None
        return n_ident

    else:
        if match_var == IDENTIFIER:
            item_2.scan_operand = False
            match_var = item_2.peek()
            item_2.scan_operand = True
            if match_var == COLON:
                label = item_2.token.value
                stmt_s = oper.stmt_stack
                i = len(stmt_s) - 1
                while i >= 0:
                    if getattr(stmt_s[i], "label", None) == label:
                        raise item_2.new_syntax_error("Duplicate label")
                    i -= 1
                item_2.get()
                n_ident = Node(item_2, LABEL)
                n_ident.label = label
                n_ident.statement = nest(item_2, oper, n_ident, statement)
                return n_ident

        n_ident = Node(item_2, SEMICOLON)
        item_2.unget()
        n_ident.expression = expression(item_2, oper)
        n_ident.end = n_ident.expression.end

    if item_2.lineno == item_2.token.lineno:
        match_var = item_2.peek_on_same_line()
        if match_var not in (END, NEWLINE, SEMICOLON, RIGHT_CURLY):
            raise item_2.new_syntax_error("Missing ; before statement")
    item_2.match(SEMICOLON)
    return n_ident


def function_definition(item_2, oper, require_name, function_form):
    init_node = Node(item_2)
    if init_node.type_ != FUNCTION:
        if init_node.value == "get":
            init_node.type_ = GETTER
        else:
            init_node.type_ = SETTER
    if item_2.match(IDENTIFIER):
        init_node.name = item_2.token.value
    elif require_name:
        raise item_2.new_syntax_error("Missing function identifier")

    item_2.must_match(LEFT_PAREN)
    init_node.params = []
    while True:
        match_var = item_2.get()
        if match_var == RIGHT_PAREN:
            break
        if match_var != IDENTIFIER:
            raise item_2.new_syntax_error("Missing formal parameter")
        init_node.params.append(item_2.token.value)
        if item_2.peek() != RIGHT_PAREN:
            item_2.must_match(COMMA)

    item_2.must_match(LEFT_CURLY)
    oper_2 = CompilerContext(True)
    init_node.body = new_script(item_2, oper_2)
    item_2.must_match(RIGHT_CURLY)
    init_node.end = item_2.token.end

    init_node.function_form = function_form
    if function_form == DECLARED_FORM:
        oper.fun_decls.append(init_node)
    return init_node


def variables(item_2, oper):
    n_ident = Node(item_2)
    while True:
        item_2.must_match(IDENTIFIER)
        node_2 = Node(item_2)
        node_2.name = node_2.value
        if item_2.match(ASSIGN):
            if item_2.token.assign_op:
                raise item_2.new_syntax_error("Invalid variable initialization")
            node_2.initializer = expression(item_2, oper, COMMA)
        node_2.read_only = not not (n_ident.type_ == CONST)
        n_ident.append(node_2)
        oper.var_decls.append(node_2)
        if not item_2.match(COMMA):
            break
    return n_ident


def paren_expression(item_2, oper):
    item_2.must_match(LEFT_PAREN)
    n_ident = expression(item_2, oper)
    item_2.must_match(RIGHT_PAREN)
    return n_ident


opPrecedence = {
    "SEMICOLON": 0,
    "COMMA": 1,
    "ASSIGN": 2, "HOOK": 2, "COLON": 2,
    # The above all have to have the same precedence, see bug 330975.
    "OR": 4,
    "AND": 5,
    "BITWISE_OR": 6,
    "BITWISE_XOR": 7,
    "BITWISE_AND": 8,
    "EQ": 9, "NE": 9, "STRICT_EQ": 9, "STRICT_NE": 9,
    "LT": 10, "LE": 10, "GE": 10, "GT": 10, "IN": 10, "INSTANCEOF": 10,
    "LSH": 11, "RSH": 11, "URSH": 11,
    "PLUS": 12, "MINUS": 12,
    "MUL": 13, "DIV": 13, "MOD": 13,
    "DELETE": 14, "VOID": 14, "TYPEOF": 14,
    # "PRE_INCREMENT": 14, "PRE_DECREMENT": 14,
    "NOT": 14, "BITWISE_NOT": 14, "UNARY_PLUS": 14, "UNARY_MINUS": 14,
    "INCREMENT": 15, "DECREMENT": 15,  # postfix
    "NEW": 16,
    "DOT": 17
}

# Map operator type code to precedence
for i in opPrecedence.copy():
    opPrecedence[globals()[i]] = opPrecedence[i]

opArity = {
    "COMMA": -2,
    "ASSIGN": 2,
    "HOOK": 3,
    "OR": 2,
    "AND": 2,
    "BITWISE_OR": 2,
    "BITWISE_XOR": 2,
    "BITWISE_AND": 2,
    "EQ": 2, "NE": 2, "STRICT_EQ": 2, "STRICT_NE": 2,
    "LT": 2, "LE": 2, "GE": 2, "GT": 2, "IN": 2, "INSTANCEOF": 2,
    "LSH": 2, "RSH": 2, "URSH": 2,
    "PLUS": 2, "MINUS": 2,
    "MUL": 2, "DIV": 2, "MOD": 2,
    "DELETE": 1, "VOID": 1, "TYPEOF": 1,
    # "PRE_INCREMENT": 1, "PRE_DECREMENT": 1,
    "NOT": 1, "BITWISE_NOT": 1, "UNARY_PLUS": 1, "UNARY_MINUS": 1,
    "INCREMENT": 1, "DECREMENT": 1,  # postfix
    "NEW": 1, "NEW_WITH_ARGS": 2, "DOT": 2, "INDEX": 2, "CALL": 2,
    "ARRAY_INIT": 1, "OBJECT_INIT": 1, "GROUP": 1
}

# Map operator type code to arity.
for i in opArity.copy():
    opArity[globals()[i]] = opArity[i]


def expression(item_2, oper, stop=None):
    operators = []
    operands = []
    br_level = oper.bracket__level
    cur_level = oper.curly_level
    par_levl = oper.paren_level
    hk_levle = oper.hook_level

    def reduce_():
        n_ident = operators.pop()
        op_value = n_ident.type_
        arity = opArity[op_value]
        if arity == -2:
            # Flatten left-associative trees.
            left = (len(operands) >= 2 and operands[-2])
            if left.type_ == op_value:
                right = operands.pop()
                left.append(right)
                return left
            arity = 2

        # Always use append to add operands to n_ident, to update start and end.
        enum_list = operands[-arity:]
        del operands[-arity:]
        for operand in enum_list:
            n_ident.append(operand)

        # Include closing bracket or postfix operator in [start,end).
        if n_ident.end < item_2.token.end:
            n_ident.end = item_2.token.end

        operands.append(n_ident)
        return n_ident

    class BreakOutOfLoops(Exception):
        pass

    try:
        while True:
            match_var = item_2.get()
            if match_var == END:
                break

            if (match_var == stop and oper.bracket__level == br_level and oper.curly_level == cur_level and
                    oper.paren_level == par_levl and oper.hook_level == hk_levle):
                # Stop only if match_var matches the optional stop parameter, and that
                # token is not quoted by some kind of bracket.
                break
            if match_var == SEMICOLON:
                # NB: cannot be empty, statement handled that.
                raise BreakOutOfLoops

            elif match_var in (ASSIGN, HOOK, COLON):
                if item_2.scan_operand:
                    raise BreakOutOfLoops
                while (
                    (operators and opPrecedence.get(operators[-1].type_, -1) > opPrecedence.get(match_var, -1)) or
                    (match_var == COLON and operators and operators[-1].type_ == ASSIGN)
                ):
                    reduce_()
                if match_var == COLON:
                    if operators:
                        n_ident = operators[-1]
                    if not operators or n_ident.type_ != HOOK:
                        raise item_2.new_syntax_error("Invalid label")
                    oper.hook_level -= 1
                else:
                    operators.append(Node(item_2))
                    if match_var == ASSIGN:
                        operands[-1].assign_op = item_2.token.assign_op
                    else:
                        oper.hook_level += 1

                item_2.scan_operand = True

            elif match_var in (
                    IN, COMMA, OR, AND, BITWISE_OR, BITWISE_XOR, BITWISE_AND, EQ, NE, STRICT_EQ, STRICT_NE, LT, LE, GE,
                    GT, INSTANCEOF, LSH, RSH, URSH, PLUS, MINUS, MUL, DIV, MOD, DOT
            ):
                # We're treating comma as left-associative so reduce can fold
                # left-heavy COMMA trees into a single array.
                if match_var == IN:
                    # An in operator should not be parsed if we're parsing the
                    # head of a for (...) loop, unless it is in the then part of
                    # a conditional expression, or parenthesized somehow.
                    if oper.in_for_loop_init and not oper.hook_level and not oper.bracket__level and \
                            not oper.curly_level and not oper.paren_level:
                        raise BreakOutOfLoops

                if item_2.scan_operand:
                    raise BreakOutOfLoops
                while operators and opPrecedence.get(operators[-1].type_, -1) and (
                    opPrecedence.get(operators[-1].type_, -1) >= opPrecedence.get(match_var, -1)
                ):
                    reduce_()
                if match_var == DOT:
                    item_2.must_match(IDENTIFIER)
                    operands.append(Node(item_2, DOT, [operands.pop(), Node(item_2)]))
                else:
                    operators.append(Node(item_2))
                    item_2.scan_operand = True

            elif match_var in (
                    DELETE, VOID, TYPEOF, NOT, BITWISE_NOT, UNARY_PLUS, UNARY_MINUS, NEW
            ):
                if not item_2.scan_operand:
                    raise BreakOutOfLoops
                operators.append(Node(item_2))

            elif match_var in (INCREMENT, DECREMENT):
                if item_2.scan_operand:
                    operators.append(Node(item_2))  # prefix increment or decrement
                else:
                    # Don'item_2 cross a line boundary for postfix {in,de}crement.
                    if item_2.tokens.get((item_2.token_index + item_2.lookahead - 1) & 3).lineno != item_2.lineno:
                        raise BreakOutOfLoops

                    # Use >, not >=, so postfix has higher precedence than
                    # prefix.
                    while operators and opPrecedence.get(operators[-1].type_, -1) > opPrecedence.get(match_var, -1):
                        reduce_()
                    n_ident = Node(item_2, match_var, [operands.pop()])
                    n_ident.postfix = True
                    operands.append(n_ident)

            elif match_var == FUNCTION:
                if not item_2.scan_operand:
                    raise BreakOutOfLoops
                operands.append(function_definition(item_2, oper, False, EXPRESSED_FORM))
                item_2.scan_operand = False

            elif match_var in (NULL, THIS, TRUE, FALSE, IDENTIFIER, NUMBER, STRING, REGEXP):
                if not item_2.scan_operand:
                    raise BreakOutOfLoops
                operands.append(Node(item_2))
                item_2.scan_operand = False

            elif match_var == LEFT_BRACKET:
                if item_2.scan_operand:
                    # Array initializer. Parse using recursive descent, as the
                    # sub-grammer here is not an operator grammar.
                    n_ident = Node(item_2, ARRAY_INIT)
                    while True:
                        match_var = item_2.peek()
                        if match_var == RIGHT_BRACKET:
                            break
                        if match_var == COMMA:
                            item_2.get()
                            n_ident.append(None)
                            continue
                        n_ident.append(expression(item_2, oper, COMMA))
                        if not item_2.match(COMMA):
                            break

                    item_2.must_match(RIGHT_BRACKET)
                    operands.append(n_ident)
                    item_2.scan_operand = False
                else:
                    operators.append(Node(item_2, INDEX))
                    item_2.scan_operand = True
                    oper.bracket__level += 1

            elif match_var == RIGHT_BRACKET:
                if item_2.scan_operand or oper.bracket__level == br_level:
                    raise BreakOutOfLoops
                while reduce_().type_ != INDEX:
                    continue
                oper.bracket__level -= 1

            elif match_var == LEFT_CURLY:
                if not item_2.scan_operand:
                    raise BreakOutOfLoops
                # Object initializer. As for array initializers (see above),
                # parse using recursive descent.
                oper.curly_level += 1
                n_ident = Node(item_2, OBJECT_INIT)

                class BreakOutOfObjectInit(Exception):
                    pass

                try:
                    if not item_2.match(RIGHT_CURLY):
                        while True:
                            match_var = item_2.get()
                            if (item_2.token.value == "get" or item_2.token.value == "set") and item_2.peek == IDENTIFIER:
                                if oper.ecma_strict_mode:
                                    raise item_2.new_syntax_error("Illegal property accessor")
                                n_ident.append(function_definition(item_2, oper, True, EXPRESSED_FORM))
                            else:
                                if match_var in (IDENTIFIER, NUMBER, STRING):
                                    id_ = Node(item_2)
                                elif match_var == RIGHT_CURLY:
                                    if oper.ecma_strict_mode:
                                        raise item_2.new_syntax_error("Illegal trailing ,")
                                    raise BreakOutOfObjectInit
                                else:
                                    raise item_2.new_syntax_error("Invalid property name")
                                item_2.must_match(COLON)
                                n_ident.append(Node(item_2, PROPERTY_INIT, [id_, expression(item_2, oper, COMMA)]))

                            if not item_2.match(COMMA):
                                break
                        item_2.must_match(RIGHT_CURLY)
                except BreakOutOfObjectInit as exc:
                    pass
                operands.append(n_ident)
                item_2.scan_operand = False
                oper.curly_level -= 1

            elif match_var == RIGHT_CURLY:
                if not item_2.scan_operand and oper.curly_level != cur_level:
                    raise ParseError("PANIC: right curly botch")
                raise BreakOutOfLoops

            elif match_var == LEFT_PAREN:
                if item_2.scan_operand:
                    operators.append(Node(item_2, GROUP))
                    oper.paren_level += 1
                else:
                    while operators and opPrecedence.get(operators[-1].type, -1) > opPrecedence[NEW]:
                        reduce_()

                    # Handle () now, to regularize the n_ident-ary case for n_ident > 0.
                    # We must set scan_operand in case there are arguments and
                    # the first one is a regexp or unary+/-.
                    if operators:
                        n_ident = operators[-1]
                    else:
                        n_ident = Object()
                        n_ident.type_ = None
                    item_2.scan_operand = True
                    if item_2.match(RIGHT_PAREN):
                        if n_ident.type_ == NEW:
                            operators.pop()
                            n_ident.append(operands.pop())
                        else:
                            n_ident = Node(item_2, CALL, [operands.pop(), Node(item_2, LIST)])
                        operands.append(n_ident)
                        item_2.scan_operand = False
                    else:
                        if n_ident.type_ == NEW:
                            n_ident.type_ = NEW_WITH_ARGS
                        else:
                            operators.append(Node(item_2, CALL))
                        oper.paren_level += 1

            elif match_var == RIGHT_PAREN:
                if item_2.scan_operand or oper.paren_level == par_levl:
                    raise BreakOutOfLoops
                while True:
                    match_var = reduce_().type_
                    if match_var in (GROUP, CALL, NEW_WITH_ARGS):
                        break
                if match_var != GROUP:
                    if operands:
                        n_ident = operands[-1]
                        if n_ident[1].type_ != COMMA:
                            n_ident[1] = Node(item_2, LIST, [n_ident[1]])
                        else:
                            n_ident[1].type_ = LIST
                    else:
                        raise ParseError("Unexpected amount of operands")
                oper.paren_level -= 1

            # Automatic semicolon insertion means we may scan across a newline
            # and into the beginning of another statement. If so, break out of
            # the while loop and let the item_2.scan_operand logic handle errors.
            else:
                raise BreakOutOfLoops
    except BreakOutOfLoops as exc:
        pass

    if oper.hook_level != hk_levle:
        raise item_2.new_syntax_error("Missing : after ?")
    if oper.paren_level != par_levl:
        raise item_2.new_syntax_error("Missing ) in parenthetical")
    if oper.bracket__level != br_level:
        raise item_2.new_syntax_error("Missing ] in index expression")
    if item_2.scan_operand:
        raise item_2.new_syntax_error("Missing operand")

    item_2.scan_operand = True
    item_2.unget()
    while operators:
        reduce_()
    return operands.pop()


def parse(source, filename=None, starting_line_number=1):
    """Parse some Javascript

    Args:
        source: the Javascript source, as a string
        filename: the filename to include in messages
        starting_line_number: the line number of the first line of the
            passed in source, for output messages
    Returns:
        the parsed source code data structure
    Raises:
        ParseError
    """
    item_2 = Tokenizer(source, filename, starting_line_number)
    oper = CompilerContext(False)
    n_ident = new_script(item_2, oper)
    if not item_2.done:
        raise item_2.new_syntax_error("Syntax error")
    return n_ident


if __name__ == "__main__":
    print(str(parse(open(sys.argv[1]).read(), sys.argv[1])))
