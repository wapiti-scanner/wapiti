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


class BaseError(Exception):
    pass


class ParseError(BaseError):
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
operator_type_names = [
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
for token_id, token_name in tokens.copy().items():
    if re.match(r'^[a-z]', token_name):
        const_name = token_name.upper()
        keywords[token_name] = token_id
    elif re.match(r'^\W', token_name):
        const_name = dict(operator_type_names)[token_name]
    else:
        const_name = token_name
    globals()[const_name] = token_id
    tokens[token_name] = token_id

assign_ops = {}

# Map assignment operators to their indexes in the tokens array.
for token_id, token_name in enumerate(['|', '^', '&', '<<', '>>', '>>>', '+', '-', '*', '/', '%']):
    assign_ops[token_name] = tokens[token_name]
    assign_ops[token_id] = token_name

# Build a regexp that recognizes operators and punctuators (except newline).
op_regexp_src = "^"
for token, __ in operator_type_names:
    if token == "\n":
        continue
    if op_regexp_src != "^":
        op_regexp_src += "|^"
    op_regexp_src += re.sub(r'[?|^&(){}\[\]+\-*/.]', lambda oper: "\\%s" % oper.group(0), token)
op_regexp = re.compile(op_regexp_src)

# Convert opTypeNames to an actual dictionary now that we don't care about ordering
operator_type_names = dict(operator_type_names)

# A regexp to match floating point literals (but not integer literals).
float_regexp = re.compile(r'^\d+\.\d*(?:[eE][-+]?\d+)?|^\d+(?:\.\d*)?[eE][-+]?\d+|^\.\d+(?:[eE][-+]?\d+)?')

# A regexp to match regexp literals.
re_regexp = re.compile(r'^/((?:\\.|\[(?:\\.|[^\]])*\]|[^/])+)/([gimy]*)')


class JavascriptSyntaxError(ParseError):
    def __init__(self, message, filename, lineno):
        ParseError.__init__(self, "Syntax error: %s\n%s:%s" %
                                  (message, filename, lineno))


class Tokenizer(object):
    def __init__(self, source, filename, starting_line_number):
        self.cursor = 0
        self.source = str(source)
        self.tokens = {}
        self.token_index = 0
        self.lookahead = 0
        self.scan_new_lines = False
        self.scan_operand = True
        self.filename = filename
        self.lineno = starting_line_number

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
                match = re.match(r'^[ \t]+', input__)
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
            match_result = float_regexp.match(input__)
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
                match_result = re_regexp.match(input__)
                if match_result:
                    token.type_ = REGEXP
                    token.value = {"regexp": match_result.group(1), "modifiers": match_result.group(2)}
                    return match_result.group(0)

            match_result = op_regexp.match(input__)
            if match_result:
                op_value = match_result.group(0)

                if op_value in assign_ops and input__[len(op_value)] == '=':
                    token.type_ = ASSIGN
                    token.assign_op = globals()[operator_type_names[op_value]]
                    token.value = op_value
                    return match_result.group(0) + "="

                token.type_ = globals()[operator_type_names[op_value]]
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
        return JavascriptSyntaxError(msg, self.filename, self.lineno)


class CompilerContext(object):
    def __init__(self, in_function):
        self.inFunction = in_function
        self.stmt_stack = []
        self.fun_decls = []
        self.var_decls = []
        self.bracket_level = 0
        self.curly_level = 0
        self.paren_level = 0
        self.hook_level = 0
        self.ecma_strict_mode = False
        self.in_for_loop_init = False


def new_script(tokenizer, context):
    node = statements(tokenizer, context)
    node.type_ = SCRIPT
    node.fun_decls = context.fun_decls
    node.var_decls = context.var_decls
    return node


class Node(list):
    def __init__(self, tokenizer, type_=None, args=[]):
        list.__init__(self)

        token = tokenizer.token
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
            self.lineno = tokenizer.lineno
        self.tokenizer = tokenizer

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
        indentation = "    "
        Node.indent_level += 1
        node_indent = Node.indent_level
        node_repr = "{\n%stype: %s" % ((indentation * node_indent), tokenstr(self.type_))

        for i, value in enum_list:
            node_repr += ",\n%s%s: " % ((indentation * node_indent), i)
            if i == "value" and self.type_ == REGEXP:
                node_repr += "/%s/%s" % (value["regexp"], value["modifiers"])
            elif value is None:
                node_repr += "null"
            elif value is False:
                node_repr += "false"
            elif value is True:
                node_repr += "true"
            elif type(value) == list:
                node_repr += ','.join((str(oper) for oper in value))
            else:
                node_repr += str(value)

        Node.indent_level -= 1
        node_indent = Node.indent_level
        node_repr += "\n%s}" % (indentation * node_indent)
        return node_repr

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
def nest(tokenizer, context, node, func, end=None):
    context.stmt_stack.append(node)
    node = func(tokenizer, context)
    context.stmt_stack.pop()
    if end:
        tokenizer.must_match(end)
    return node


def tokenstr(token_type):
    token_repr = tokens[token_type]
    if re.match(r'^\W', token_repr):
        return operator_type_names[token_repr]
    return token_repr.upper()


def statements(tokenizer, context):
    node = Node(tokenizer, BLOCK)
    context.stmt_stack.append(node)
    while not tokenizer.done and tokenizer.peek() != RIGHT_CURLY:
        node.append(statement(tokenizer, context))
    context.stmt_stack.pop()
    return node


def block(tokenizer, context):
    tokenizer.must_match(LEFT_CURLY)
    node = statements(tokenizer, context)
    tokenizer.must_match(RIGHT_CURLY)
    return node


DECLARED_FORM = 0
EXPRESSED_FORM = 1
STATEMENT_FORM = 2


def statement(tokenizer, context):
    token_type = tokenizer.get()

    # Cases for statements ending in a right curly return early, avoiding the
    # common semicolon insertion magic after this switch.
    if token_type == FUNCTION:
        if len(context.stmt_stack) > 1:
            type_ = STATEMENT_FORM
        else:
            type_ = DECLARED_FORM
        return function_definition(tokenizer, context, True, type_)

    elif token_type == LEFT_CURLY:
        node = statements(tokenizer, context)
        tokenizer.must_match(RIGHT_CURLY)
        return node

    elif token_type == IF:
        node = Node(tokenizer)
        node.condition = paren_expression(tokenizer, context)
        context.stmt_stack.append(node)
        node.then_part = statement(tokenizer, context)
        if tokenizer.match(ELSE):
            node.else_part = statement(tokenizer, context)
        else:
            node.else_part = None
        context.stmt_stack.pop()
        return node

    elif token_type == SWITCH:
        node = Node(tokenizer)
        tokenizer.must_match(LEFT_PAREN)
        node.discriminant = expression(tokenizer, context)
        tokenizer.must_match(RIGHT_PAREN)
        node.cases = []
        node.default_index = -1
        context.stmt_stack.append(node)
        tokenizer.must_match(LEFT_CURLY)
        while True:
            token_type = tokenizer.get()
            if token_type == RIGHT_CURLY:
                break

            if token_type in (DEFAULT, CASE):
                if token_type == DEFAULT and node.default_index >= 0:
                    raise tokenizer.new_syntax_error("More than one switch default")
                node_2 = Node(tokenizer)
                if token_type == DEFAULT:
                    node.default_index = len(node.cases)
                else:
                    node_2.case_label = expression(tokenizer, context, COLON)
            else:
                raise tokenizer.new_syntax_error("Invalid switch case")
            tokenizer.must_match(COLON)
            node_2.statements = Node(tokenizer, BLOCK)
            while True:
                token_type = tokenizer.peek()
                if token_type == CASE or token_type == DEFAULT or token_type == RIGHT_CURLY:
                    break
                node_2.statements.append(statement(tokenizer, context))
            node.cases.append(node_2)
        context.stmt_stack.pop()
        return node

    elif token_type == FOR:
        node = Node(tokenizer)
        node_2 = None
        node.is_loop = True
        tokenizer.must_match(LEFT_PAREN)
        token_type = tokenizer.peek()
        if token_type != SEMICOLON:
            context.in_for_loop_init = True
            if token_type == VAR or token_type == CONST:
                tokenizer.get()
                node_2 = variables(tokenizer, context)
            else:
                node_2 = expression(tokenizer, context)
            context.in_for_loop_init = False

        if node_2 and tokenizer.match(IN):
            node.type_ = FOR_IN
            if node_2.type_ == VAR:
                if len(node_2) != 1:
                    raise SyntaxError("Invalid for..in left-hand side", tokenizer.filename, node_2.lineno)

                # NB: n2[0].type_ == INDENTIFIER and n2[0].value == n2[0].name
                node.iterator = node_2[0]
                node.var_decl = node_2
            else:
                node.iterator = node_2
                node.var_decl = None
            node.object = expression(tokenizer, context)
        else:
            if node_2:
                node.setup = node_2
            else:
                node.setup = None
            tokenizer.must_match(SEMICOLON)
            if tokenizer.peek() == SEMICOLON:
                node.condition = None
            else:
                node.condition = expression(tokenizer, context)
            tokenizer.must_match(SEMICOLON)
            if tokenizer.peek() == RIGHT_PAREN:
                node.update = None
            else:
                node.update = expression(tokenizer, context)
        tokenizer.must_match(RIGHT_PAREN)
        node.body = nest(tokenizer, context, node, statement)
        return node

    elif token_type == WHILE:
        node = Node(tokenizer)
        node.is_loop = True
        node.condition = paren_expression(tokenizer, context)
        node.body = nest(tokenizer, context, node, statement)
        return node

    elif token_type == DO:
        node = Node(tokenizer)
        node.is_loop = True
        node.body = nest(tokenizer, context, node, statement, WHILE)
        node.condition = paren_expression(tokenizer, context)
        if not context.ecma_strict_mode:
            # <script language="JavaScript"> (without version hints) may need
            # automatic semicolon insertion without a newline after do-while.
            # See http://bugzilla.mozilla.org/show_bug.cgi?id=238945.
            tokenizer.match(SEMICOLON)
            return node

    elif token_type in (BREAK, CONTINUE):
        node = Node(tokenizer)
        if tokenizer.peek_on_same_line() == IDENTIFIER:
            tokenizer.get()
            node.label = tokenizer.token.value

        stmt_stack = context.stmt_stack
        i = len(stmt_stack)
        label = getattr(node, "label", None)
        if label:
            while True:
                i -= 1
                if i < 0:
                    raise tokenizer.new_syntax_error("Label not found")
                if getattr(stmt_stack[i], "label", None) == label:
                    break
        else:
            while True:
                i -= 1
                if i < 0:
                    if token_type == BREAK:
                        raise tokenizer.new_syntax_error("Invalid break")
                    else:
                        raise tokenizer.new_syntax_error("Invalid continue")
                if getattr(stmt_stack[i], "is_loop", None) or (token_type == BREAK and stmt_stack[i].type_ == SWITCH):
                    break
        node.target = stmt_stack[i]

    elif token_type == TRY:
        node = Node(tokenizer)
        node.tryBlock = block(tokenizer, context)
        node.catchClauses = []

        while tokenizer.match(CATCH):
            node_2 = Node(tokenizer)
            tokenizer.must_match(LEFT_PAREN)
            node_2.varName = tokenizer.must_match(IDENTIFIER).value
            if tokenizer.match(IF):
                if context.ecma_strict_mode:
                    raise tokenizer.new_syntax_error("Illegal catch guard")
                if node.catchClauses and not node.catchClauses[-1].guard:
                    raise tokenizer.new_syntax_error("Gaurded catch after unguarded")
                node_2.guard = expression(tokenizer, context)
            else:
                node_2.guard = None
            tokenizer.must_match(RIGHT_PAREN)
            node_2.block = block(tokenizer, context)
            node.catchClauses.append(node_2)

        if tokenizer.match(FINALLY):
            node.finallyBlock = block(tokenizer, context)

        if not node.catchClauses and not getattr(node, "finallyBlock", None):
            raise tokenizer.new_syntax_error("Invalid try statement")

        return node

    elif token_type in (CATCH, FINALLY):
        raise tokenizer.new_syntax_error(tokens[token_type] + " without preceding try")

    elif token_type == THROW:
        node = Node(tokenizer)
        node.exception = expression(tokenizer, context)

    elif token_type == RETURN:
        if not context.inFunction:
            raise tokenizer.new_syntax_error("Invalid return")
        node = Node(tokenizer)
        token_type = tokenizer.peek_on_same_line()
        if token_type not in (END, NEWLINE, SEMICOLON, RIGHT_CURLY):
            node.value = expression(tokenizer, context)

    elif token_type == WITH:
        node = Node(tokenizer)
        node.object = paren_expression(tokenizer, context)
        node.body = nest(tokenizer, context, node, statement)
        return node

    elif token_type in (VAR, CONST):
        node = variables(tokenizer, context)

    elif token_type == DEBUGGER:
        node = Node(tokenizer)

    elif token_type in (NEWLINE, SEMICOLON):
        node = Node(tokenizer, SEMICOLON)
        node.expression = None
        return node

    else:
        if token_type == IDENTIFIER:
            tokenizer.scan_operand = False
            token_type = tokenizer.peek()
            tokenizer.scan_operand = True

            if token_type == COLON:
                label = tokenizer.token.value
                stmt_stack = context.stmt_stack
                i = len(stmt_stack) - 1

                while i >= 0:
                    if getattr(stmt_stack[i], "label", None) == label:
                        raise tokenizer.new_syntax_error("Duplicate label")
                    i -= 1

                tokenizer.get()
                node = Node(tokenizer, LABEL)
                node.label = label
                node.statement = nest(tokenizer, context, node, statement)
                return node

        node = Node(tokenizer, SEMICOLON)
        tokenizer.unget()
        node.expression = expression(tokenizer, context)
        node.end = node.expression.end

    if tokenizer.lineno == tokenizer.token.lineno:
        token_type = tokenizer.peek_on_same_line()
        if token_type not in (END, NEWLINE, SEMICOLON, RIGHT_CURLY):
            raise tokenizer.new_syntax_error("Missing ; before statement")
    tokenizer.match(SEMICOLON)
    return node


def function_definition(tokenizer, context, require_name, function_form):
    function_node = Node(tokenizer)
    if function_node.type_ != FUNCTION:
        if function_node.value == "get":
            function_node.type_ = GETTER
        else:
            function_node.type_ = SETTER
    if tokenizer.match(IDENTIFIER):
        function_node.name = tokenizer.token.value
    elif require_name:
        raise tokenizer.new_syntax_error("Missing function identifier")

    tokenizer.must_match(LEFT_PAREN)
    function_node.params = []
    while True:
        token_type = tokenizer.get()
        if token_type == RIGHT_PAREN:
            break
        if token_type != IDENTIFIER:
            raise tokenizer.new_syntax_error("Missing formal parameter")
        function_node.params.append(tokenizer.token.value)
        if tokenizer.peek() != RIGHT_PAREN:
            tokenizer.must_match(COMMA)

    tokenizer.must_match(LEFT_CURLY)
    context_2 = CompilerContext(True)
    function_node.body = new_script(tokenizer, context_2)
    tokenizer.must_match(RIGHT_CURLY)
    function_node.end = tokenizer.token.end

    function_node.functionForm = function_form
    if function_form == DECLARED_FORM:
        context.fun_decls.append(function_node)
    return function_node


def variables(tokenizer, context):
    node = Node(tokenizer)
    while True:
        tokenizer.must_match(IDENTIFIER)
        node_2 = Node(tokenizer)
        node_2.name = node_2.value
        if tokenizer.match(ASSIGN):
            if tokenizer.token.assign_op:
                raise tokenizer.new_syntax_error("Invalid variable initialization")
            node_2.initializer = expression(tokenizer, context, COMMA)
        node_2.readOnly = not not (node.type_ == CONST)
        node.append(node_2)
        context.var_decls.append(node_2)
        if not tokenizer.match(COMMA):
            break
    return node


def paren_expression(tokenizer, context):
    tokenizer.must_match(LEFT_PAREN)
    node = expression(tokenizer, context)
    tokenizer.must_match(RIGHT_PAREN)
    return node


operator_precedence = {
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
for token_id in operator_precedence.copy():
    operator_precedence[globals()[token_id]] = operator_precedence[token_id]

operator_arity = {
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
for token_id in operator_arity.copy():
    operator_arity[globals()[token_id]] = operator_arity[token_id]


def expression(tokenizer, context, stop=None):
    operators = []
    operands = []
    bracket_level = context.bracket_level
    curly_level = context.curly_level
    paren_level = context.paren_level
    hook_level = context.hook_level

    def reduce_():
        node = operators.pop()
        node_type = node.type_
        arity = operator_arity[node_type]
        if arity == -2:
            # Flatten left-associative trees.
            left = (len(operands) >= 2 and operands[-2])
            if left.type_ == node_type:
                right = operands.pop()
                left.append(right)
                return left
            arity = 2

        # Always use append to add operands to node, to update start and end.
        operand_list = operands[-arity:]
        del operands[-arity:]
        for operand in operand_list:
            node.append(operand)

        # Include closing bracket or postfix operator in [start,end).
        if node.end < tokenizer.token.end:
            node.end = tokenizer.token.end

        operands.append(node)
        return node

    class BreakOutOfLoops(Exception):
        pass

    try:
        while True:
            token_type = tokenizer.get()
            if token_type == END:
                break

            if (token_type == stop and context.bracket_level == bracket_level and context.curly_level == curly_level and
                    context.paren_level == paren_level and context.hook_level == hook_level):
                # Stop only if token_type matches the optional stop parameter, and that
                # token is not quoted by some kind of bracket.
                break
            if token_type == SEMICOLON:
                # NB: cannot be empty, statement handled that.
                raise BreakOutOfLoops

            elif token_type in (ASSIGN, HOOK, COLON):
                if tokenizer.scan_operand:
                    raise BreakOutOfLoops

                while (
                        (operators and operator_precedence.get(operators[-1].type_, -1) > operator_precedence.get(
                            token_type, -1)) or
                        (token_type == COLON and operators and operators[-1].type_ == ASSIGN)
                ):
                    reduce_()

                if token_type == COLON:
                    if operators:
                        node = operators[-1]
                    if not operators or node.type_ != HOOK:
                        raise tokenizer.new_syntax_error("Invalid label")
                    context.hook_level -= 1
                else:
                    operators.append(Node(tokenizer))
                    if token_type == ASSIGN:
                        operands[-1].assign_op = tokenizer.token.assign_op
                    else:
                        context.hook_level += 1

                tokenizer.scan_operand = True

            elif token_type in (
                    IN, COMMA, OR, AND, BITWISE_OR, BITWISE_XOR, BITWISE_AND, EQ, NE, STRICT_EQ, STRICT_NE, LT, LE, GE,
                    GT, INSTANCEOF, LSH, RSH, URSH, PLUS, MINUS, MUL, DIV, MOD, DOT
            ):
                # We're treating comma as left-associative so reduce can fold
                # left-heavy COMMA trees into a single array.
                if token_type == IN:
                    # An in operator should not be parsed if we're parsing the
                    # head of a for (...) loop, unless it is in the then part of
                    # a conditional expression, or parenthesized somehow.
                    if context.in_for_loop_init and not context.hook_level and not context.bracket_level and \
                            not context.curly_level and not context.paren_level:
                        raise BreakOutOfLoops

                if tokenizer.scan_operand:
                    raise BreakOutOfLoops
                while operators and operator_precedence.get(operators[-1].type_, -1) and (
                        operator_precedence.get(operators[-1].type_, -1) >= operator_precedence.get(token_type, -1)
                ):
                    reduce_()
                if token_type == DOT:
                    tokenizer.must_match(IDENTIFIER)
                    operands.append(Node(tokenizer, DOT, [operands.pop(), Node(tokenizer)]))
                else:
                    operators.append(Node(tokenizer))
                    tokenizer.scan_operand = True

            elif token_type in (
                    DELETE, VOID, TYPEOF, NOT, BITWISE_NOT, UNARY_PLUS, UNARY_MINUS, NEW
            ):
                if not tokenizer.scan_operand:
                    raise BreakOutOfLoops
                operators.append(Node(tokenizer))

            elif token_type in (INCREMENT, DECREMENT):
                if tokenizer.scan_operand:
                    operators.append(Node(tokenizer))  # prefix increment or decrement
                else:
                    # Don't cross a line boundary for postfix {in,de}crement.
                    if tokenizer.tokens.get(
                            (tokenizer.token_index + tokenizer.lookahead - 1) & 3).lineno != tokenizer.lineno:
                        raise BreakOutOfLoops

                    # Use >, not >=, so postfix has higher precedence than
                    # prefix.
                    while operators and operator_precedence.get(operators[-1].type_, -1) > operator_precedence.get(
                            token_type, -1):
                        reduce_()
                    node = Node(tokenizer, token_type, [operands.pop()])
                    node.postfix = True
                    operands.append(node)

            elif token_type == FUNCTION:
                if not tokenizer.scan_operand:
                    raise BreakOutOfLoops
                operands.append(function_definition(tokenizer, context, False, EXPRESSED_FORM))
                tokenizer.scan_operand = False

            elif token_type in (NULL, THIS, TRUE, FALSE, IDENTIFIER, NUMBER, STRING, REGEXP):
                if not tokenizer.scan_operand:
                    raise BreakOutOfLoops
                operands.append(Node(tokenizer))
                tokenizer.scan_operand = False

            elif token_type == LEFT_BRACKET:
                if tokenizer.scan_operand:
                    # Array initializer. Parse using recursive descent, as the
                    # sub-grammer here is not an operator grammar.
                    node = Node(tokenizer, ARRAY_INIT)
                    while True:
                        token_type = tokenizer.peek()
                        if token_type == RIGHT_BRACKET:
                            break
                        if token_type == COMMA:
                            tokenizer.get()
                            node.append(None)
                            continue
                        node.append(expression(tokenizer, context, COMMA))
                        if not tokenizer.match(COMMA):
                            break

                    tokenizer.must_match(RIGHT_BRACKET)
                    operands.append(node)
                    tokenizer.scan_operand = False
                else:
                    operators.append(Node(tokenizer, INDEX))
                    tokenizer.scan_operand = True
                    context.bracket_level += 1

            elif token_type == RIGHT_BRACKET:
                if tokenizer.scan_operand or context.bracket_level == bracket_level:
                    raise BreakOutOfLoops
                while reduce_().type_ != INDEX:
                    continue
                context.bracket_level -= 1

            elif token_type == LEFT_CURLY:
                if not tokenizer.scan_operand:
                    raise BreakOutOfLoops
                # Object initializer. As for array initializers (see above),
                # parse using recursive descent.
                context.curly_level += 1
                node = Node(tokenizer, OBJECT_INIT)

                class BreakOutOfObjectInit(Exception):
                    pass

                try:
                    if not tokenizer.match(RIGHT_CURLY):
                        while True:
                            token_type = tokenizer.get()
                            if (
                                    tokenizer.token.value == "get" or tokenizer.token.value == "set") and tokenizer.peek == IDENTIFIER:
                                if context.ecma_strict_mode:
                                    raise tokenizer.new_syntax_error("Illegal property accessor")
                                node.append(function_definition(tokenizer, context, True, EXPRESSED_FORM))
                            else:
                                if token_type in (IDENTIFIER, NUMBER, STRING):
                                    id_ = Node(tokenizer)
                                elif token_type == RIGHT_CURLY:
                                    if context.ecma_strict_mode:
                                        raise tokenizer.new_syntax_error("Illegal trailing ,")
                                    raise BreakOutOfObjectInit
                                else:
                                    raise tokenizer.new_syntax_error("Invalid property name")
                                tokenizer.must_match(COLON)
                                node.append(
                                    Node(tokenizer, PROPERTY_INIT, [id_, expression(tokenizer, context, COMMA)]))

                            if not tokenizer.match(COMMA):
                                break
                        tokenizer.must_match(RIGHT_CURLY)
                except BreakOutOfObjectInit:
                    pass
                operands.append(node)
                tokenizer.scan_operand = False
                context.curly_level -= 1

            elif token_type == RIGHT_CURLY:
                if not tokenizer.scan_operand and context.curly_level != curly_level:
                    raise ParseError("PANIC: right curly botch")
                raise BreakOutOfLoops

            elif token_type == LEFT_PAREN:
                if tokenizer.scan_operand:
                    operators.append(Node(tokenizer, GROUP))
                    context.paren_level += 1
                else:
                    while operators and operator_precedence.get(operators[-1].type, -1) > operator_precedence[NEW]:
                        reduce_()

                    # Handle () now, to regularize the n-ary case for n > 0.
                    # We must set scanOperand in case there are arguments and
                    # the first one is a regexp or unary+/-.
                    if operators:
                        node = operators[-1]
                    else:
                        node = Object()
                        node.type_ = None
                    tokenizer.scan_operand = True
                    if tokenizer.match(RIGHT_PAREN):
                        if node.type_ == NEW:
                            operators.pop()
                            node.append(operands.pop())
                        else:
                            node = Node(tokenizer, CALL, [operands.pop(), Node(tokenizer, LIST)])
                        operands.append(node)
                        tokenizer.scan_operand = False
                    else:
                        if node.type_ == NEW:
                            node.type_ = NEW_WITH_ARGS
                        else:
                            operators.append(Node(tokenizer, CALL))
                        context.paren_level += 1

            elif token_type == RIGHT_PAREN:
                if tokenizer.scan_operand or context.paren_level == paren_level:
                    raise BreakOutOfLoops
                while True:
                    token_type = reduce_().type_
                    if token_type in (GROUP, CALL, NEW_WITH_ARGS):
                        break
                if token_type != GROUP:
                    if operands:
                        node = operands[-1]
                        if node[1].type_ != COMMA:
                            node[1] = Node(tokenizer, LIST, [node[1]])
                        else:
                            node[1].type_ = LIST
                    else:
                        raise ParseError("Unexpected amount of operands")
                context.paren_level -= 1

            # Automatic semicolon insertion means we may scan across a newline
            # and into the beginning of another statement. If so, break out of
            # the while loop and let the t.scanOperand logic handle errors.
            else:
                raise BreakOutOfLoops
    except BreakOutOfLoops:
        pass

    if context.hook_level != hook_level:
        raise tokenizer.new_syntax_error("Missing : after ?")
    if context.paren_level != paren_level:
        raise tokenizer.new_syntax_error("Missing ) in parenthetical")
    if context.bracket_level != bracket_level:
        raise tokenizer.new_syntax_error("Missing ] in index expression")
    if tokenizer.scan_operand:
        raise tokenizer.new_syntax_error("Missing operand")

    tokenizer.scan_operand = True
    tokenizer.unget()
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
    tokenizer = Tokenizer(source, filename, starting_line_number)
    context = CompilerContext(False)
    node = new_script(tokenizer, context)
    if not tokenizer.done:
        raise tokenizer.new_syntax_error("Syntax error")
    return node


if __name__ == "__main__":
    print(str(parse(open(sys.argv[1]).read(), sys.argv[1])))
