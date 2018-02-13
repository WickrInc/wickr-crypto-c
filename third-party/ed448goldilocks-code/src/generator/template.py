from textwrap import dedent
from curve_data import field_data,curve_data,ser,msqrt,ceil_log2

import os
import argparse
import re

parser = argparse.ArgumentParser(description='Generate Decaf headers and other such files.')
parser.add_argument('-o', required = True, help = "Output")
parser.add_argument('--per', required = True, help = "Files to be generated are global or per field/curve", choices=["global","field","curve"])
parser.add_argument('--item', required = False, default = "global", help = "Which curve/field to choose")
parser.add_argument('--guard', required = False, default = None, help = "header guard")
parser.add_argument('files', metavar='file', type=str, nargs='+', help='a list of files to fill')
args = parser.parse_args()

per_map = {"field":field_data, "curve":curve_data, "global":{"global":{"field":field_data,"curve":curve_data} }}

def redoc(filename,doc,author):
    doc = doc.replace("\n","\n * ")
    doc = dedent("""
        /**
         * @file %(filename)s
         * @author %(author)s
         *
         * @copyright
         *   Copyright (c) 2015-2016 Cryptography Research, Inc.  \\n
         *   Released under the MIT License.  See LICENSE.txt for license information.
         *
         * %(doc)s
         *
         * @warning This file was automatically generated in Python.
         * Please do not edit it.
         */""") % { "filename": filename, "doc": doc, "author" : author }
    doc = doc.replace(" * \n", " *\n")
    return doc[1:]

def gen_file(public,name,doc,code,per="global",author="Mike Hamburg"):
    is_header = name.endswith(".h") or name.endswith(".hxx") or name.endswith(".h++")

def fillin(template,data):
    position = 0
    ret = ""
    while True:
        dollars = template.find("$(",position)
        if dollars is -1: return ret + template[position:]
        ret += template[position:dollars]
        position = dollars + 2
        parens = 1
        while parens > 0:
            if template[position] == '(': parens += 1
            elif template[position] == ')': parens -= 1
            position += 1
        ret += str(eval(template[dollars+2:position-1],{'re':re,'ser':ser,'msqrt':msqrt,'ceil_log2':ceil_log2},data))

author = "Mike Hamburg" # FUTURE
for name in args.files:
    _,_,name_suffix = name.rpartition(".")
    template0 = open(name,"r").read()
    
    data = per_map[args.per][args.item]

    template = template0
    
    outname = args.o
    guard = args.guard
    if guard is None: guard = outname
    header_guard = "__" + guard.replace(".","_").replace("/","_").upper() + "__"
    
    # Extract doxygenation
    m = re.match(r"^\s*/\*\*([^*]|\*[^/])+\*/[ \t]*\n",template)
    if m:
        doc = re.sub("^\s*/?\*+/?[ \t]*","",m.group(),flags=re.MULTILINE)
        doc = re.sub("\\s*\*/","",doc)
        template = template[m.end():]
    else: doc = ""
    
    ns_doc = dedent(doc).strip().rstrip()
    ns_doc = redoc(guard, fillin(ns_doc,data), author)
    ns_code = fillin(template,data)
    ret = ns_doc + "\n"
    
    if outname.endswith(".h") or outname.endswith(".hxx"):
        ns_code = dedent("""\n
            #ifndef %(header_guard)s
            #define %(header_guard)s 1
            %(code)s
            #endif /* %(header_guard)s */
            """) % { "header_guard" : header_guard, "code": ns_code }
    ret += ns_code[1:-1]
    
    if not os.path.exists(os.path.dirname(outname)):
        os.makedirs(os.path.dirname(outname))
    with open(outname,"w") as f:
        f.write(ret + "\n")


    