import r2pipe
import argparse
import json
import pdb
import magic
import sys

noreturn_custom = ["sym.imp.__assert_fail", "sym.imp.abort", "sym.imp.pthread_exit", "sym.imp.exit", "sym.imp.std::__throw_bad_cast__",
        "sym.imp.std::__throw_logic_error_char_const_", "sym.imp.std::__throw_length_error_char_const_",
        "sym.imp.std::__throw_out_of_range_fmt_char_const__..._" , "sym.imp.__cxa_throw_bad_array_new_length"]

parser = argparse.ArgumentParser(description='Collect CFG information from file')
parser.add_argument('-f', '--infile', required=True)
parser.add_argument('-o', '--outfile', required=True)
args = parser.parse_args()

def cleanFuncName(name):
    if "dbg." in name:
        return name[4:]
    elif "sym.imp." in name:
        return name[8:]
    elif "sym." in name:
        return name[4:]
    else:
        return name

class CFGCtx:
    def __init__(self, pipe):
        self._handle = pipe
        self._output = {}

    def pipeExecute(self, cmd):
        return self._handle.cmd(cmd)

    def pipeExecuteJ(self, cmd):
        return self._handle.cmdj(cmd)

    def handleNonReturningFunctions(self):
        self.noreturn = []
        noreturn_out = self.pipeExecuteJ('aflj')
        for func in noreturn_out:
            if func["noreturn"] or func["name"] in noreturn_custom:
                self.noreturn += [func["offset"]]

    def parseNewFunction(self, func):
        self.func = func
        self.fn_addr = func['offset']

        self.bbs = self.pipeExecuteJ('afbj @ {}'.format(self.fn_addr))

        self._output[self.fn_addr]               = {}
        self._output[self.fn_addr]['bbs']        = []
        self._output[self.fn_addr]['name']       = cleanFuncName(func['name'])
        self._output[self.fn_addr]['ret_blocks'] = []

    def getOutput(self):
        return self._output

    def parseNewBB(self, bb):
        self.bb = bb
        self.bb_addr = bb['addr']
        self.ends_in_no_return = False

        self.insns = self.pipeExecuteJ('pdbj @ {}'.format(bb['addr']))
        self.prev_ins = None

    def createOutputBB(self, addr):
        bb = {}
        bb['start'] = addr
        bb['succs'] = []
        bb['call_succs'] = []
        bb['size'] = 0
        bb['end'] = 0
        bb['is_ret'] = 0
        bb['is_indirect'] = 0

        return bb

    def createSucc(self, addr, type_id=0):
        succ = {}
        succ['addr'] = addr
        succ['type'] = 0

        return succ

    def handleTerminatorIns(self, idx, bb_info):
        ins = self.insns[idx]
        rep_addr = ins['offset']

        bb_info['end'] = ins['offset']
        # Fallthrough sucessor
        if idx + 1 < len(self.insns):
            bb_info['succs'].append(self.createSucc(self.insns[idx+1]['offset']))
        # Add any explicit fail block (most likely same as fallthrough)
        if 'fail' in ins:
            bb_info['succs'].append(self.createSucc(ins['fail']))
        # Add instruction target if any to call_succ
        if 'jump' in ins:
            bb_info['call_succs'].append(self.createSucc(ins['jump']))

        bb_info['succs'] = list({x['addr']:x for x in bb_info['succs']}.values())
        self._output[self.fn_addr]['bbs'].append(bb_info)

    def handleRepIns(self, idx, bb_info):
        ins = self.insns[idx]
        rep_addr = ins['offset']

        # Previous BB ends here
        bb_info['end'] = self.prev_ins['offset']
        # Add ins as successor to previous
        bb_info['succs'].append(self.createSucc(rep_addr))

        self._output[self.fn_addr]['bbs'].append(bb_info)

        # New BB starts and ends here
        bb_info = self.createOutputBB(rep_addr)
        bb_info['end'] = rep_addr
        bb_info['size'] = ins['size']

        # Fallthrough sucessor
        if idx + 1 < len(self.insns):
            bb_info['succs'].append(self.createSucc(self.insns[idx+1]['offset']))
        # Add any explicit fail block (most likely same as fallthrough)
        if 'fail' in ins:
            bb_info['succs'].append(self.createSucc(ins['fail']))
        # Append self
        bb_info['succs'].append(self.createSucc(rep_addr))
        # No call target in rep instruction

        bb_info['succs'] = list({x['addr']:x for x in bb_info['succs']}.values())
        self._output[self.fn_addr]['bbs'].append(bb_info)

    def handleCallIns(self, idx, bb_info):
        ins = self.insns[idx]
        bb_info['end'] = ins['offset']

        if idx + 1 < len(self.insns):
            if 'jump' in ins and ins['jump'] in self.noreturn:
                self.ends_in_no_return = True
            else:
                bb_info['succs'].append(self.createSucc(self.insns[idx+1]['offset']))

            if 'jump' in ins:
                bb_info['call_succs'].append(self.createSucc(ins['jump']))
            if 'fail' in ins and ins['jump'] not in self.noreturn:
                bb_info['succs'].append(self.createSucc(ins['fail']))
        elif idx == len(self.insns) - 1:
            if 'jump' in ins:
                jmp_addr = ins['jump']
                target_fn = self.pipeExecuteJ('pij 1 @ {}'.format(jmp_addr))[0]['fcn_addr']
                if target_fn == self.fn_addr:
                    bb_info['succs'].append(self.createSucc(jmp_addr))
                else:
                    bb_info['call_succs'].append(self.createSucc(jmp_addr))
            if 'fail' in ins and ins['jump'] not in self.noreturn:
                fail_addr = ins['fail']
                target_fn = self.pipeExecuteJ('pij 1 @ {}'.format(fail_addr))[0]['fcn_addr']
                if target_fn == self.fn_addr:
                    bb_info['succs'].append(self.createSucc(fail_addr))
                else:
                    bb_info['call_succs'].append(self.createSucc(fail_addr))

            # Successor blocks to indirect calls
            if 'jump' in self.bb:
                if 'jump' in ins:
                    if ins['jump'] not in self.noreturn:
                        jmp_addr = self.bb['jump']
                        bb_info['succs'].append(self.createSucc(jmp_addr))
                else:
                    jmp_addr = self.bb['jump']
                    bb_info['succs'].append(self.createSucc(jmp_addr))

        # Mark indirect calls in JSON so that it becomes easier for incremental lifting
        if 'jump' not in ins and 'fail' not in ins:
            bb_info['is_indirect'] = 1

        bb_info['succs'] = list({x['addr']:x for x in bb_info['succs']}.values())
        self._output[self.fn_addr]['bbs'].append(bb_info)

    def handleOtherIns(self, idx, bb_info):
        if idx != len(self.insns) - 1:
            return
        
        ins = self.insns[idx]
        bb_info['end'] = ins['offset']
        if 'fail' in self.bb:
            bb_info['succs'].append(self.createSucc(self.bb['fail']))
        if 'jump' in self.bb:
            jmp_addr = self.bb['jump']
            disass_j = self.pipeExecuteJ('pij 1 @ {}'.format(jmp_addr))[0]
            if 'fcn_addr' not in disass_j:
                return
            target_fn = disass_j['fcn_addr']
            if target_fn == self.fn_addr:
                bb_info['succs'].append(self.createSucc(jmp_addr))
            else:
                if 'jmp' in ins['opcode'] or 'call' in ins['opcode']:
                    # Tail calls are _usually_ called only via jmp and call
                    bb_info['call_succs'].append(self.createSucc(jmp_addr))
                else:
                    # Code pattern seen in astar for 64 bit. jump to 'cold' fragment
                    # of function, the BB for which is not part of the function
                    bb_info['succs'].append(self.createSucc(jmp_addr))

        if 'jump' in ins:
            # Tail calls baby
            jmp_addr = ins['jump']
            target_fn = self.pipeExecuteJ('pij 1 @ {}'.format(jmp_addr))[0]['fcn_addr']
            if target_fn == self.fn_addr:
                bb_info['succs'].append(self.createSucc(jmp_addr))
            else:
                if 'jmp' in ins['opcode'] or 'call' in ins['opcode']:
                    # Tail calls are _usually_ called only via jmp and call
                    bb_info['call_succs'].append(self.createSucc(jmp_addr))
                else:
                    # Code pattern seen in astar for 64 bit. jump to 'cold' fragment
                    # of function, the BB for which is not part of the function
                    bb_info['succs'].append(self.createSucc(jmp_addr))

        bb_info['succs'] = list({x['addr']:x for x in bb_info['succs']}.values())
        bb_info['call_succs'] = list({x['addr']:x for x in bb_info['call_succs']}.values())
        if 'ret' in ins['opcode']:
            bb_info['is_ret'] = 1
        self._output[self.fn_addr]['bbs'].append(bb_info)

"""
HELPERS (S2E)
==============
0xF4, // HLT
0xFF, // CALL
0xE8, // CALL
0x9A, // CALL
0xCC, // INT
0xCD, // INT
0xCE, // INT
0xF2, // REPNE
0xF3  // REPE
"""

def isTerminatorIns(ins):
    terminator_opcodes = ['hlt', 'int']
    for opcode in terminator_opcodes:
        if opcode in ins:
            return True
    return False

def isCallIns(ins):
    if 'call' in ins:
        return True
    return False

def isRepIns(ins):
    rep_opcodes = ['repne', 'repe', 'rep']
    for opcode in rep_opcodes:
        if opcode in ins:
            return True
    return False

# def isFuncExit(ins):
#     # Also, should include calls to non-returning functions (but can r2 find that?)
#     exit_opcodes = ['jmp', 'call', 'ret']
#     for opcode in exit_opcodes:
#         if opcode in ins:
#             return True

if __name__ == "__main__":
    ftype = magic.from_file(args.infile)
    # Kernel modules are relocatable 
    if "relocatable" in ftype:
        rz = r2pipe.open(args.infile, flags=["-e", "bin.cache=true"])
    else:
        rz = r2pipe.open(args.infile)

    if rz is None:
        print("Could not open r2pipe. Abort!")
        exit()

    ctx = CFGCtx(rz)

    # Increase analysis depth to discover more BBs
    ctx.pipeExecute('e anal.depth=256')
    # Disable noreturn analysis propagation
    ctx.pipeExecute('e anal.noret=false')

    # Analyze all
    ctx.pipeExecute('aaa')

    # Handle non-returning functions. Ensure that the followthrough is not added!
    ctx.handleNonReturningFunctions()

    for func in ctx.pipeExecuteJ('aflj'):
        ctx.parseNewFunction(func)
        for bb in ctx.bbs:
            ctx.parseNewBB(bb)

            is_new_bb = True
            idx = 0

            while idx < len(ctx.insns):
                ins = ctx.insns[idx]
                if 'type' in ins and ins['type'] == 'invalid':
                    continue

                if ctx.ends_in_no_return:
                    ctx.ends_in_no_return = False
                    break

                if is_new_bb:
                    bb_info = ctx.createOutputBB(int(ins['offset']))
                    is_new_bb = False

                if isTerminatorIns(ins['opcode']):
                    is_new_bb = True
                    ctx.handleTerminatorIns(idx, bb_info)

                elif isRepIns(ins['opcode']):
                    is_new_bb = True
                    ctx.handleRepIns(idx, bb_info)

                elif isCallIns(ins['opcode']):
                    is_new_bb = True
                    ctx.handleCallIns(idx, bb_info)

                else:
                    ctx.handleOtherIns(idx, bb_info)

                idx += 1

                # Bookkeeping for REP
                if idx < len(ctx.insns):
                    new_ins = ctx.insns[idx]
                    if 'type' in new_ins and new_ins['type'] == 'invalid':
                        continue
                    if isRepIns(new_ins['opcode']):
                        ctx.prev_ins = ins

                bb_info['size'] += ins['size']

    with open(args.outfile, 'w') as f:
        json.dump(ctx.getOutput(), f)
