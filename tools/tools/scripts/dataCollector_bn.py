import argparse
import json
import pdb

import binaryninja as binja

parser = argparse.ArgumentParser(description='Collect CFG information from file')
parser.add_argument('-f', '--infile', required=True)
parser.add_argument('-o', '--outfile', required=True)
args = parser.parse_args()

class CFGCtx:
    def __init__(self, handle):
        self._handle = handle
        self._output = {}

    # def pipeExecute(self, cmd):
    #     return self._handle.cmdj(cmd)

    def parseNewFunction(self, func):
        self.func = func
        self.fn_addr = func.start

        self.bbs = list(func) 

        self._output[self.fn_addr]               = {}
        self._output[self.fn_addr]['bbs']        = []
        self._output[self.fn_addr]['name']       = func.name
        self._output[self.fn_addr]['ret_blocks'] = []

    def getOutput(self):
        return self._output

    def parseNewBB(self, bb):
        self.bb = bb
        self.bb_addr = bb.start

        self.insns = list(bb) 
        self.prev_ins = None

    def createOutputBB(self, addr):
        bb = {}
        bb['start'] = addr
        bb['succs'] = []
        bb['call_succs'] = []
        bb['size'] = 0
        bb['end'] = 0

        return bb

    def handleTerminatorIns(self, idx, bb_info):
        ins = self.insns[idx]
        rep_addr = ins['offset']

        bb_info['end'] = ins['offset']
        # Fallthrough sucessor
        if idx + 1 < len(self.insns):
            bb_info['succs'].append(self.insns[idx+1]['offset'])
        # Add any explicit fail block (most likely same as fallthrough)
        if 'fail' in ins:
            bb_info['succs'].append(ins['fail'])
        # Add instruction target if any to call_succ
        if 'jump' in ins:
            bb_info['call_succs'].append(ins['jump'])

        bb_info['succs'] = list(set(bb_info['succs']))
        self._output[self.fn_addr]['bbs'].append(bb_info)

    def handleRepIns(self, idx, bb_info):
        ins = self.insns[idx]
        rep_addr = ins['offset']

        # Previous BB ends here
        bb_info['end'] = self.prev_ins['offset']
        # Add ins as successor to previous
        bb_info['succs'].append(rep_addr)

        self._output[self.fn_addr]['bbs'].append(bb_info)

        # New BB starts and ends here
        bb_info = self.createOutputBB(rep_addr)
        bb_info['end'] = rep_addr
        bb_info['size'] = ins['size']

        # Fallthrough sucessor
        if idx + 1 < len(self.insns):
            bb_info['succs'].append(self.insns[idx+1]['offset'])
        # Add any explicit fail block (most likely same as fallthrough)
        if 'fail' in ins:
            bb_info['succs'].append(ins['fail'])
        # Append self
        bb_info['succs'].append(rep_addr)
        # No call target in rep instruction

        bb_info['succs'] = list(set(bb_info['succs']))
        self._output[self.fn_addr]['bbs'].append(bb_info)

    def handleCallIns(self, idx, bb_info):
        ins = self.insns[idx]
        bb_info['end'] = ins['offset']

        if idx + 1 < len(self.insns):
            bb_info['succs'].append(self.insns[idx+1]['offset'])
            if 'jump' in ins:
                bb_info['call_succs'].append(ins['jump'])
            if 'fail' in ins:
                bb_info['succs'].append(ins['fail'])
        elif idx == len(self.insns) - 1:
            if 'jump' in ins:
                jmp_addr = ins['jump']
                target_fn = self.pipeExecute('pij 1 @ {}'.format(jmp_addr))[0]['fcn_addr']
                if target_fn == self.fn_addr:
                    bb_info['succs'].append(jmp_addr)
                else:
                    bb_info['call_succs'].append(jmp_addr)

        bb_info['succs'] = list(set(bb_info['succs']))
        self._output[self.fn_addr]['bbs'].append(bb_info)

    def handleOtherIns(self, idx, bb_info):
        if idx != len(self.insns) - 1:
            return

        ins = self.insns[idx]
        bb_info['end'] = ins['offset']
        if 'fail' in self.bb:
            bb_info['succs'].append(self.bb['fail'])
        if 'jump' in self.bb:
            jmp_addr = self.bb['jump']
            target_fn = self.pipeExecute('pij 1 @ {}'.format(jmp_addr))[0]['fcn_addr']
            if target_fn == self.fn_addr:
                bb_info['succs'].append(jmp_addr)
            else:
                bb_info['call_succs'].append(jmp_addr)

        bb_info['succs'] = list(set(bb_info['succs']))
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
    bv = binja.BinaryViewType.get_view_of_file(args.infile)
    if bv is None:
        print("Could not open bn. Abort!")
        exit()

    ctx = CFGCtx(bv)

    for func in bv.functions:
        ctx.parseNewFunction(func)
        for bb in ctx.bbs:
            ctx.parseNewBB(bb)

            is_new_bb = True
            idx = 0

            while idx < len(ctx.insns):
                ins = ctx.insns[idx]
                if is_new_bb:
                    bb_info = ctx.createOutputBB(ins.address))
                    is_new_bb = False

                if isTerminatorIns(str(ins)):
                    is_new_bb = True
                    ctx.handleTerminatorIns(idx, bb_info)

                elif isRepIns(str(ins)):
                    is_new_bb = True
                    ctx.handleRepIns(idx, bb_info)

                elif isCallIns(str(ins)):
                    is_new_bb = True
                    ctx.handleCallIns(idx, bb_info)

                else:
                    ctx.handleOtherIns(idx, bb_info)

                idx += 1

                # Bookkeeping for REP
                if idx < len(ctx.insns):
                    new_ins = ctx.insns[idx]
                    if isRepIns(str(new_ins)):
                        ctx.prev_ins = ins

                bb_info['size'] += ins.size

    with open(args.outfile, 'w') as f:
        json.dump(ctx.getOutput(), f)
