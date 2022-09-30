import r2pipe
import argparse
import json
import pdb

parser = argparse.ArgumentParser(description='Collect CFG information from file')
parser.add_argument('-f', '--infile', required=True)
parser.add_argument('-o', '--outfile', required=True)
args = parser.parse_args()

if __name__ == "__main__":
    rz = r2pipe.open(args.infile)
    if rz is None:
        print("Could not open r2pipe. Abort!")
        exit()

    cfg = json.load(open(args.outfile))
    for func in cfg:
        bbs = cfg[func]["bbs"]

        all_bbs = {}
        for bb_map in bbs:
            all_bbs[bb_map["start"]] = 1

        for bb_map in bbs:
            for succ in bb_map["succs"]:
                if succ not in all_bbs:
                    phy = rz.cmd("?p {}".format(succ)).strip()
