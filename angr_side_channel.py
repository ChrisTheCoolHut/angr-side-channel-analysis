import angr
import angr.sim_options as so
import argparse
import string
import IPython
import operator
import os
from multiprocessing.pool import Pool
import multiprocessing
import logging
logging.getLogger('angr').disabled = True
logger = logging.getLogger()
logger.disabled = True


def trace_step(simgr):
    trace_str = ""
    for stash in simgr.stashes:
        if(len(simgr.stashes[stash]) > 0):
            trace_str += "{} : {}, ".format(stash, len(simgr.stashes[stash]))
    pc_list = []
    if len(simgr.active) > 0:
        for path in simgr.active:
            pc_list.append(hex(path.se.eval(path.regs.pc)))
    print(trace_str + str(pc_list) )
    #print(trace_str + str(pc_list) + "\r"),
    return simgr

def conc_trace(file_name, p, prog_input="", input_stdin=True):
    ret_dict = {}
    if input_stdin:
        my_stdin = angr.SimFile(name='my_stdin', content=prog_input, has_end=True)
        state = p.factory.entry_state(args=[file_name], mode='tracing', stdin=my_stdin)
    else:
        state = p.factory.full_init_state(args=[file_name, prog_input], mode='tracing')
    simgr = p.factory.simgr(state)
    simgr.run()
    ret_dict['count'] = 0
    if len(simgr.deadended) > 0:
        ret_dict['count'] = simgr.deadended[0].history.block_count
        ret_dict['stdout'] = simgr.deadended[0].state.posix.dumps(1)
    elif len(simgr.errored) > 0:
        ret_dict['count'] = simgr.errored[0].state.history.block_count
        ret_dict['stdout'] = simgr.errored[0].state.posix.dumps(1)
    return ret_dict
    
def conc_trace_wrap((file_name, p, prog_input, input_stdin, letter)):
    return (letter, conc_trace(file_name, p, prog_input=prog_input, input_stdin=input_stdin), prog_input)

def solve_ins_count_parallel(file_name, input_len, input_rev=False, input_stdin=True, processes=1):

    p = angr.Project(file_name, load_options={'auto_load_libs':True}, use_sim_procedures=False)

    trace_list = []
    input_in = "A"*input_len
    run_dict = {}
    my_r = range(input_len)
    if input_rev:
        my_r.reverse()

    for y in my_r:
        m_pool = Pool(processes)
        m_data = []
        for x in string.printable:
            input_test = list(input_in)
            input_test[y] = x
            input_test = ''.join(input_test)
            m_data.append((file_name, p, input_test, input_stdin, x))
        for i in m_pool.imap_unordered(conc_trace_wrap, m_data):
            run_dict[i[0]] = i[1]
#            run_dict[x] = conc_trace(file_name, p, prog_input=input_test, input_stdin=input_stdin)
            input_test = i[2]
            x = i[0]
            my_str = "{} {} {}\r".format(x, input_test, run_dict[x]['count'])
            trace_list.append(my_str)
            if len(trace_list) > 10:
                trace_list.reverse()
                trace_list.pop()
                trace_list.reverse()
            os.system("clear")
            print("Analyzing: {}".format(file_name))
            print("Strategy : {}".format("Basic Block Count"))
            print("Reverse : {}".format(input_rev))
            print("Length : {}".format(input_len))
            print("Current input: {}".format(input_in))
            print("Trace record:")
            for trace in trace_list:
                print trace
            if 'stdout' in run_dict[x].keys():
                print("stdout:")
                print(run_dict[x]['stdout'])
        m_pool.close()
        m_pool.join()
        input_in = list(input_in)
        input_in[y] = max(run_dict.iteritems(), key=operator.itemgetter(1))[0]
        input_in = ''.join(input_in)
        print("{} - {}".format(y, input_in))
        run_dict = {}
    print(input_in)
    print(conc_trace(file_name, p, prog_input=input_in, input_stdin=input_stdin)['stdout'])
    return input_in



def solve_ins_count(file_name, input_len, input_rev=False, input_stdin=True):

    p = angr.Project(file_name, load_options={'auto_load_libs':True}, use_sim_procedures=False)

    trace_list = []
    input_in = "A"*input_len
    run_dict = {}
    my_r = range(input_len)
    if input_rev:
        my_r.reverse()

    for y in my_r:
        for x in string.printable:
            input_test = list(input_in)
            input_test[y] = x
            input_test = ''.join(input_test)
            run_dict[x] = conc_trace(file_name, p, prog_input=input_test, input_stdin=input_stdin)
            my_str = "{} {} {}\r".format(x, input_test, run_dict[x]['count'])
            trace_list.append(my_str)
            if len(trace_list) > 10:
                trace_list.reverse()
                trace_list.pop()
                trace_list.reverse()
            os.system("clear")
            print("Analyzing: {}".format(file_name))
            print("Strategy : {}".format("Basic Block Count"))
            print("Reverse : {}".format(input_rev))
            print("Length : {}".format(input_len))
            print("Current input: {}".format(input_in))
            print("Trace record:")
            for trace in trace_list:
                print trace
            if 'stdout' in run_dict[x].keys():
                print("stdout:")
                print(run_dict[x]['stdout'])
        input_in = list(input_in)
        input_in[y] = max(run_dict.iteritems(), key=operator.itemgetter(1))[0]
        input_in = ''.join(input_in)
        print("{} - {}".format(y, input_in))
        run_dict = {}
    print(input_in)
    print(conc_trace(file_name, p, prog_input=input_in, input_stdin=input_stdin)['stdout'])
    return input_in

'''
Doesn't seem to work as well as PinCTF's input
length detection.
'''
def get_input_len(file_name, input_stdin=True):
    p = angr.Project(file_name, load_options={'auto_load_libs':True}, use_sim_procedures=False)
    len_dict = {}
    for x in range(1,40):
        print("{} - {}".format(x, "A"*x))
        len_dict[x] = conc_trace(file_name, p, prog_input="A"*x, input_stdin=input_stdin)
    return max(len_dict.iteritems(), key=operator.itemgetter(1))[0]


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument("File", help="File to analyze")

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--stdin", action="store_true", default=False, help="Send inputs through STDIN")
    group.add_argument("--arg", action="store_false", help="Send inputs through argv[2]")

    parser.add_argument("-i", "--inputLength", help="Length of input", type=int)
    parser.add_argument("-r", "--reverse", help="Reverse input checking", default=False, action='store_true')
    parser.add_argument("-c", "--procCount", help="Multiprocess count", default=1, type=int)

    args = parser.parse_args()

    if args.procCount == 1:
        solve_ins_count(args.File, args.inputLength, input_rev=args.reverse, input_stdin=args.stdin)
    else:
        solve_ins_count_parallel(args.File, args.inputLength, input_rev=args.reverse, input_stdin=args.stdin, processes=args.procCount)


if __name__ == '__main__':
    main()
