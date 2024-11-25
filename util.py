import re
def fix_bad_datavars(bv):
    for datavar_key in bv.data_vars.keys():
        datavar = bv.data_vars[datavar_key]
        if datavar.name != None:
            badname = re.match(r'@([1-9]+)', datavar.name)
            if badname != None:
                datavar.name = 'global_{}'.format(badname.group(1))