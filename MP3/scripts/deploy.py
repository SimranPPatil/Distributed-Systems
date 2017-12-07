# pip install --user fabric
# fab -f scripts/deploy.py deploy

from fabric.api import env,run,put,cd

env.hosts = [
    'nalland2@fa17-cs425-g13-01.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-02.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-03.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-04.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-05.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-06.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-07.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-08.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-09.cs.illinois.edu',
    'nalland2@fa17-cs425-g13-10.cs.illinois.edu'
]

def vm_str_num(host):
    if host[15] == '1':
        return str(10)
    else:
        return str(int(host[16]))

def deploy():
    run('rm -r ~/mp2/*')
    run('mkdir -p ~/mp2')
    put(local_path='include', remote_path='~/mp2')
    put(local_path='src', remote_path='~/mp2')
    put(local_path='modules', remote_path='~/mp2')
    put(local_path='Makefile', remote_path='~/mp2')
    put(local_path='main.cpp', remote_path='~/mp2')

#    if(vm_str_num(env.host) == "1"):
#        put(local_path='tests', remote_path='~/mp2')

    with cd('~/mp2'):
        run('make workspace')
        run('make -j')
        run('find ! -name \".\" -name \".*\" -exec rm {} \;')
