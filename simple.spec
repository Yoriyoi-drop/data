
a = Analysis(['run_simple.py'], datas=[('templates', 'templates')])
exe = EXE(a.pure, a.scripts, a.binaries, a.datas, name='InfiniteAISecurity', console=True)
