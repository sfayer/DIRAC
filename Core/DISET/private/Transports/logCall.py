import thread
DOLOG= True
def logCall(func):
  def innerFunc(*args, **kwargs):
    print "CHRISLOG %s -> %s(%s, %s)"%(thread.get_ident(), func.func_name, args[1:], kwargs)
    r = func(*args, **kwargs)
    print "CHRISLOG %s <- %s: %s"%(thread.get_ident(),func.func_name, r)
    return r
  if DOLOG:
    return innerFunc
  else:
    return func

def doLog(message):
  print "CHRISLOG %s MANUAL: %s"%(thread.get_ident(), message)
