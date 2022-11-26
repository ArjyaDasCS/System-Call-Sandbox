# import libraries
import angr
from angr.knowledge_plugins.functions.function_manager import Function as angr_Function
import networkx as nx
import graphviz
import copy

# Node structure
class CallGraphNode():

  def __init__(self, address, functionName, predecessors = None):
     self.predecessors = set()
     self.successors = dict()
     self.address = address
     self.functionName = functionName

  def addPredecessors(self, callgraphNode):
    self.predecessors.add(callgraphNode)
  
  def addSuccessors(self, callgraphNode, edgeData):
    self.successors[callgraphNode] = edgeData

# Graph Structure
class CallGraph():

  def __init__(self, name):
    self.name = name
    self.nodes = set()

  def addNode(self, callgraphNode):
    if callgraphNode is not None:
      currentlyAvailableNodesInGraph = set()
      for aNode in self.nodes:
        currentlyAvailableNodesInGraph.add(str(aNode.address))
      if callgraphNode.address not in currentlyAvailableNodesInGraph:
        self.nodes.add(callgraphNode)
  
  def getSpecifiedNode(self, address):
    desired = None
    for node in self.nodes:
      if node.address == address:
        desired = node
    return desired

  def addAllNodes(self, anotherGraph):
    for node in anotherGraph.nodes:
      nodeAddress = node.address
      nodeFunName = node.functionName
      newNode = CallGraphNode(nodeAddress, nodeFunName)
      self.addNode(newNode)

  def addAllEdges(self, anotherGraph):
    for node in anotherGraph.nodes:
      nodeAddress = node.address
      nodePred = (node.predecessors)
      nodeSuc = (node.successors)
      nodeFromMerged = self.getSpecifiedNode(node.address)
      for pred in nodePred:
        predInstance = self.getSpecifiedNode(pred.address)
        nodeFromMerged.addPredecessors(pred)
      for suc in nodeSuc:  
        nodeFromMerged.addSuccessors(self.getSpecifiedNode(suc.address), copy.deepcopy(nodeSuc[suc]))

# function to display graph
def display(my_Graph):
  g = graphviz.Digraph(my_Graph.name)
  for n in my_Graph.nodes:
    g.node(n.address)
  for node in my_Graph.nodes:
    successors = node.successors
    for successor in successors:
      currentEdge = successors[successor]
      isFunctionCallInfo = currentEdge['isFunctionCall']
      isSystemCallInfo = currentEdge['isSystemCall']
      if isFunctionCallInfo == False:
        g.edge(node.address, successor.address)
      elif isFunctionCallInfo == True and isSystemCallInfo == False:
        label=currentEdge['FunctionCallName']
        g.edge(node.address, successor.address, label=currentEdge['FunctionCallName'])
      elif isFunctionCallInfo == True and isSystemCallInfo == True:
        g.edge(node.address, successor.address, label=currentEdge['SystemCallName'])
  
  g.render(my_Graph.name, directory="optimized functions", format="png")

# function that creats all reachable graphs (from entry point) per function
def createPrimaryFunctionGraphs(globalEntryNodeAddress, allFunctions):
  functionName = cfg.get_any_node(globalEntryNodeAddress).name
  globalEntryNode = CallGraphNode(hex(globalEntryNodeAddress),functionName)
  globalEntryFunction = allFunctions[globalEntryNodeAddress]
  functionList = list()
  functionProcessed = set()
  functionList.append(globalEntryFunction)
  functionProcessed.add(globalEntryFunction)
  globalSysCallSet = set()
  allReachableFunctionGraphs = {}

  while(len(functionList) > 0):
    currentFunctionInstance = functionList.pop(0)
    originalGraph = currentFunctionInstance.transition_graph
    originalGraphEntryNode = None
    functionEntryPoint = currentFunctionInstance.startpoint
    calledFunctions = set()
    for node in originalGraph.nodes():
      if node == functionEntryPoint:
        originalGraphEntryNode = node
    edgeSetBFS = nx.edge_bfs(originalGraph, originalGraphEntryNode)
    myFunctionGraph = CallGraph(str(currentFunctionInstance.name))
    for currentBlock, successor in edgeSetBFS:
      isFunctionCall = isinstance(successor, angr_Function)
      isSystemCall = (isFunctionCall == True) and (successor.is_syscall == True)
      sourceNode = CallGraphNode(str(hex(currentBlock.addr)), str(currentFunctionInstance.name))
      myFunctionGraph.addNode(sourceNode)

      n = None
      # if successor is a function call (not system call)
      if isFunctionCall==True and isSystemCall==False:
        n = CallGraphNode(str(hex(successor.startpoint.addr)), str(successor.name))
        # process the next function only if it has not been processed yet
        nextCalledFuncion = allFunctions[successor.startpoint.addr]
        if nextCalledFuncion not in functionProcessed:
          functionList.append(nextCalledFuncion)
          functionProcessed.add(nextCalledFuncion)
          calledFunctions.add(nextCalledFuncion)

      # if successor is neither function call nor system call (i.e. successor is in same function)
      if isFunctionCall==False and isSystemCall==False:
        n = CallGraphNode(str(hex(successor.addr)), str(currentFunctionInstance.name))

      myFunctionGraph.addNode(n)

    edgeSetBFS = nx.edge_bfs(originalGraph, originalGraphEntryNode)
    for currentBlock, successor in edgeSetBFS:
      isFunctionCall = isinstance(successor, angr_Function)
      isSystemCall = (isFunctionCall == True) and (successor.is_syscall == True)
      source = myFunctionGraph.getSpecifiedNode(hex(currentBlock.addr))

      destination = None
      # if successor is a function call (not system call)
      if isFunctionCall==True and isSystemCall==False:
        destination = myFunctionGraph.getSpecifiedNode(str(hex(successor.startpoint.addr)))

      # if successor is a system call
      if isFunctionCall==True and isSystemCall==True:
        continue

      # if successor is neither function call nor system call (i.e. successor is in same function)
      if isFunctionCall==False and isSystemCall==False:
        destination = myFunctionGraph.getSpecifiedNode(str(hex(successor.addr)))

      edgeData = {'isFunctionCall':isFunctionCall, 'isSystemCall':isSystemCall}
      source.addSuccessors(destination, edgeData)
      destination.addPredecessors(source)

    edgeSetBFS = nx.edge_bfs(originalGraph, originalGraphEntryNode)
    for currentBlock, successor in edgeSetBFS:
      isFunctionCall = isinstance(successor, angr_Function)
      isSystemCall = (isFunctionCall == True) and (successor.is_syscall == True)
      source = myFunctionGraph.getSpecifiedNode(hex(currentBlock.addr))

      # if successor is a system call
      if isFunctionCall==True and isSystemCall==True:
        data = source.successors.keys()
        for destinationNode in data:
          destination = myFunctionGraph.getSpecifiedNode(destinationNode.address)
          edgeInformation = source.successors[destination]
          edgeInformation['isFunctionCall'] = True
          edgeInformation['isSystemCall'] = True
          edgeInformation['SystemCallName'] = str(successor.name)
          globalSysCallSet.add(str(successor.name))
    myGraphEntryPoint = myFunctionGraph.getSpecifiedNode(str(hex(functionEntryPoint.addr)))
    if myGraphEntryPoint is None:
      continue
    allReachableFunctionGraphs[str(myGraphEntryPoint.address)] = {'graph': myFunctionGraph, 'entry':myGraphEntryPoint, 'calledFunctions':calledFunctions}
  
  return allReachableFunctionGraphs

# function to get function call or system call data from successors
def getTransitiveSuccessorsData(currentNode, currentNodeSuccessors):
  calledFunction = None
  hasSystemCall = False
  sysCall = None
  NonCallSuccessors = []
  for currentSuccessor in currentNodeSuccessors:
    if currentSuccessor.address == currentNode.address:
      continue
    currentEdge = currentNodeSuccessors[currentSuccessor]
    isFunctionCallInfo = currentEdge['isFunctionCall']
    isSystemCallInfo = currentEdge['isSystemCall']

    # Either function call or system call
    if isFunctionCallInfo == True and isSystemCallInfo==False:
      calledFunction = currentSuccessor.functionName
    elif isFunctionCallInfo == True and isSystemCallInfo==True:
      hasSystemCall |= isSystemCallInfo
      sysCall = currentEdge['SystemCallName']
    else:
      NonCallSuccessors.append(currentSuccessor)
  return NonCallSuccessors, calledFunction, hasSystemCall, sysCall

# function to create optimized function graphs (per function)
def createOptimizedFunctionGraphs(allReachableFunctionGraphs):
  allOptimizedFunctionGraphs = {}
  for g in allReachableFunctionGraphs:
    graphDetails = allReachableFunctionGraphs[g]
    graph = graphDetails['graph']
    entryNode = graphDetails['entry']
    calledFunctions = graphDetails['calledFunctions']
    funName = entryNode.functionName
    myOptimizedFunctionGraph = CallGraph(funName)
    processingList = [(entryNode, entryNode)]
    visitStatus = set(processingList)
    exitNodeName = "EXIT" + str(entryNode.functionName)
    exitNode = CallGraphNode(exitNodeName, str(entryNode.functionName))
    myOptimizedFunctionGraph.addNode(exitNode)
    
    while(len(processingList) > 0):
      value = (processingList.pop(0))
      currentNode = value[0]
      generator = value[1]
     
      if len(currentNode.successors) == 0:
        exitNodeInstance = myOptimizedFunctionGraph.getSpecifiedNode(exitNodeName)
        source = CallGraphNode(generator.address, str(entryNode.functionName))
        myOptimizedFunctionGraph.addNode(source)
        sourceInstance = myOptimizedFunctionGraph.getSpecifiedNode(generator.address)
        edgeData = {'isFunctionCall':False, 'isSystemCall':False}
        sourceInstance.addSuccessors(exitNodeInstance,edgeData)
        exitNodeInstance.addPredecessors(sourceInstance)
      
      NonCallSuccessors, calledFunction, hasSystemCall, sysCall = getTransitiveSuccessorsData(currentNode, currentNode.successors)

      # Successors are in the same function (neither function call nor system call)
      if calledFunction is None and hasSystemCall==False:
        for s in  NonCallSuccessors:
          processingListEntry = (s, generator)
          if processingListEntry not in visitStatus:
            processingList.append(processingListEntry)
            visitStatus.add(processingListEntry)
      
      # for function calls and system calls
      else:
        # for system call
        edgeData1 = {}
        if hasSystemCall == True:
          edgeData1 = {'isFunctionCall':True, 'isSystemCall':True, 'SystemCallName':sysCall}
        # for function call
        else:
          edgeData1 = {'isFunctionCall':True, 'isSystemCall':False, 'FunctionCallName':calledFunction}
      
        # if there is no successor after call then attach the generator with exit
        if len(NonCallSuccessors) == 0:
          exitNodeInstance = myOptimizedFunctionGraph.getSpecifiedNode(exitNodeName)
          source = CallGraphNode(generator.address, str(entryNode.functionName))
          myOptimizedFunctionGraph.addNode(source)
          sourceInstance = myOptimizedFunctionGraph.getSpecifiedNode(generator.address)
          sourceInstance.addSuccessors(exitNodeInstance,edgeData1)
          exitNodeInstance.addPredecessors(sourceInstance)
      
        for s in  NonCallSuccessors:
          suc = CallGraphNode(s.address, str(entryNode.functionName))
          myOptimizedFunctionGraph.addNode(suc)
          SuccessorInstance = myOptimizedFunctionGraph.getSpecifiedNode(s.address)
          source = CallGraphNode(generator.address, str(entryNode.functionName))
          myOptimizedFunctionGraph.addNode(source)
          sourceInstance = myOptimizedFunctionGraph.getSpecifiedNode(generator.address)
          sourceInstance.addSuccessors(SuccessorInstance,edgeData1)
          SuccessorInstance.addPredecessors(sourceInstance)

          processingListEntry = (s, s)
          if processingListEntry not in visitStatus:
            processingList.append(processingListEntry)
            visitStatus.add(processingListEntry)

    optimizedStartNode = myOptimizedFunctionGraph.getSpecifiedNode(entryNode.address)
    optimizedExitNode = myOptimizedFunctionGraph.getSpecifiedNode(exitNodeName)
    if optimizedStartNode is None:
      continue
    allOptimizedFunctionGraphs[optimizedStartNode.address] = {'graph':myOptimizedFunctionGraph, 'entry':optimizedStartNode, 'exit':optimizedExitNode, 'calledFunctions':calledFunctions}    
  return allOptimizedFunctionGraphs

# function that return callsite and return site from caller graph
def getCallAndReturnSites(CallerGraph, CalleeName):
  callAndReturnSites = {}
  for node in CallerGraph.nodes:
    for suc in node.successors.keys():
      if (node.successors)[suc]['isFunctionCall']==True and (node.successors)[suc]['isSystemCall']==False and (node.successors)[suc]['FunctionCallName']==CalleeName.name:
        callAndReturnSites[node] = suc
  return callAndReturnSites

# function to create single merged graph (single)
def createMergedGraph(functionCallGraphs):
  mergedGraph = CallGraph('Merged Graph')
  funL = set()
  
  for currentFunctionGraph in functionCallGraphs:
    currentGraphInstance = functionCallGraphs[currentFunctionGraph]['graph']
    mergedGraph.addAllNodes(currentGraphInstance)
    #mergedGraph.nodes = currentGraphInstance.nodes.copy()
  
  for currentFunctionGraph in functionCallGraphs:
    currentGraphInstance = functionCallGraphs[currentFunctionGraph]['graph']
    mergedGraph.addAllEdges(currentGraphInstance)

  
  for currentFunctionGraph in functionCallGraphs:
    funL.add(functionCallGraphs[currentFunctionGraph]['entry'].functionName)
    details = functionCallGraphs[currentFunctionGraph]
    calledFunctions = details['calledFunctions']
    for calledFunction in calledFunctions:
      callAndReturnSites = getCallAndReturnSites(details['graph'], calledFunction)
      calledFunctionAddr = str(hex(calledFunction.startpoint.addr))

      if calledFunctionAddr in functionCallGraphs.keys():
        #Reachable function
        calledFunctionEntry = functionCallGraphs[calledFunctionAddr]['entry']
        calledFunctionExit = functionCallGraphs[calledFunctionAddr]['exit']

        calledFunctionEntry = mergedGraph.getSpecifiedNode(calledFunctionEntry.address)
        calledFunctionExit = mergedGraph.getSpecifiedNode(calledFunctionExit.address)

        for x in callAndReturnSites:
          callsite = x
          returnSite = callAndReturnSites[x]

          callSiteFromFunctionGraph = (details['graph']).getSpecifiedNode(callsite.address)
          returnSiteFromFunctionGraph = (details['graph']).getSpecifiedNode(returnSite.address)
          callSiteInstance = mergedGraph.getSpecifiedNode(callsite.address)
          returnSiteInstance = mergedGraph.getSpecifiedNode(returnSite.address)

          callSiteInstance.addSuccessors(calledFunctionEntry, {'isSystemCall':False,'isFunctionCall':False})
          calledFunctionEntry.addPredecessors(callSiteInstance)
          calledFunctionExit.addSuccessors(returnSiteInstance, {'isSystemCall':False,'isFunctionCall':False})
          returnSiteInstance.addPredecessors(calledFunctionExit)

          if returnSiteInstance.address in callSiteInstance.successors:
            del callSiteInstance.successors[returnSiteInstance]
          #returnSiteInstance.predecessors.remove(callSiteInstance)
      
      else:
        # unreachable functions
        for x in callAndReturnSites:
          callsite = x
          returnSite = callAndReturnSites[x]
          callSiteInstance = mergedGraph.getSpecifiedNode(callsite.address)
          returnSiteInstance = mergedGraph.getSpecifiedNode(returnSite.address)
          callSiteInstance.addSuccessors(returnSiteInstance,{'isFunctionCall':False, 'isSystemCall':False, 'FunctionCallName':None})
          returnSiteInstance.addPredecessors(callSiteInstance)
  return mergedGraph

# function to optimize final graph
def optimizeFinalGraph(mergedGraph, entryNode):
  finalGraph = CallGraph('finalGraph')
  processingList = [(entryNode, entryNode)]
  visitStatus = set(processingList)
  j = 0
  while(len(processingList) > 0):
    value = (processingList.pop(0))
    currentNode = value[0]
    generator = value[1]
    currentNode = mergedGraph.getSpecifiedNode(currentNode.address)
    generatorInstance = mergedGraph.getSpecifiedNode(generator.address)
    for s in currentNode.successors:
      edgeInformation = currentNode.successors[s]
      isFunctionCall = edgeInformation['isFunctionCall']
      isSystemCall = edgeInformation['isSystemCall']
      sInstance = mergedGraph.getSpecifiedNode(s.address)
      exist = False
      if isFunctionCall == False:
        exist = None

      if exist is None:
        processingListEntry = (s, generator)
      else:
        sCreate = CallGraphNode(s.address, str(s.functionName))
        generatorCreate = CallGraphNode(generator.address, str(generator.functionName))
        if isSystemCall == True:
          syscallName = 'SYS_'+edgeInformation['SystemCallName']
          generatorCreate.addSuccessors(sCreate, {'isFunctionCall':isFunctionCall,'isSystemCall':isSystemCall,'SystemCallName':syscallName})
          sCreate.addPredecessors(generatorCreate)
          finalGraph.addNode(generatorCreate)
          finalGraph.addNode(sCreate)
          processingListEntry = (s, s)
        else:
          processingListEntry = (s, s)
      
      if processingListEntry not in visitStatus:
        processingList.append(processingListEntry)
        visitStatus.add(processingListEntry)  
  return finalGraph 

# function to enforce sanity checks (for pendent vertcies)
def enforceSanity(finalGraph, entry):
  finalGraphCopy = copy.deepcopy(finalGraph)
  for node in finalGraph.nodes:
    p_exist = False
    for p in node.predecessors:
      if (finalGraph.getSpecifiedNode(p.address)) is None:
       p_exist |= False
      else:
        p_exist |= True
    if node.address != hex(entry):
      n = finalGraphCopy.getSpecifiedNode(node.address)
      finalGraphCopy.nodes.remove(n)
  return finalGraphCopy

# function to generate output files (text)
def writeInfo(finalGraph, entry):
  nodeInfo = [hex(entry)]
  successors1 = []
  nodeInfo.append(str(len(finalGraph.nodes)))
  successors1.append(str(len(finalGraph.nodes)))
  for eachNode in finalGraph.nodes:
    nodeInfo.append(str(eachNode.address))
    successors1.append(str(eachNode.address))
    successors1.append(str(len(eachNode.successors)))
    for suc in eachNode.successors:
      successors1.append(str(suc.address))
      successors1.append(eachNode.successors[suc]['SystemCallName'])
    
  with open('nodeInformation.txt','w') as p:
    p.write('\n'.join(nodeInfo))
  
  with open('edgeInformation.txt','w') as p:
    p.write('\n'.join(successors1))

# function that creates system call graph
def systemCallGraph(p, cfg):
  functions = cfg.functions

  print("Creating primary graphs (per function).")
  allReachableFunctionGraphs = createPrimaryFunctionGraphs((p.entry), functions)

  print("Creating optimized Graphs (per function).")
  allOptimizedFunctionGraphs = createOptimizedFunctionGraphs(allReachableFunctionGraphs)

  print("Creating single merged graph.")
  mergedGraph = createMergedGraph(allOptimizedFunctionGraphs)

  print("Creating optimized merged graph.")
  finalGraph = optimizeFinalGraph(mergedGraph, mergedGraph.getSpecifiedNode(hex(p.entry)))

  finalGraph = enforceSanity(finalGraph, p.entry)
  print("Final System Call Graph Produced.")

  writeInfo(finalGraph,p.entry)

if __name__ == "__main__":

    # form the project
    p = angr.Project('victim.out', load_options={'auto_load_libs': False})

    # get the cfg of whole program
    cfg = p.analyses.CFGFast()

    # build the system call graph
    systemCallGraph(p, cfg)