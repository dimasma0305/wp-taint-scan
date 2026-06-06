package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (s *analysisState) assignToNode(node ast.Node, origins originSet, className string) {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return
		}
		s.varTaint[name] = origins
		if className != "" {
			s.classEnv[name] = className
		} else {
			delete(s.classEnv, name)
		}
	case *ast.ExprArrayDimFetch:
		if path, ok := localClassPathKey(typed); ok {
			if className != "" {
				s.classEnv[path] = className
			} else {
				delete(s.classEnv, path)
			}
		}
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			clearStructuralPrefix(s.staticPropTaint, path)
			if len(origins) == 0 {
				delete(s.staticPropTaint, path)
			} else {
				s.staticPropTaint[path] = origins
			}
		}
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			clearStructuralPrefix(s.propTaint, path)
			if len(origins) == 0 {
				s.propTaint[path] = originSet{}
			} else {
				s.propTaint[path] = origins
			}
			if strings.HasPrefix(path, "this.") {
				unionMapEntry(s.receiverWrites, strings.TrimPrefix(path, "this."), origins)
			}
		}
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			clearStructuralPrefix(s.propTaint, path)
			if len(origins) == 0 {
				s.propTaint[path] = originSet{}
			} else {
				s.propTaint[path] = origins
			}
			if strings.HasPrefix(path, "this.") {
				unionMapEntry(s.receiverWrites, strings.TrimPrefix(path, "this."), origins)
			}
			return
		}
	case *ast.ExprStaticPropertyFetch:
		if path, ok := staticPropertyPathKey(typed, s.current.Class, s.engine); ok {
			clearStructuralPrefix(s.staticPropTaint, path)
			if len(origins) == 0 {
				delete(s.staticPropTaint, path)
			} else {
				s.staticPropTaint[path] = origins
			}
			return
		}
	}
}

func (s *analysisState) assignStringHint(target ast.Node, expr ast.Node) {
	variable, ok := target.(*ast.ExprVariable)
	if !ok {
		return
	}
	name, ok := variable.Name.(string)
	if !ok {
		return
	}
	if value := dynamicDispatchStringForCallable(expr, s.current, s.engine, s.stringEnv); value != "" {
		s.stringEnv[name] = value
		return
	}
	delete(s.stringEnv, name)
}

func (s *analysisState) appendStringHint(target ast.Node, expr ast.Node) {
	variable, ok := target.(*ast.ExprVariable)
	if !ok {
		return
	}
	name, ok := variable.Name.(string)
	if !ok {
		return
	}
	current := dynamicDispatchStringForCallable(target, s.current, s.engine, s.stringEnv)
	next := dynamicDispatchStringForCallable(expr, s.current, s.engine, s.stringEnv)
	if current == "" || next == "" {
		delete(s.stringEnv, name)
		return
	}
	s.stringEnv[name] = current + next
}

func (s *analysisState) applyPostAssignEffects(target ast.Node, expr ast.Node) {
	s.copyStructuralAssignEffects(target, expr)
	if root, ok := s.structuralRoot(target); ok {
		pruneCoveredStructuralRoot(s.destinationStructuralStore(root), root.key)
	}
	newExpr, ok := expr.(*ast.ExprNew)
	if !ok {
		return
	}
	root := receiverRootKey(target, s.current.Class)
	if root == "" {
		return
	}
	className := resolveClassName(newExpr.Class, s.current.Class, s.engine.classParents)
	if className == "" {
		return
	}
	key := s.resolveMethodKey(className, "__construct")
	if key == "" {
		return
	}
	args := s.evalArgs(newExpr.Args)
	summary := s.summaryForKey(key)
	for name, effect := range summary.ReceiverWrites {
		unionMapEntry(s.propTaint, root+"."+name, s.instantiateTaintSummary(effect, args, newExpr.Args))
	}
	for path, effect := range summary.ReceiverPathWrites {
		unionMapEntry(s.propTaint, root+"."+path, s.instantiateTaintSummary(effect, args, newExpr.Args))
	}
	for path, family := range summary.ReceiverStorageLinks {
		dstRoot := root + "." + path
		copyPersistentStructuralPathMap(s.propTaint, s.engine.storagePaths, dstRoot, family)
		copyStructuralPathMap(s.propTaint, s.storagePathWrites, dstRoot, family)
		s.recordStructuralStorageLink(dstRoot, family)
	}
}

func (s *analysisState) resolveClassExpr(node ast.Node) string {
	switch typed := node.(type) {
	case *ast.ExprVariable:
		name, ok := typed.Name.(string)
		if !ok {
			return ""
		}
		if name == "this" {
			return s.current.Class
		}
		if s.current.ParamTypes != nil {
			if className := strings.TrimSpace(s.current.ParamTypes[strings.TrimSpace(name)]); className != "" {
				return className
			}
		}
		return s.classEnv[name]
	case *ast.ExprArrayDimFetch:
		if path, ok := localClassPathKey(typed); ok {
			return s.classEnv[path]
		}
		return ""
	case *ast.ExprNew:
		return resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
	case *ast.ExprAssign:
		return s.resolveClassExpr(typed.Expr)
	case *ast.ExprAssignRef:
		return s.resolveClassExpr(typed.Expr)
	case *ast.ExprFuncCall:
		if className := s.engine.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		if key := s.resolveFunctionKey(typed.Name); key != "" {
			return s.engine.callableReturnClassHint(key)
		}
		return ""
	case *ast.ExprStaticCall:
		if className := s.engine.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		name := strings.ToLower(identifierText(typed.Name))
		className := resolveClassName(typed.Class, s.current.Class, s.engine.classParents)
		if singletonClass := singletonFactoryReturnClass(name, className); singletonClass != "" {
			return singletonClass
		}
		if key := s.resolveMethodKey(className, name); key != "" {
			if className := s.engine.callableReturnClassHint(key); className != "" {
				return className
			}
			return s.engine.callableReturnedReceiverPropertyClassHint(key, className, "")
		}
		return ""
	case *ast.ExprMethodCall:
		if className := s.engine.inferLiteralFactoryReturnClass(identifierText(typed.Name), typed.Args); className != "" {
			return className
		}
		name := strings.ToLower(identifierText(typed.Name))
		receiverClass := s.resolveClassExpr(typed.Var)
		if key := s.resolveMethodKey(receiverClass, name); key != "" {
			if className := s.engine.callableReturnClassHint(key); className != "" {
				return className
			}
			previousMethodKey := ""
			if previousCall, ok := typed.Var.(*ast.ExprMethodCall); ok {
				previousReceiverClass := s.resolveClassExpr(previousCall.Var)
				previousMethodKey = s.resolveMethodKey(previousReceiverClass, strings.ToLower(identifierText(previousCall.Name)))
			}
			return s.engine.callableReturnedReceiverPropertyClassHint(key, receiverClass, previousMethodKey)
		}
		return ""
	case *ast.ExprPropertyFetch:
		if path, ok := propertyPathKey(typed, s.current.Class); ok {
			return s.engine.receiverPropertyReturnClassHint(s.current.Class, path)
		}
		return ""
	default:
		return ""
	}
}
