package taintscan

import (
	"strings"

	"github.com/dimasma0305/php-parser-go/ast"
)

func (e *engine) resolveStaticPropertyOwner(className string, propertyName string) string {
	if className == "" || propertyName == "" {
		return className
	}
	seen := map[string]struct{}{}
	current := className
	for current != "" {
		if _, ok := seen[current]; ok {
			break
		}
		seen[current] = struct{}{}
		if props := e.staticPropOwners[current]; props != nil {
			if owner, ok := props[propertyName]; ok && owner != "" {
				return owner
			}
		}
		current = e.classParents[current]
	}
	return className
}

func (e *engine) resolveClassNameForCallable(node ast.Node, current callable) string {
	return resolveClassNameWithAliases(node, current.Class, e.classParents, current.UseAliases)
}

func resolveClassName(node ast.Node, currentClass string, classParents map[string]string) string {
	return resolveClassNameWithAliases(node, currentClass, classParents, nil)
}

func resolveClassNameWithAliases(node ast.Node, currentClass string, classParents map[string]string, useAliases map[string]string) string {
	switch typed := node.(type) {
	case *ast.Name:
		value := strings.ToLower(typed.Name)
		switch value {
		case "self", "static":
			return currentClass
		case "parent":
			if classParents != nil {
				return classParents[currentClass]
			}
			return ""
		default:
			if resolved, ok := typed.Attribute("resolvedName"); ok {
				return normalizedResolvedName(resolved, typed.Name)
			}
			if resolved := resolveAliasedClassName(typed.Name, useAliases); resolved != "" {
				return resolved
			}
			if namespace := namespaceForClassName(currentClass); namespace != "" {
				return qualifiedName(namespace, typed.Name)
			}
			return qualifiedName("", typed.Name)
		}
	case *ast.NameFullyQualified:
		return qualifiedName("", typed.Name)
	case *ast.NameRelative:
		return qualifiedName("", typed.Name)
	case *ast.Identifier:
		value := strings.ToLower(typed.Name)
		switch value {
		case "self", "static":
			return currentClass
		case "parent":
			if classParents != nil {
				return classParents[currentClass]
			}
		default:
			if resolved := resolveAliasedClassName(typed.Name, useAliases); resolved != "" {
				return resolved
			}
			if namespace := namespaceForClassName(currentClass); namespace != "" {
				return qualifiedName(namespace, typed.Name)
			}
			return qualifiedName("", typed.Name)
		}
	}
	return ""
}

func resolveAliasedClassName(name string, useAliases map[string]string) string {
	name = strings.TrimPrefix(strings.TrimSpace(name), `\`)
	if name == "" || len(useAliases) == 0 {
		return ""
	}
	alias := name
	remainder := ""
	if idx := strings.Index(name, `\`); idx >= 0 {
		alias = name[:idx]
		remainder = name[idx+1:]
	}
	target := strings.TrimSpace(useAliases[strings.ToLower(alias)])
	if target == "" {
		return ""
	}
	target = strings.TrimPrefix(target, `\`)
	if remainder != "" {
		target += `\` + remainder
	}
	return qualifiedName("", target)
}

func normalizedResolvedName(value any, fallback string) string {
	switch typed := value.(type) {
	case *ast.Name:
		return qualifiedName("", typed.Name)
	case *ast.NameFullyQualified:
		return qualifiedName("", typed.Name)
	case *ast.NameRelative:
		return qualifiedName("", typed.Name)
	default:
		return qualifiedName("", fallback)
	}
}
