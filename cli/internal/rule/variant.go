package rule

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/Athar-HQ/Athar/cli/internal/condition"
)

// Implies reports whether the variant-of link from variant to family holds
// up: both name the same family, and every service the variant matches is
// one the family matches too (spec section 8). It is false when that could
// not be shown.
func Implies(variant, family *Rule) bool {
	return len(checkVariant(variant, family)) == 0
}

// checkVariant checks one variant-of link. The check is simple on purpose:
// every selection the family's condition requires must be repeated by a
// selection the variant's condition requires. Conditions it can't decide
// give a warning, not an error.
func checkVariant(v, f *Rule) []Problem {
	if v == f || v.ID == f.ID {
		return []Problem{errorf("variant-of %s: a rule can't be a variant of itself", f.ID)}
	}
	var p []Problem
	if v.Identifies.Family != f.Identifies.Family {
		p = append(p, errorf("variant-of %s: identifies.family %q differs from the family rule's %q", f.ID, v.Identifies.Family, f.Identifies.Family))
	}
	undecided := func(why string) []Problem {
		return append(p, warnf("variant-of %s: could not check that this rule implies its family: %s", f.ID, why))
	}

	need, plain, err := required(f)
	if err != nil {
		return undecided("the family's condition: " + err.Error())
	}
	if !plain {
		return undecided("the family's condition is not a single selection or an AND of selections")
	}
	have, _, err := required(v)
	if err != nil {
		return undecided("this rule's condition: " + err.Error())
	}
	if len(have) == 0 {
		return undecided("this rule's condition requires no selection; start it with the family's selections, joined by AND")
	}
	for _, name := range need {
		repeated := false
		for _, h := range have {
			if selectionImplies(v, v.Detection[h], f, f.Detection[name]) {
				repeated = true
				break
			}
		}
		if !repeated {
			p = append(p, errorf("variant-of %s: does not imply its family: no required selection repeats the family's %q (same probe, fields, modifiers and values)", f.ID, name))
		}
	}
	return p
}

// required returns the selections a rule's condition requires: the condition
// itself or the terms of its top-level AND, as far as they are plain
// selection names. plain says that there are no other terms.
func required(r *Rule) (names []string, plain bool, err error) {
	cond, _ := r.Detection["condition"].(string)
	var all []string
	for name := range r.Detection {
		if name != "condition" {
			all = append(all, name)
		}
	}
	root, err := condition.Parse(cond, all)
	if err != nil {
		return nil, false, err
	}
	plain = true
	var walk func(n condition.Node)
	walk = func(n condition.Node) {
		switch x := n.(type) {
		case condition.Ident:
			names = append(names, string(x))
		case condition.And:
			for _, term := range x {
				walk(term)
			}
		default:
			plain = false
		}
	}
	walk(root)
	return names, plain, nil
}

// selectionImplies reports whether a service that matches the variant's
// selection vs also matches the family's selection fs.
func selectionImplies(v *Rule, vs any, f *Rule, fs any) bool {
	vMaps, vWords := alternatives(vs)
	fMaps, fWords := alternatives(fs)
	if len(vMaps) == 0 || len(fMaps) == 0 {
		// Keywords: the variant may search for fewer of them.
		return len(vMaps) == 0 && len(fMaps) == 0 && len(vWords) > 0 && subset(vWords, fWords)
	}
	if len(vWords) > 0 || len(fWords) > 0 {
		return false
	}
	// Lists of maps are OR: each of the variant's maps must imply one of
	// the family's.
	for _, vm := range vMaps {
		implied := false
		for _, fm := range fMaps {
			if mapImplies(v, vm, f, fm) {
				implied = true
				break
			}
		}
		if !implied {
			return false
		}
	}
	return true
}

// alternatives splits a selection into its maps (one map, or a list of maps)
// and its keywords.
func alternatives(sel any) (maps []map[string]any, words []any) {
	switch x := sel.(type) {
	case map[string]any:
		return []map[string]any{x}, nil
	case []any:
		for _, e := range x {
			if m, ok := e.(map[string]any); ok {
				maps = append(maps, m)
			} else {
				words = append(words, e)
			}
		}
		return maps, words
	case nil:
		return nil, nil
	}
	return nil, []any{sel}
}

// mapImplies reports whether the variant's map vm has every field condition
// of the family's map fm, on the same probe. More conditions only narrow it.
func mapImplies(v *Rule, vm map[string]any, f *Rule, fm map[string]any) bool {
	vProbe, fProbe := probeOf(vm), probeOf(fm)
	if vProbe != fProbe || !reflect.DeepEqual(v.Probes[vProbe], f.Probes[fProbe]) {
		return false
	}
	vConds := map[string][]any{}
	for k, val := range vm {
		key, _ := fieldKey(k)
		vConds[key] = values(val)
	}
	for k, val := range fm {
		if k == "probe" {
			continue
		}
		key, all := fieldKey(k)
		vv, ok := vConds[key]
		if !ok {
			return false
		}
		fv := values(val)
		if all {
			// |all is AND: the variant must ask for at least the family's values.
			vv, fv = fv, vv
		}
		if !subset(vv, fv) {
			return false
		}
	}
	return true
}

func probeOf(m map[string]any) string {
	if p, ok := m["probe"].(string); ok {
		return p
	}
	return "default"
}

// fieldKey returns "field|modifiers" with the modifiers sorted, and whether
// |all is among them.
func fieldKey(k string) (key string, all bool) {
	parts := strings.Split(k, "|")
	sort.Strings(parts[1:])
	for _, mod := range parts[1:] {
		all = all || mod == "all"
	}
	return strings.Join(parts, "|"), all
}

func values(v any) []any {
	if list, ok := v.([]any); ok {
		return list
	}
	return []any{v}
}

// subset reports whether every value of a is also in b.
func subset(a, b []any) bool {
	for _, x := range a {
		found := false
		for _, y := range b {
			if (x == nil) == (y == nil) && fmt.Sprint(x) == fmt.Sprint(y) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// variantOf reports whether rule r is, over any number of variant-of links,
// a variant of the rule with the given id.
func variantOf(byID map[string]*Rule, r *Rule, id string, seen map[*Rule]bool) bool {
	if seen[r] {
		return false
	}
	seen[r] = true
	for _, rel := range r.Related {
		if rel.Type != "variant-of" {
			continue
		}
		if rel.ID == id {
			return true
		}
		if next := byID[rel.ID]; next != nil && variantOf(byID, next, id, seen) {
			return true
		}
	}
	return false
}

// Families returns the rules that variant-of links in rules point to and that
// are not among rules, taken from the other rule files in each variant's
// directory. They are for CheckSet, to check one variant on its own. Files
// that can't be read are skipped.
func Families(rules []*Rule) []*Rule {
	have := map[string]bool{}
	for _, r := range rules {
		have[r.ID] = true
	}
	wanted := map[string]map[string]bool{} // directory -> family ids
	for _, r := range rules {
		for _, rel := range r.Related {
			if rel.Type != "variant-of" || have[rel.ID] {
				continue
			}
			dir := filepath.Dir(r.Path)
			if wanted[dir] == nil {
				wanted[dir] = map[string]bool{}
			}
			wanted[dir][rel.ID] = true
		}
	}
	var out []*Rule
	for _, dir := range sortedKeys(wanted) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if ext := filepath.Ext(e.Name()); e.IsDir() || (ext != ".yml" && ext != ".yaml") {
				continue
			}
			r, err := Load(filepath.Join(dir, e.Name()))
			if err != nil || !wanted[dir][r.ID] || have[r.ID] {
				continue
			}
			have[r.ID] = true
			out = append(out, r)
		}
	}
	return out
}
