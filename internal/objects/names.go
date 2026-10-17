// Naming helpers adapted from golang.org/x/debug/cmd/viewcore (BSD license).

package objects

import (
	"fmt"

	"github.com/vrutkovs/golang-cold-memory/internal/xdebug/gocore"
)

// typeName names x's type; unknown types become unk<size>.
func typeName(c *gocore.Process, x gocore.Object) string {
	size := c.Size(x)
	typ, repeat := c.Type(x)
	if typ == nil {
		return fmt.Sprintf("unk%d", size)
	}
	name := typ.String()
	n := size / typ.Size
	if n <= 1 {
		return name
	}
	if repeat < n {
		return fmt.Sprintf("[%d+%d?]%s", repeat, n-repeat, name)
	}
	return fmt.Sprintf("[%d]%s", repeat, name)
}

// fieldName names the field at offset off in x.
func fieldName(c *gocore.Process, x gocore.Object, off int64) string {
	size := c.Size(x)
	typ, repeat := c.Type(x)
	if typ == nil {
		return fmt.Sprintf(".f%d", off)
	}
	n := size / typ.Size
	i := off / typ.Size
	if i == 0 && repeat == 1 {
		return typeFieldName(typ, off)
	}
	if i >= n {
		return fmt.Sprintf(".f%d", off)
	}
	q := ""
	if i >= repeat {
		q = "?"
	}
	return fmt.Sprintf("[%d]%s%s", i, typeFieldName(typ, off-i*typ.Size), q)
}

func typeFieldName(t *gocore.Type, off int64) string {
	if t == nil {
		return ""
	}
	switch t.Kind {
	case gocore.KindBool, gocore.KindInt, gocore.KindUint, gocore.KindFloat, gocore.KindPtr, gocore.KindFunc:
		return ""
	case gocore.KindComplex:
		if off == 0 {
			return ".real"
		}
		return ".imag"
	case gocore.KindIface, gocore.KindEface:
		if off == 0 {
			return ".type"
		}
		return ".data"
	case gocore.KindString:
		if off == 0 {
			return ".ptr"
		}
		return ".len"
	case gocore.KindSlice:
		if off == 0 {
			return ".ptr"
		}
		if off <= t.Size/2 {
			return ".len"
		}
		return ".cap"
	case gocore.KindArray:
		s := t.Elem.Size
		i := off / s
		return fmt.Sprintf("[%d]%s", i, typeFieldName(t.Elem, off-i*s))
	case gocore.KindStruct:
		for _, f := range t.Fields {
			if f.Off <= off && off < f.Off+f.Type.Size {
				return "." + f.Name + typeFieldName(f.Type, off-f.Off)
			}
		}
	}
	return ".???"
}
