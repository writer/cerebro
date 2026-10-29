package iac

import (
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/hcl/v2/ext/tryfunc"
	"github.com/zclconf/go-cty/cty"
	"github.com/zclconf/go-cty/cty/convert"
	"github.com/zclconf/go-cty/cty/function"
	"github.com/zclconf/go-cty/cty/function/stdlib"
)

// stdFunctions returns the deterministic, side-effect-free subset of
// Terraform's function library that this analyzer supports. Functions with
// provider/filesystem/time/randomness side effects (file, templatefile,
// timestamp, uuid, bcrypt, and similar) are intentionally absent; calling one
// produces an HCL "call to unknown function" diagnostic that the evaluator
// turns into a scoped iac.unsupported_function gap rather than a fabricated
// value.
func stdFunctions() map[string]function.Function {
	return map[string]function.Function{
		"concat":                 stdlib.ConcatFunc,
		"coalesce":               stdlib.CoalesceFunc,
		"coalescelist":           stdlib.CoalesceListFunc,
		"compact":                stdlib.CompactFunc,
		"contains":               stdlib.ContainsFunc,
		"distinct":               stdlib.DistinctFunc,
		"chunklist":              stdlib.ChunklistFunc,
		"element":                stdlib.ElementFunc,
		"flatten":                stdlib.FlattenFunc,
		"index":                  stdlib.IndexFunc,
		"keys":                   stdlib.KeysFunc,
		"length":                 stdlib.LengthFunc,
		"lookup":                 stdlib.LookupFunc,
		"merge":                  stdlib.MergeFunc,
		"reverse":                stdlib.ReverseListFunc,
		"setintersection":        stdlib.SetIntersectionFunc,
		"setunion":               stdlib.SetUnionFunc,
		"setsubtract":            stdlib.SetSubtractFunc,
		"setproduct":             stdlib.SetProductFunc,
		"setsymmetricdifference": stdlib.SetSymmetricDifferenceFunc,
		"slice":                  stdlib.SliceFunc,
		"sort":                   stdlib.SortFunc,
		"values":                 stdlib.ValuesFunc,
		"zipmap":                 stdlib.ZipmapFunc,
		"jsonencode":             stdlib.JSONEncodeFunc,
		"jsondecode":             stdlib.JSONDecodeFunc,
		"csvdecode":              stdlib.CSVDecodeFunc,
		"format":                 stdlib.FormatFunc,
		"formatlist":             stdlib.FormatListFunc,
		"join":                   stdlib.JoinFunc,
		"split":                  stdlib.SplitFunc,
		"lower":                  stdlib.LowerFunc,
		"upper":                  stdlib.UpperFunc,
		"strrev":                 stdlib.ReverseFunc,
		"substr":                 stdlib.SubstrFunc,
		"title":                  stdlib.TitleFunc,
		"trim":                   stdlib.TrimFunc,
		"trimprefix":             stdlib.TrimPrefixFunc,
		"trimsuffix":             stdlib.TrimSuffixFunc,
		"trimspace":              stdlib.TrimSpaceFunc,
		"chomp":                  stdlib.ChompFunc,
		"indent":                 stdlib.IndentFunc,
		"replace":                stdlib.ReplaceFunc,
		"regex":                  stdlib.RegexFunc,
		"regexall":               stdlib.RegexAllFunc,
		"regex_replace":          stdlib.RegexReplaceFunc,
		"abs":                    stdlib.AbsoluteFunc,
		"ceil":                   stdlib.CeilFunc,
		"floor":                  stdlib.FloorFunc,
		"log":                    stdlib.LogFunc,
		"max":                    stdlib.MaxFunc,
		"min":                    stdlib.MinFunc,
		"parseint":               stdlib.ParseIntFunc,
		"pow":                    stdlib.PowFunc,
		"signum":                 stdlib.SignumFunc,
		"try":                    tryfunc.TryFunc,
		"can":                    tryfunc.CanFunc,
		"tostring":               convFunc(cty.String),
		"tonumber":               convFunc(cty.Number),
		"tobool":                 convFunc(cty.Bool),
		"tolist":                 convFunc(cty.List(cty.DynamicPseudoType)),
		"toset":                  convFunc(cty.Set(cty.DynamicPseudoType)),
		"tomap":                  convFunc(cty.Map(cty.DynamicPseudoType)),
		"one":                    oneFunc,
		"base64encode":           base64EncodeFunc,
		"base64decode":           base64DecodeFunc,
	}
}

// convFunc builds a Terraform-style conversion function (tostring, tonumber,
// ...) in terms of cty's own conversion rules.
func convFunc(want cty.Type) function.Function {
	return function.New(&function.Spec{
		Params: []function.Parameter{{
			Name:             "v",
			Type:             cty.DynamicPseudoType,
			AllowNull:        true,
			AllowUnknown:     true,
			AllowDynamicType: true,
		}},
		Type: func(args []cty.Value) (cty.Type, error) {
			if !args[0].IsWhollyKnown() {
				return cty.DynamicPseudoType, nil
			}
			v, err := convert.Convert(args[0], want)
			if err != nil {
				return cty.NilType, err
			}
			return v.Type(), nil
		},
		Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
			return convert.Convert(args[0], want)
		},
	})
}

var oneFunc = function.New(&function.Spec{
	Params: []function.Parameter{{
		Name:             "list",
		Type:             cty.DynamicPseudoType,
		AllowDynamicType: true,
	}},
	Type: func(args []cty.Value) (cty.Type, error) {
		ty := args[0].Type()
		if ty == cty.DynamicPseudoType {
			return cty.DynamicPseudoType, nil
		}
		if ty.IsListType() || ty.IsSetType() || ty.IsTupleType() {
			if ty.IsTupleType() {
				return cty.DynamicPseudoType, nil
			}
			return ty.ElementType(), nil
		}
		return cty.NilType, fmt.Errorf("argument must be list, set, or tuple")
	},
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		v := args[0]
		if !v.IsKnown() {
			return cty.UnknownVal(retType), nil
		}
		if v.LengthInt() == 0 {
			return cty.NilVal, fmt.Errorf("the list, set, or tuple is empty")
		}
		if v.LengthInt() != 1 {
			return cty.NilVal, fmt.Errorf("the list, set, or tuple has more than one element")
		}
		var result cty.Value
		v.ForEachElement(func(key, val cty.Value) bool {
			result = val
			return true
		})
		return result, nil
	},
})

var base64EncodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		return cty.StringVal(base64.StdEncoding.EncodeToString([]byte(args[0].AsString()))), nil
	},
})

var base64DecodeFunc = function.New(&function.Spec{
	Params: []function.Parameter{{Name: "str", Type: cty.String}},
	Type:   function.StaticReturnType(cty.String),
	Impl: func(args []cty.Value, retType cty.Type) (cty.Value, error) {
		b, err := base64.StdEncoding.DecodeString(args[0].AsString())
		if err != nil {
			return cty.UnknownVal(cty.String), fmt.Errorf("invalid base64 string: %w", err)
		}
		return cty.StringVal(string(b)), nil
	},
})
