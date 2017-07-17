package aml

import (
	"fmt"
	"gopheros/kernel"
	"gopheros/kernel/kfmt"
	"io"
)

const interpreterVersion = uint8(1)

var (
	errParsingAML = &kernel.Error{Module: "aml_parser", Message: "could not parse AML bytestream"}
)

type parser struct {
	r         *seekableByteReader
	errWriter io.Writer

	lastOpcode int
	lastErr    kernel.Error

	root    Namespace
	nsStack []Namespace
}

// Parse processes the given AML stream and returns back the root ACPI
// namespace containing all definitions found in the stream. The parser emits
// any encountered errors to the supplied io.Writer.
func Parse(amlStream []byte, errWriter io.Writer) (Namespace, error) {
	p := newParser(
		&seekableByteReader{data: amlStream},
		errWriter,
	)

	// The AML stream points to a TermList
	ok := p.pTermList(uint32(len(amlStream)))
	if !ok {
		lastOpcode, err := p.r.LastByte()
		if err == nil {
			//spew.Config.DisablePointerAddresses = true
			//spew.Dump(p.root)
			kfmt.Fprintf(errWriter, "\n[offset %d] parse failed; opcode: 0x%2x", p.r.Offset()-1, lastOpcode)
			return nil, errParsingAML
		} else {
			kfmt.Fprintf(errWriter, "\n[offset %d] parse failed; reached EOF", p.r.Offset())
			return nil, errParsingAML
		}
	}
	return p.root, nil
}

// newParser creates a new AML parser and initializes the default namespaces
// according to the ACPI spec.
func newParser(r *seekableByteReader, errWriter io.Writer) *parser {
	return &parser{
		r:         r,
		errWriter: errWriter,
		root: &scope{
			name: `\`,
			children: []Object{
				&scope{name: `_GPE`}, // General events in GPE register block
				&scope{name: `_PR_`}, // ACPI 1.0 processor namespace
				&scope{name: `_SB_`}, // System bus with all device objects
				&scope{name: `_SI_`}, // System indicators
				&scope{name: `_TZ_`}, // ACPI 1.0 thermal zone namespace
			},
		},
	}
}

// pTermList parses a TermList until an error occurs or the AML stream reader's
// offset reaches maxOffset.
func (p *parser) pTermList(maxOffset uint32) bool {
	var ok = true

	for ok && p.r.Offset() < maxOffset && !p.r.EOF() {
		ok = p.pTermObj()
	}

	return ok && !p.r.EOF()
}

// pTermObj parses a TermObject which is either an Object, as Type1Opcode or a
// Type2Opcode.
//
// Grammar:
// TermObject := Object | Type1Opcode | Type2Opcode
// Object := NamespaceModifierObj | NamedObj
// NameSpaceModifierObj := DefAlias | DefName | DefScope
func (p *parser) pTermObj() bool {
	next, err := p.r.ReadByte()
	fmt.Printf("pTerm: next 0x%0x\n", next)
	if err != nil {
		return false
	}

	switch {
	case next == 0x06: // DefAlias := AliasOp NameString NameString
		srcName, ok := p.pNameString()
		if !ok {
			return false
		}

		// srcName must already exist in the namespace
		srcObj := p.objFind(srcName)
		if srcObj == nil {
			kfmt.Fprintf(p.errWriter, "alias: unknown source name: %s", srcName)
			return false
		}

		dstName, ok := p.pNameString()
		if !ok {
			return false
		}

		return p.nsCurrent().Append(&alias{
			name:   dstName,
			target: srcObj,
		})
	case next == 0x08: // DefName := NameOp NameString DataRefObject
		return p.pDefName()
	case next == 0x10: // DefScope := NameOp NameString DataRefObjec
		return p.pDefScope()
	case p.isType1Opcode(next):
		return p.pType1Opcode(next)
	case p.isType2Opcode(next):
		return p.pType2Opcode(next)
	case p.isNamedObject(next):
		return p.pNamedObject(next)
	}

	return false
}

// pTermArgList attempts to pass argCount TermArg objects and returns them
// as a []interface{}.
func (p *parser) pTermArgList(argCount uint8) ([]interface{}, bool) {
	var args []interface{}

	for argIndex := uint8(0); argIndex < argCount && !p.r.EOF(); argIndex++ {
		arg := p.pTermArg()
		if arg == nil {
			return nil, false
		}

		args = append(args, arg)
	}

	return args, !p.r.EOF()
}

// pTermArg parses a TermArg and returns it. If the parsing fails, pTermArg
// returns nil. This is intentional so that pTermArg can be used as an argument
// to the various evalAsXXX methods.
//
// Grammar:
// TermArg := Type2Opcode | DataObject | ArgObj | LocalObj
// DataObject := ComputationalData | DefPackage | DefVarPackage
// ComputationalData := ByteConst | WordConst | DWordConst | QWordConst | String | ConstObj | RevisionOp | DefBuffer
func (p *parser) pTermArg() interface{} {
	next, err := p.r.ReadByte()
	fmt.Printf("pTermArg. Next: 0x%2x\n", next)
	if err != nil {
		return false
	}

	if p.isType2Opcode(next) {
		fmt.Printf("isType2!\n")
		// pType2Opcode pushes the result to the namespace so we need
		// to extract the value and return it.
		if !p.pType2Opcode(next) {
			return nil
		}

		return p.nsCurrent().removeLast()
	}

	switch {
	case next == 0x0a: // ByteConst
		if v, ok := p.pNumConstant(1); ok {
			return uint8(v)
		}
	case next == 0x0b: // WordConst
		if v, ok := p.pNumConstant(2); ok {
			return uint16(v)
		}
	case next == 0x0c: // DWordConst
		if v, ok := p.pNumConstant(4); ok {
			return uint32(v)
		}
	case next == 0x0d: // String
		if v, ok := p.pString(); ok {
			return v
		}
	case next == 0x0e: // QWordConst
		if v, ok := p.pNumConstant(8); ok {
			return v
		}
	case next == 0x00: // ConstObj -> Zero
		return uint8(0)
	case next == 0x01: // ConstObj -> One
		return uint8(1)
	case next == 0xff: // ConstObj -> All bits set
		return uint64(1<<64 - 1)
	case next == 0x5b: // ExtOpPrefix
		if next, err = p.r.ReadByte(); err != nil {
			return nil
		}

		switch next {
		case 0x30: // RevisionOp (returns AML interpreter version)
			return interpreterVersion
		}
	case next >= 0x60 && next <= 0x67: // LocalArg
		return &fnLocalArg{arg: next - 0x60}
	case next >= 0x68 && next <= 0x6e: // Arg
		return &fnArg{arg: next - 0x68}
	}

	return nil
}

// isType1Opcode returns true if op is one of the valid Type1 opcodes.
func (p *parser) isType1Opcode(op uint8) bool {
	next, err := p.r.PeekByte()

	switch op {
	case 0x5b: // ExtOpPrefix
		if err != nil {
			return false
		}

		switch next {
		case 0x20: // DefLoad
		case 0x21: // DefStall
		case 0x22: // DefSleep
		case 0x24: // DefSignal
		case 0x26: // DefReset
		case 0x27: // DefRelease
		case 0x2a: // DefUnload
		case 0x32: // DefFatal
		default:
			return false
		}
	case 0x86: // DefNotify
	case 0x9f: // DefContinue
	case 0xa0: // DefIfElse
	case 0xa1: // DefElse (missing from Type1 opcode list; grammar typo?)
	case 0xa2: // DefWhile
	case 0xa3: // DefNoop
	case 0xa4: // DefReturn
	case 0xa5: // DefBreak
	case 0xcc: // DefBreakpoint
	default:
		return false
	}

	return true
}

// pType1Opcode parses a Type1Opcode from the AML bytestream and inserts it
// into the current namespace. This method assumes that the caller has
// validated that this is indeed a valid opcode via isType1Opcode.
func (p *parser) pType1Opcode(op uint8) bool {
	fmt.Printf("parse typ1: 0x%0x\n", op)

	switch op {
	case 0x5b: // ExtOpPrefix
		// We have already verified that a next byte is available so
		// we can safely ignore the error from ReadByte
		next, _ := p.r.ReadByte()

		switch next {
		case 0x20: // DefLoad
		case 0x21: // DefStall
		case 0x22: // DefSleep
		case 0x24: // DefSignal
		case 0x26: // DefReset
		case 0x27: // DefRelease
		case 0x2a: // DefUnload
		case 0x32: // DefFatal
		default:
			return false
		}
	case 0x86: // DefNotify
	case 0x9f: // DefContinue
	case 0xa0: // DefIfElse
		curOffset := p.r.Offset()
		pkgLen, ok := p.pPkgLength()
		if !ok {
			return false
		}

		predicate := p.pTermArg()
		if predicate == nil {
			return false
		}

		thenBlock := &scope{}
		elseBlock := &scope{}

		ifBlock := &fnIfElse{predicate: predicate}
		ifBlock.Append(thenBlock)
		ifBlock.Append(elseBlock)

		// Enter "then" block and parse elements.
		p.nsCurrent().Append(ifBlock)
		p.nsEnter(thenBlock)
		ok = p.pTermList(curOffset + pkgLen)
		p.nsExit()

		return ok
	case 0xa1: // DefElse := ElseOp PkgLength TermList
		curOffset := p.r.Offset()
		pkgLen, ok := p.pPkgLength()
		if !ok {
			return false
		}

		// The last element in the current namespace should be an fnIfElse
		ifBlock, ok := p.nsCurrent().Children()[len(p.nsCurrent().Children())-1].(*fnIfElse)
		if !ok {
			kfmt.Fprintf(p.errWriter, "encountered else block without an ifElse function")
			return false
		}

		// Temporarily enter the else block so we can parse the block
		p.nsEnter(ifBlock.children[1].(Namespace))
		ok = p.pTermList(curOffset + pkgLen)
		p.nsExit()

		return ok
	case 0xa2: // DefWhile := WhileOp PkgLength Predicate TermList
		curOffset := p.r.Offset()
		pkgLen, ok := p.pPkgLength()
		if !ok {
			return false
		}

		predicate := p.pTermArg()
		if predicate == nil {
			return false
		}

		whileBlock := &fnWhile{predicate: predicate}

		p.nsCurrent().Append(whileBlock)
		p.nsEnter(whileBlock)
		ok = p.pTermList(curOffset + pkgLen)
		p.nsExit()

		return ok
	case 0xa3: // DefNoop
		return true
	case 0xa4: // DefReturn := ReturnOp TermArg => DataRefObject
		arg := p.pTermArg()
		if arg == nil {
			return false
		}

		return p.nsCurrent().Append(&fnReturn{
			val: arg,
		})
	case 0xa5: // DefBreak
	case 0xcc: // DefBreakpoint
	default:
		return false
	}

	return true
}

// isType2Opcode returns true if op is one of the valid Type2 opcodes.
func (p *parser) isType2Opcode(op uint8) bool {
	next, err := p.r.PeekByte()

	switch op {
	case 0x11: // DefBuffer
	case 0x12: // DefPackage
	case 0x13: // DefVarPackage
	case 0x5b: // ExtOpPrefix
		if err != nil {
			return false
		}

		switch next {
		case 0x1f: // DefLoadTable
		case 0x12: // DefCondRefOf
		case 0x23: // DefAcquire
		case 0x25: // DefWait
		case 0x28: // DefFromBCD
		case 0x29: // DefToBCD
		case 0x33: // DefTimer
		default:
			return false
		}
	case 0x70: // DefStore
	case 0x71: // DefRefOf
	case 0x72: // DefAdd
	case 0x73: // DefConcat
	case 0x74: // DefSubtract
	case 0x75: // DefIncrement
	case 0x76: // DefDecrement
	case 0x77: // DefMultiply
	case 0x78: // DefDivide
	case 0x79: // DefShiftLeft
	case 0x7a: // DefShiftRight
	case 0x7b: // DefAnd
	case 0x7c: // DefNAnd
	case 0x7d: // DefOr
	case 0x7e: // DefNOr
	case 0x7f: // DefXOr
	case 0x80: // DefNot
	case 0x81: // DefFindSetLeftBit
	case 0x82: // DefFindSetRightBit
	case 0x83: // DefDerefOf
	case 0x84: // DefConcatRes
	case 0x85: // DefMod
	case 0x87: // DefSizeOf
	case 0x88: // DefIndex
	case 0x89: // DefMatch
	case 0x8e: // DefObjectType
	case 0x90: // DefLAnd
	case 0x91: // DefLOr
	case 0x92: // LnotOp
		if err != nil {
			return false
		}

		switch next {
		case 0x93: // DefLNotEqual
		case 0x94: // DefLLessEqual
		case 0x95: // DefLGreaterEqual
		default:
			return true // DefNot
		}
	case 0x93: // DefLEqual
	case 0x94: // DefLGreater
	case 0x95: // DefLLess
	case 0x96: // DefToBuffer
	case 0x97: // DefToDecimalString
	case 0x98: // DefToHexString
	case 0x99: // DefToInteger
	case 0x9c: // DefToString
	case 0x9d: // DefCopyObject
	case 0x9e: // DefMid
	default:
		// Special case:
		// ObjectList -> NameString
		// MethodInvocation -> NameString TermArgList
		return op == '\\' ||
			op == '^' ||
			op == '_' ||
			(op >= 'A' && op <= 'Z') ||
			(op >= '0' && op <= '9')
	}

	return true
}

// pCompareOp parses the two operands for a comparison operator from the AML
// bytestream and inserts a fnCompare object to the current namespace.
func (p *parser) pCompareOp(operator fnCompareOp) bool {
	op1, op2 := p.pTermArg(), p.pTermArg()
	fmt.Printf("op1: %v, op2: %v\n", op1, op2)
	if op1 == nil || op2 == nil {
		return false
	}

	return p.nsCurrent().Append(&fnCompare{
		operator: operator,
		operands: [2]interface{}{op1, op2},
	})
}

// pType2Opcode parses a Type2Opcode from the AML bytestream and inserts it
// into the current namespace. This method assumes that the caller has
// validated that this is indeed a valid opcode via isType2Opcode.
func (p *parser) pType2Opcode(op uint8) bool {
	fmt.Printf("parseT2: next 0x%2x\n", op)
	switch op {
	case 0x11: // DefBuffer := BufferOp PkgLength BufferSize ByteList
		curOff := p.r.Offset()
		pkgLen, ok := p.pPkgLength()
		if !ok {
			return false
		}

		bufSize := p.pTermArg()
		if !ok {
			return false
		}

		buf := &fnBuffer{
			size: bufSize,
		}

		// Read any data up to pkgLen
		for p.r.Offset() < curOff+pkgLen {
			b, err := p.r.ReadByte()
			if err != nil {
				return false
			}
			buf.data = append(buf.data, b)
		}

		return p.nsCurrent().Append(buf)
	case 0x12: // DefPackage
	case 0x13: // DefVarPackage
	case 0x5b: // ExtOpPrefix
		// We have already verified that a next byte is available so
		// we can safely ignore the error from ReadByte
		next, _ := p.r.ReadByte()

		switch next {
		case 0x1f: // DefLoadTable
		case 0x12: // DefCondRefOf
		case 0x23: // DefAcquire
		case 0x25: // DefWait
		case 0x28: // DefFromBCD
		case 0x29: // DefToBCD
		case 0x33: // DefTimer
		default:
			return false
		}
	case 0x70: // DefStore := StoreOp TermArg SuperName
		val := p.pTermArg()
		if val == nil {
			return false
		}

		dst := p.pSuperName()
		if dst == nil {
			return false
		}

		return p.nsCurrent().Append(&fnStore{
			dst: dst,
			val: val,
		})
	case 0x71: // DefRefOf
	case 0x72: // DefAdd := AddOp Operand Operand Target
		op1 := p.pTermArg()
		if op1 == nil {
			return false
		}

		op2 := p.pTermArg()
		if op2 == nil {
			return false
		}

		dst := p.pTarget()
		if dst == nil {
			return false
		}

		return p.nsCurrent().Append(&fnAdd{
			operands: [2]interface{}{op1, op2},
			dst:      dst,
		})
	case 0x73: // DefConcat
	case 0x74: // DefSubtract := SubOp Operand Operand Target
		op1 := p.pTermArg()
		if op1 == nil {
			return false
		}

		op2 := p.pTermArg()
		if op2 == nil {
			return false
		}

		dst := p.pTarget()
		if dst == nil {
			return false
		}

		return p.nsCurrent().Append(&fnSub{
			operands: [2]interface{}{op1, op2},
			dst:      dst,
		})
	case 0x75: // DefIncrement := IncrementOp SuperName
		target := p.pSuperName()
		if target == nil {
			return false
		}

		return p.nsCurrent().Append(&fnInc{operand: target})
	case 0x76: // DefDecrement := DecrementOp SuperName
		target := p.pSuperName()
		if target == nil {
			return false
		}

		return p.nsCurrent().Append(&fnDec{operand: target})
	case 0x77: // DefMultiply
	case 0x78: // DefDivide
	case 0x79: // DefShiftLeft
	case 0x7a: // DefShiftRight
	case 0x7b: // DefAnd
	case 0x7c: // DefNAnd
	case 0x7d: // DefOr
	case 0x7e: // DefNOr
	case 0x7f: // DefXOr
	case 0x80: // DefNot
	case 0x81: // DefFindSetLeftBit
	case 0x82: // DefFindSetRightBit
	case 0x83: // DefDerefOf := DerefOfOp ObjReference
		arg := p.pTermArg()
		obj, ok := arg.(Object)
		if !ok {
			return false
		}

		return p.nsCurrent().Append(obj)
	case 0x84: // DefConcatRes
	case 0x85: // DefMod
	case 0x87: // DefSizeOf := SizeOfOp SuperName
		val := p.pSuperName()
		if val == nil {
			return false
		}

		return p.nsCurrent().Append(&fnSizeof{
			val: val,
		})
	case 0x88: // DefIndex := IndexOp BuffPkgStrObj IndexValue Target
		src := p.pTermArg()
		if src == nil {
			return false
		}

		offset := p.pTermArg()
		if offset == nil {
			return false
		}

		dst := p.pTarget()
		if dst == nil {
			return false
		}

		return p.nsCurrent().Append(&fnIndex{
			src:    src,
			offset: offset,
			dst:    dst,
		})
	case 0x89: // DefMatch
	case 0x8e: // DefObjectType
	case 0x90: // DefLAnd
	case 0x91: // DefLOr
	case 0x92: // LnotOp
		// We have already verified that a next byte is available so
		// we can safely ignore the error from ReadByte
		next, _ := p.r.ReadByte()

		switch next {
		case 0x93: // DefLNotEqual
			return p.pCompareOp(fnCompareOpNotEqual)
		case 0x94: // DefLLessEqual
			return p.pCompareOp(fnCompareOpLessThanOrEqual)
		case 0x95: // DefLGreaterEqual
			return p.pCompareOp(fnCompareOpGreaterThanOrEqual)
		default: // DefLNot := LnotOp Operand
			p.r.UnreadByte()
			operand := p.pTermArg()
			if operand == nil {
				return false
			}

			return p.nsCurrent().Append(&fnNot{operand: operand})
		}
	case 0x93: // DefLEqual
		return p.pCompareOp(fnCompareOpEqual)
	case 0x94: // DefLGreater
		return p.pCompareOp(fnCompareOpGreater)
	case 0x95: // DefLLess
		return p.pCompareOp(fnCompareOpLess)
	case 0x96: // DefToBuffer
	case 0x97: // DefToDecimalString
	case 0x98: // DefToHexString
	case 0x99: // DefToInteger
	case 0x9c: // DefToString
	case 0x9d: // DefCopyObject
	case 0x9e: // DefMid
	default: // ObjectReference OR MethodInvocation := NameString TermArgList
		p.r.UnreadByte()
		methodName, ok := p.pNameString()
		if !ok {
			return false
		}

		target := p.objFind(methodName)
		if target == nil {
			return false
		}

		targetMethod, ok := target.(*Method)
		if !ok {
			// This is probably an object reference
			return p.nsCurrent().Append(target)
		}

		argList, ok := p.pTermArgList(targetMethod.argCount)
		if !ok {
			return false
		}

		return p.nsCurrent().Append(&fnCall{
			target: targetMethod,
			args:   argList,
		})
	}

	return false
}

// isNamedObject returns true if op defines a named object.
func (p *parser) isNamedObject(op uint8) bool {
	next, err := p.r.PeekByte()

	switch op {
	case 0x14: // DefMethod (not part of NamedObj; grammar typo?)
	case 0x5b: // ExtOpPrefix
		if err != nil {
			return false
		}

		switch next {
		case 0x01: // DefMutex (not part of NamedObj; grammar typo?)
		case 0x02: // DefEvent (not part of NamedObj; grammar typo?)
		case 0x13: // DefCreateField
		case 0x80: // DefOpRegion
		case 0x81: // DefField (not part of NamedObj; grammar typo?)
		case 0x82: // DefDevice (not part of NamedObj; grammar typo?)
		case 0x83: // DefProcessor
		case 0x84: // DefPowerRes
		case 0x85: // DefThermalZone
		case 0x86: // DefIndexField (not part of NamedObj; grammar typo?)
		case 0x87: // DefBankField
		case 0x88: // DefDataRegion
		default:
			return false
		}

	case 0x8d: // DefCreateBitField
	case 0x8c: // DefCreateByteField
	case 0x8a: // DefCreateDWordField
	case 0x8f: // DefCreateQWordField
	case 0x8b: // DefCreateWordField
	case 0x15: // DefExternal
	default:
		return false
	}

	return true
}

// pNamedObject parses a NamedObject from the AML bytestream and inserts it
// into the current namespace. This method assumes that the caller has
// validated that this is indeed a named object via a call to
// isNamedObject.
func (p *parser) pNamedObject(op uint8) bool {
	var obj Object

	switch op {
	case 0x14: // DefMethod := MethodOp PkgLength NameString MethodFlags TermList
		curOffset := p.r.Offset()
		pkgLen, ok := p.pPkgLength()
		if !ok {
			return false
		}

		methodName, ok := p.pNameString()
		if !ok {
			return false
		}

		flags, err := p.r.ReadByte()
		if err != nil {
			return false
		}

		// According to the spec, Method opens a new scope
		method := &Method{
			scope:      scope{name: methodName},
			argCount:   (flags & 0x7),         // bits[0:2]
			serialized: (flags>>3)&0x1 == 0x1, // bit 3
			syncLevel:  (flags >> 4) & 0xf,    // bits[4:7]
		}

		p.nsCurrent().Append(method)
		p.nsEnter(method)

		// Parse function body
		if !p.pTermList(curOffset + pkgLen) {
			return false
		}

		p.nsExit()
		return true
	case 0x5b: // ExtOpPrefix
		// We have already verified that a next byte is available so
		// we can safely ignore the error from ReadByte
		next, _ := p.r.ReadByte()
		switch next {
		case 0x01: // DefMutex (not part of NamedObj; grammar typo?)
			kfmt.Fprintf(p.errWriter, "DefMutex not implemented")
		case 0x02: // DefEvent (not part of NamedObj; grammar typo?)
			kfmt.Fprintf(p.errWriter, "DefEvent not implemented")
		case 0x13: // DefCreateField
			kfmt.Fprintf(p.errWriter, "DefCreateField not implemented")
		case 0x80: // DefOpRegion := OpRegionOp NameString RegionSpace RegionOffset RegionLen
			name, ok := p.pNameString()
			if !ok {
				return false
			}

			space, err := p.r.ReadByte()
			if err != nil {
				return false
			}

			offset, ok := p.evalAsNumber(p.pTermArg())
			if !ok {
				return false
			}

			length, ok := p.evalAsNumber(p.pTermArg())
			if !ok {
				return false
			}

			obj = &opRegion{
				name:   name,
				space:  regionSpace(space),
				offset: offset,
				length: length,
			}
		case 0x81: // DefField := FieldOp PkgLength NameString FieldFlags FieldList
			curOffset := p.r.Offset()
			pkgLen, ok := p.pPkgLength()
			if !ok {
				return false
			}

			regionName, ok := p.pNameString()
			if !ok {
				return false
			}

			regionObj := p.objFind(regionName)
			if regionObj == nil {
				kfmt.Fprintf(p.errWriter, "defField: could not find region %s", regionName)
				return false
			}

			region, ok := regionObj.(*opRegion)
			if !ok {
				kfmt.Fprintf(p.errWriter, "defField: %s is not a region object", regionName)
				return false
			}

			flags, err := p.r.ReadByte()
			if err != nil {
				return false
			}

			return p.pFieldList(
				curOffset+pkgLen,
				region,
				fieldAccessType(flags&0xf),      // access type; bits[0:3]
				(flags>>4)&0x1 == 0x1,           // lock; bit 4
				fieldUpdateRule((flags>>5)&0x3), // update rule; bits[5:6]
			)
		case 0x82: // DefDevice
			kfmt.Fprintf(p.errWriter, "DefDevice not implemented")
		case 0x83: // DefProcessor
			kfmt.Fprintf(p.errWriter, "DefProcessor not implemented")
		case 0x84: // DefPowerRes
			kfmt.Fprintf(p.errWriter, "DefPowerRes not implemented")
		case 0x85: // DefThermalZone
			kfmt.Fprintf(p.errWriter, "DefThermalZone not implemented")
		case 0x86: // DefIndexField
			kfmt.Fprintf(p.errWriter, "DefIndexField not implemented")
		case 0x87: // DefBankField
			kfmt.Fprintf(p.errWriter, "DefBankField not implemented")
		case 0x88: // DefDataRegion
			kfmt.Fprintf(p.errWriter, "DefDataRegion not implemented")
		}
	case 0x8d: // DefCreateBitField
		kfmt.Fprintf(p.errWriter, "DefCreateBitField not implemented")
	case 0x8c: // DefCreateByteField
		kfmt.Fprintf(p.errWriter, "DefCreateByteField not implemented")
	case 0x8a: // DefCreateDWordField
		kfmt.Fprintf(p.errWriter, "DefCreateDWordField not implemented")
	case 0x8f: // DefCreateQWordField
		kfmt.Fprintf(p.errWriter, "DefCreateDWordField not implemented")
	case 0x8b: // DefCreateWordField
		kfmt.Fprintf(p.errWriter, "DefCreateWordField not implemented")
	case 0x15: // DefExternal
		kfmt.Fprintf(p.errWriter, "DefExternal not implemented")
	}

	return p.nsCurrent().Append(obj)
}

// pFieldList parses a list of FieldElements until the reader reaches maxOffset
// and appends them to the provided opRegion object. A field reference is also
// injected at the current namespace.
//
// Grammar:
// FieldElement := NamedField | ReservedField | AccessField | ExtendedAccessField | ConnectField
// NamedField := NameSeg PkgLength
// ReservedField := 0x00 PkgLength
// AccessField := 0x1 AccessType AccessAttrib
// ConnectField := 0x02 NameString | 0x02 BufferData
// ExtendedAccessField := 0x3 AccessType ExtendedAccessType AccessLength
func (p *parser) pFieldList(maxOffset uint32, region *opRegion, accessType fieldAccessType, lock bool, updateRule fieldUpdateRule) bool {
	var (
		ok              bool
		bitWidth        uint32
		curBitOffset    uint32
		accessAttrib    fieldAccessAttrib
		accessByteCount uint8
		unitName        string
	)

	for p.r.Offset() < maxOffset && !p.r.EOF() {
		next, err := p.r.ReadByte()
		if err != nil {
			return false
		}

		switch next {
		case 0x00: // ReservedField; generated by the Offset() command
			bitWidth, ok = p.pPkgLength()
			if !ok {
				return false
			}

			curBitOffset += bitWidth
			continue
		case 0x1: // AccessField; set access attributes for following fields
			accessType = fieldAccessType(next & 0xf) // access type; bits[0:3]

			attrib, err := p.r.ReadByte()
			if err != nil {
				return false
			}

			// bits[7:6] specify the access attributes:
			//
			// Bits 7:6 - 0 = AccessAttrib = following attribute byte
			//            1 = AccessAttrib = AttribBytes (following byte is the count)
			//            2 = AccessAttrib = AttribRawBytes (following byte is the count)
			//            3 = AccessAttrib = AttribRawProcessBytes (following byte is the count)
			switch (next >> 6) & 0x3 {
			case 0:
				accessByteCount = 0
				accessAttrib = fieldAccessAttrib(attrib)
			case 1:
				accessByteCount = attrib
				accessAttrib = fieldAccessAttribBytes
			case 2:
				accessByteCount = attrib
				accessAttrib = fieldAccessAttribRawBytes
			case 3:
				accessByteCount = attrib
				accessAttrib = fieldAccessAttribRawProcessBytes
			}

			continue
		case 0x2: // ConnectField
			panic("ConnectField: not implemented")
			//if unitName, ok = p.pNameString(); !ok {
			//	return false
			//}
		case 0x3: // ExtendedAccessField
			panic("ExtendedAccessField: not implemented")
			//if unitName, ok = p.pNameString(); !ok {
			//	return false
			//}
		default: // NamedField
			p.r.UnreadByte()
			if unitName, ok = p.pNameString(); !ok {
				return false
			}

			bitWidth, ok = p.pPkgLength()
			if !ok {
				return false
			}

			// According to the spec, the field unit is a child of the region
			// but its name is available at the same scope as the Field command.
			p.nsCurrent().Append(&fieldUnit{
				name:         unitName,
				bitOffset:    curBitOffset,
				bitWidth:     bitWidth,
				lock:         lock,
				updateRule:   updateRule,
				accessType:   accessType,
				accessAttrib: accessAttrib,
				byteCount:    accessByteCount,
				region:       region,
			})

			curBitOffset += bitWidth

		}

	}

	return ok && !p.r.EOF()
}

// pSuperName attempts to pass a SuperName from the AML bytestream.
//
// Grammar:
// SuperName := SimpleName | DebugObj | Type6Opcode
// SimpleName := NameString | ArgObj | LocalObj
// ArgObj := Arg0Op | Arg1Op | Arg2Op | Arg3Op | Arg4Op | Arg5Op | Arg6Op
// LocalObj := Local0Op | Local1Op | Local2Op | Local3Op | Local4Op | Local5Op | Local6Op | Local7Op
// DebugObj := ExtOpPrefix 0x31
// Type6Opcode := DefRefOf | DefDerefOf | DefIndex | UserTermObj
func (p *parser) pSuperName() Object {
	next, err := p.r.ReadByte()
	if err != nil {
		return nil
	}

	switch {
	case next >= 0x60 && next <= 0x67: // LocalArg
		return &fnLocalArg{arg: next - 0x60}
	case next >= 0x68 && next <= 0x6e: // Arg
		return &fnArg{arg: next - 0x68}
	case next == 0x5b: // ExtOpPrefix
		next, err = p.r.ReadByte()
		if err != nil {
			return nil
		}

		switch next {
		case 0x31: // DebugObj
			return &fnDbgObj{}
		}

		return nil
	case next == 0x71: // Type6Opcode DefRefOf
		fmt.Printf("pSuperName: DefRefOf not supported")
	case next == 0x83: // Type6Opcode DefDerefOf
		fmt.Printf("pSuperName: DefDerefOf not supported")
	case next == 0x88: // Type6Opcode DefIndex
		fmt.Printf("pSuperName: DefIndex not supported")
	}

	// If we reached this point then SuperName must be a NameString
	p.r.UnreadByte()
	if name, ok := p.pNameString(); ok {
		return p.objFind(name)
	}

	return nil
}

// pRefName parses a DefName from the AML bytestream and
// inserts it into the current namespace. The caller has
// already read NameOp from the stream.
//
// Grammar:
// DefName := NameOp NameString DataRefObject
// DataRefObject := DataObject | ObjectReference | DDBHandleObject
// DataObject := ComputationalData | DefPackage | DefVarPackage
// ObjectReference := TermArg => ObjectReference | String
// DDBHandleObject := Supername
func (p *parser) pDefName() bool {
	name, ok := p.pNameString()
	if !ok {
		return false
	}

	ns := &scope{name: name}
	p.nsCurrent().Append(ns)

	p.nsEnter(ns)
	ok = p.pTermObj()
	p.nsExit()

	return ok
}

// pRefName parses a DefScope from the AML bytestream. The caller has
// already read ScopeOp from the stream.
func (p *parser) pDefScope() bool {
	curOff := p.r.Offset()
	pkgLen, ok := p.pPkgLength()
	if !ok {
		return false
	}

	name, ok := p.pNameString()
	if !ok {
		return false
	}

	// Apply scope modifier. According to the spec the scope name must
	// have already been defined.
	switch name[0] {
	case '\\': // enter root scope
		p.nsEnter(p.root)
	case '^': // enter parent scope
		parentNs := p.nsCurrent().Parent()
		if parentNs == nil {
			kfmt.Fprintf(p.errWriter, "defScope: already at root NS; %s is not a valid scope", name)
			return false
		}

		p.nsEnter(parentNs)
	default: // lookup scope relative to current namespace and its parents
		relObj := p.objFind(name)
		if relObj == nil {
			kfmt.Fprintf(p.errWriter, "defScope: could not find relative namespace %s", name)
			return false
		}

		relNs, ok := relObj.(Namespace)
		if !ok {
			kfmt.Fprintf(p.errWriter, "defScope: %s is not a namespaced object", name)
			return false
		}

		p.nsEnter(relNs)
	}

	// Parse scoped TermList
	ok = p.pTermList(curOff + pkgLen)

	p.nsExit()
	return ok
}

// pNameString parses a NameString from the AML bytestream.
//
// Grammar:
// NameString := RootChar NamePath | PrefixPath NamePath
// PrefixPath := Nothing | '^' PrefixPath
// NamePath := NameSeg | DualNamePath | MultiNamePath | NullName
func (p *parser) pNameString() (string, bool) {
	var str []byte

	// NameString := RootChar NamePath | PrefixPath NamePath
	next, err := p.r.PeekByte()
	if err != nil {
		return "", false
	}

	switch next {
	case '\\': // RootChar
		str = append(str, next)
		p.r.ReadByte()
	case '^': // PrefixPath := Nothing | '^' PrefixPath
		str = append(str, next)
		for {
			next, err = p.r.PeekByte()
			if err != nil {
				return "", false
			}

			if next != '^' {
				break
			}

			str = append(str, next)
			p.r.ReadByte()
		}
	}

	// NamePath := NameSeg | DualNamePath | MultiNamePath | NullName
	next, err = p.r.ReadByte()
	var readCount int
	switch next {
	case 0x00: // NullName
	case 0x2e: // DualNamePath := DualNamePrefix NameSeg NameSeg
		readCount = 8 // NameSeg x 2
	case 0x2f: // MultiNamePath := MultiNamePrefix SegCount NameSeg(SegCount)
		segCount, err := p.r.ReadByte()
		if segCount == 0 || err != nil {
			return "", false
		}

		readCount = int(segCount) * 4
	default: // NameSeg := LeadNameChar NameChar NameChar NameChar
		str = append(str, next) // LeadNameChar
		readCount = 3           // NameChar x 3
	}

	for ; readCount > 0; readCount-- {
		next, err := p.r.ReadByte()
		if err != nil {
			return "", false
		}

		str = append(str, next)
	}

	return string(str), true
}

// pTarget parses a Target value from the AML bytestream.
//
// Grammar:
// Target := SuperName | NullName
// NullName := 0x00
func (p *parser) pTarget() Object {
	next, err := p.r.PeekByte()
	if err != nil {
		return nil
	}

	if next == 0x00 { // NullName
		p.r.SetOffset(p.r.Offset() + 1)
		return &fnNilObj{}
	}

	return p.pSuperName()
}

// pPkgLength parses a PkgLength value from the AML bytestream.
func (p *parser) pPkgLength() (uint32, bool) {
	lead, err := p.r.ReadByte()
	if err != nil {
		return 0, false
	}

	// The high 2 bits of the lead byte indicate how many bytes follow.
	var pkgLen uint32
	switch lead >> 6 {
	case 0:
		pkgLen = uint32(lead)
	case 1:
		b1, err := p.r.ReadByte()
		if err != nil {
			return 0, false
		}

		// lead bits 0-3 are the lsb of the length nybble
		pkgLen = uint32(b1)<<4 | uint32(lead&0xf)
	case 2:
		b1, err := p.r.ReadByte()
		if err != nil {
			return 0, false
		}

		b2, err := p.r.ReadByte()
		if err != nil {
			return 0, false
		}

		// lead bits 0-3 are the lsb of the length nybble
		pkgLen = uint32(b2)<<12 | uint32(b1)<<4 | uint32(lead&0xf)
	case 3:
		b1, err := p.r.ReadByte()
		if err != nil {
			return 0, false
		}

		b2, err := p.r.ReadByte()
		if err != nil {
			return 0, false
		}

		b3, err := p.r.ReadByte()
		if err != nil {
			return 0, false
		}

		// lead bits 0-3 are the lsb of the length nybble
		pkgLen = uint32(b3)<<20 | uint32(b2)<<12 | uint32(b1)<<4 | uint32(lead&0xf)
	}

	return pkgLen, true
}

// pNumConstant parses a byte/word/dword or qword value from the AML bytestream.
func (p *parser) pNumConstant(numBytes uint8) (uint64, bool) {
	var (
		next byte
		err  error
		res  uint64
	)

	for c := uint8(0); c < numBytes; c++ {
		if next, err = p.r.ReadByte(); err != nil {
			return 0, false
		}

		res = res | (uint64(next) << (8 * c))
	}

	return res, true
}

// pString parses a string from the AML bytestream.
func (p *parser) pString() (string, bool) {
	// Read ASCII chars till we reach a null byte
	var (
		next byte
		err  error
		str  []byte
	)

	for {
		next, err = p.r.ReadByte()
		if err != nil {
			return "", false
		}

		if next == 0x00 {
			break
		} else if next >= 0x01 && next <= 0x7f { // AsciiChar
			str = append(str, next)
		} else {
			return "", false
		}
	}
	return string(str), true
}

// nsCurrent returns the currently active namespace.
func (p *parser) nsCurrent() Namespace {
	if len(p.nsStack) == 0 {
		return p.root
	}

	return p.nsStack[len(p.nsStack)-1]
}

// nsEnter pushes ns to the namespace stack.
func (p *parser) nsEnter(ns Namespace) {
	fmt.Printf("setting namespace %q\n", ns.Name())
	p.nsStack = append(p.nsStack, ns)
}

// nsExit exits the last entered namespace.
func (p *parser) nsExit() {
	fmt.Printf("exiting namespace %q\n", p.nsStack[len(p.nsStack)-1].Name())
	p.nsStack = p.nsStack[:len(p.nsStack)-1]
}

// objFind attempts to find an object with the given name. This method supports
// the following name patterns:
//  - \X.Y.Z : look for Z descending from the root scope (\)
//  - X : look for X in the current namespace and then recursively up the
//  namespace tree.
func (p *parser) objFind(name string) Object {
	switch name[0] {
	case '\\':
		panic(fmt.Errorf("objFind(%q); not implemented", name))
	default:
		for ns := p.nsCurrent(); ns != nil; ns = ns.Parent() {
			for _, child := range ns.Children() {
				if child.Name() == name {
					return child
				}
			}
		}
	}

	// Not found
	return nil
}

// evalAsNumber attempts to evaluate arg as a number. If arg was obtained after
// parsing a Type2Opcode (e.g. a MethodInvocation) then the parser will invoke
// the interpreter to obtain the evaluated value before attempting the number
// conversion.
func (p *parser) evalAsNumber(arg interface{}) (uint64, bool) {
	switch t := arg.(type) {
	case uint64:
		return t, true
	case uint32:
		return uint64(t), true
	case uint16:
		return uint64(t), true
	case uint8:
		return uint64(t), true
	}

	return 0, false
}

/*
func (p *parser) termObj() bool {
	next, err := p.r.ReadByte()
	if err != nil {
		return nil, false
	}

	// Start of namestring
	if next == '\\' || next == '^' ||
		next == '_' || next == '.' || next == '/' ||
		(next >= 'A' && next <= 'Z') {

		// Unshift character and read string
		p.r.SetOffset(p.r.offset - 1)
		return p.pNameString()
	}

	switch next {
	case 0x00, 0x01: // ConstObj -> ZeroOp | OneOp
		return uint64(next), true
	case 0x06: // DefAlias -> AliasOp NameString NameString
		name1, ok1 := p.pNameString()
		name2, ok2 := p.pNameString()
		if !ok1 || !ok2 {
			return nil, false
		}

		return fmt.Sprintf("alias(%q -> %q)", name1, name2), false
	case 0x08: // DefName-> NameOp NameString DataRefObject
		name, ok := p.pNameString()
		if !ok {
			return nil, false
		}

		val, ok := p.pTermObj()
		if !ok {
			return nil, false
		}

		fmt.Printf("def: %s\n", name)

		return &defRef{name: name, value: val}, true
	case 0x0a: // ByteConst -> BytePrefix ByteData
		val, ok := p.scanNum(1)
		return uint8(val), ok
	case 0x0b: // WordConst -> WordPrefix WordData
		val, ok := p.scanNum(2)
		return uint16(val), ok
	case 0x0c: // DWordConst -> DWordPrefix DWordData
		val, ok := p.scanNum(4)
		return uint32(val), ok
	case 0x0d: // String -> StringPrefix AsciiCharList NullChar
		// Read ASCII chars till we reach a null byte
		var str []byte
		for {
			next, err = p.r.ReadByte()
			if err != nil {
				return nil, false
			}

			if next == 0x00 {
				break
			} else if next >= 0x01 && next <= 0x7f { // AsciiChar
				str = append(str, next)
			} else {
				return nil, false
			}
		}
		return string(str), true
	case 0x0e: // QWordConst -> QWordPrefix QWordData
		val, ok := p.scanNum(8)
		return uint64(val), ok
	case 0x10: // DefScope -> ScopeOp PkgLength NameString TermList
		return p.pDefScope()
	case 0x11: // DefBuffer -> BufferOp PkgLength BufferSize ByteList
		return p.pDefBuffer()
	case 0x12: // DefPackage -> PackageOp PkgLength NumElements PackageElementList
		return nil, p.skipPackagedEntity("DefPackage")
	case 0x14: // DefMethod -> MethodOp PkgLength NameString MethodFlags TermList
		return nil, p.skipPackagedEntity("DefMethod")
	case 0x5b: // ExtOpPrefix
		if next, err = p.r.ReadByte(); err != nil {
			return nil, false
		}

		switch next {
		case 0x13: // DefCreateField -> CreateFieldOp SourceBuff BitIndex NumBits NameString
			panic("DefCreateField: not implemented")
		case 0x30: // RevisionOp -> ExtOpPrefix RevisionOp
			return uint64(0), true
		case 0x80: // DefOpRegion -> OpRegionOp NameString RegionSpace RegionOffset RegionLen
			return p.pDefOpRegion()
		case 0x81: // ??? -> DefField -> FieldOp PkgLength NameString FieldFlags FieldList
			return nil, p.skipPackagedEntity("DefField")
		case 0x82: // DefDevice -> DeviceOp PkgLength NameString ObjectList
			return p.pDefDevice()
		case 0x83: // DefProcessor -> ProcessorOp PkgLength NameString ProcID PblkAddr PblkLen ObjectList
			panic("DefProcessor: not implemented")
		case 0x84: // DefPowerRes -> PowerResOp PkgLength NameString SystemLevel ResourceOrder ObjectList
			panic("DefPowerRes: not implemented")
		case 0x85: // DefThermalZone -> ThermalZoneOp PkgLength NameString ObjectList
			panic("DefThermalZone: not implemented")
		case 0x86: // DefIndexField -> IndexFieldOp PkgLength NameString NameString FieldFlags FieldList
			return nil, p.skipPackagedEntity("DefIndexField")
		case 0x87: // DefBankField -> BankFieldOp PkgLength NameString NameString BankKV
			panic("DefBankField: not implemented")
		case 0x88: // DefDataRegion -> DataRegionOp NameString TermArg TermArg TermArg
			panic("DefDataRegion: not implemented")
		default:
			return nil, false
		}
	// 0x8a -> DefCreateDWordField -> CreateDWordFieldOp SourceBuff BitIndex NameString
	// 0x8b -> DefCreateWordField -> CreateWordFieldOp SourceBuff BitIndex NameString
	// 0x8c -> DefCreateByteField -> CreateByteFieldOp SourceBuff BitIndex NameString
	// 0x8d -> DefCreateBitField -> CreateBitFieldOp SourceBuff BitIndex NameString
	case 0x8a, 0x8b, 0x8c, 0x8d:
		var ok bool
		if _, ok = p.pTermObj(); !ok {
			return nil, false
		}

		if _, ok = p.pTermObj(); !ok {
			return nil, false
		}

		if _, ok := p.pNameString(); !ok {
			return nil, false
		}

		return nil, true
	// 0x8f -> DefCreateQWordField -> CreateQWordFieldOp SourceBuff BitIndex NameString
	case 0x8f: //
		panic("DefCreateQWordField: not implemented")
	case 0xa0: // DefIfElse -> IfOp PkgLength Predicate TermList DefIfElse
		return nil, p.skipPackagedEntity("DefIfElse")
	case 0xff: // ConstObj -> OnesOp
		return uint64(1<<64 - 1), true
	}

	return nil, false
}*/
/*
func (i *interpreter) pDefOpRegion() (*OpRegion, bool) {
	// DefOpRegion -> OpRegionOp(consumed by caller) NameString RegionSpace RegionOffset RegionLen
	name, ok := p.pNameString()
	if !ok {
		return nil, false
	}

	space, err := p.r.ReadByte()
	if err != nil {
		return nil, false
	}

	offsetArg, ok := p.pTermObj()
	if !ok {
		return nil, false
	}

	lengthArg, ok := p.pTermObj()
	if !ok {
		return nil, false
	}

	return &OpRegion{
		Name:   name,
		Space:  RegionSpace(space),
		Offset: p.evalTermArgAsNumber(offsetArg),
		Len:    p.evalTermArgAsNumber(lengthArg),
	}, true
}


func (i *interpreter) pDefDevice() (*Device, bool) {
	curOff := p.r.Offset()
	pkgLen, ok := p.pPkgLength()
	if !ok {
		return nil, false
	}

	name, ok := p.pNameString()
	if !ok {
		return nil, false
	}

	list, ok := p.pTermList(curOff + pkgLen)
	if !ok {
		return nil, false
	}

	dev := &Device{
		Namespace:  Namespace{name: name},
		Properties: make(map[string]interface{}, 0),
	}

	for _, item := range list {
		switch t := item.(type) {
		case *Device:
			//dev.ChildDevices = append(dev.ChildDevices, t)
		case *OpRegion:
			dev.Regions = append(dev.Regions, t)
		case *defRef:
			if resTemplate, ok := p.evalResourceTemplate(t.value); ok {
				t.value = resTemplate
			}
			dev.Properties[t.name] = t.value
		}
	}

	p.curNamespace().Append(dev)

	return dev, true
}

func (i *interpreter) pDefBuffer() ([]byte, bool) {
	_, ok := p.pPkgLength()
	if !ok {
		return nil, false
	}

	sizeArg, ok := p.pTermObj()
	if !ok {
		return nil, false
	}

	var (
		size = p.evalTermArgAsNumber(sizeArg)
		buf  []byte
	)

	for ; size > 0; size-- {
		next, err := p.r.ReadByte()
		if err != nil {
			return nil, false
		}

		buf = append(buf, next)
	}

	return buf, true
}
*/

/*

func (i *interpreter) evalResourceTemplate(arg interface{}) (*ResourceTemplate, bool) {
	// arg should be a byte buffer
	data, ok := arg.([]byte)
	if !ok {
		return nil, false
	}

	// Calculate checksum
	var checksum uint8
	for _, b := range data {
		checksum += b
	}

	var (
		res       = &ResourceTemplate{}
		resTagLen int
	)
	for index := 0; index < len(data); index += resTagLen {
		// Bit 7 will be cleared for a small resource DT and set for a
		// large resource DT
		switch (data[index] >> 7) & 0x1 {
		case 0: // small resource data type
			resTagLen = int(data[index]&0x7) + 1

			switch data[index] {
			case 0x79: // End tag (always the last tag)
				// index+1 contains a checksum value. If not zero
				// then adding it to the checksum value should yield 0.
				// If the field is zero then no checksum is required
				if data[index+1] != 0 && checksum+data[index+1] != 0 {
					return nil, false
				}
			case 0x22: // IRQ (use default options: edge/active-high/exclusive)
				// index+1 is a mask for IRQ 0-7 and index+2 is a mask for IRQ 8-15
				var (
					irqNum  uint8
					irqMask = uint16(data[index+2])<<8 | uint16(data[index+1])
				)

				for mask := uint16(1); irqMask&mask == 0; mask, irqNum = mask<<1, irqNum+1 {
				}

				res.IRQ = append(res.IRQ, &IRQResource{
					Number:   irqNum,
					Mode:     IRQModeEdgeTriggered,
					Polarity: IRQPolarityActiveHigh,
					Sharing:  IRQSharingExclusive,
					Wake:     IRQWakeNotCapable,
				})
			case 0x23: // IRQ with options
				// index+1 is a mask for IRQ 0-7 and index+2 is a mask for IRQ 8-15
				var (
					irqNum  uint8
					irqMask = uint16(data[index+2])<<8 | uint16(data[index+1])
				)

				for mask := uint16(1); irqMask&mask == 0; mask, irqNum = mask<<1, irqNum+1 {
				}

				res.IRQ = append(res.IRQ, &IRQResource{
					Number:   irqNum,
					Mode:     IRQMode(data[index+3] & 0x1),
					Polarity: IRQPolarity((data[index+3] >> 3) & 0x1),
					Sharing:  IRQSharing((data[index+3] >> 4) & 0x1),
					Wake:     IRQWake((data[index+3] >> 5) & 0x1),
				})
			case 0x2a: // DMA
				// index+1 is a mask for DMA chan 0-7
				var dmaChan uint8
				for mask := uint8(1); data[index+1]&mask == 0; mask, dmaChan = mask<<1, dmaChan+1 {
				}

				res.DMA = append(res.DMA, &DMAResource{
					Channel:      dmaChan,
					Speed:        DMASpeed((data[index] + 2>>5) & 0x3),
					BusStatus:    DMABusStatus((data[index+2] >> 2) & 0x1),
					TransferPref: DMATransferPref(data[index+2] & 0x3),
				})
			case 0x47: // IO port
				ioPort := &IOPortResource{
					DecodeType:           IOPortDecodeType(data[index+1] & 0x1),
					MinBaseAddr:          uint16(data[index+3])<<8 | uint16(data[index+2]),
					MaxBaseAddr:          uint16(data[index+5])<<8 | uint16(data[index+4]),
					MinBaseAddrAlignment: data[index+6],
					PortRange:            data[index+7],
				}
				ioPort.Fixed = ioPort.MinBaseAddr == ioPort.MaxBaseAddr

				res.IOPort = append(res.IOPort, ioPort)
			case 0x4b: // Fixed location IO port (10-bit addressing)
				ioPort := &IOPortResource{
					DecodeType: IOPortDecodeType10,
					// index+1 contains bits[7:0] and index+2 contains bits [9:8]
					MinBaseAddr: uint16(data[index+2]&0x3)<<8 | uint16(data[index+1]),
					PortRange:   data[index+3],
				}
				ioPort.MaxBaseAddr = ioPort.MinBaseAddr
				ioPort.Fixed = true

				res.IOPort = append(res.IOPort, ioPort)
			}
		case 1: // large resource data type
			resTagLen = int(data[index+2])<<8 | int(data[index+1])

			switch data[index] {
			case 0x86: // 32-bit Fixed-Location Memory Range
				res.MemRange = append(res.MemRange, &MemRangeResource{
					Permissions: MemRangePerm(data[index+3] & 0x1),
					BaseAddr:    uint64(data[index+7])<<24 | uint64(data[index+6])<<16 | uint64(data[index+5])<<8 | uint64(data[index+4]),
					Length:      uint64(data[index+11])<<24 | uint64(data[index+10])<<16 | uint64(data[index+9])<<8 | uint64(data[index+8]),
				})
			}
		}
	}

	return res, true
}

func (i *interpreter) skipPackagedEntity(name string) bool {
	curOff := p.r.Offset()
	pkgLen, ok := p.pPkgLength()
	if !ok {
		return false
	}

	p.r.SetOffset(curOff + pkgLen)
	//fmt.Printf("[skip] %q (%d bytes)\n", name, pkgLen)
	return true
}

*/
