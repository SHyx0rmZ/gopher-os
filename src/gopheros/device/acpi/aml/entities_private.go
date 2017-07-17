package aml

type scope struct {
	name     string
	parent   Namespace
	children []Object
}

func (s *scope) Name() string          { return s.name }
func (s *scope) Parent() Namespace     { return s.parent }
func (s *scope) setParent(p Namespace) { s.parent = p }

func (s *scope) Children() []Object {
	return s.children
}

func (s *scope) Append(obj Object) bool {
	if obj == nil {
		return false
	}

	obj.setParent(s)
	s.children = append(s.children, obj)
	return true
}

func (s *scope) removeLast() Object {
	if len(s.children) == 0 {
		return nil
	}

	numElem := len(s.children)
	obj := s.children[numElem-1]
	s.children = s.children[:numElem-1]

	return obj
}

type alias struct {
	name   string
	parent Namespace
	target Object
}

func (a *alias) Name() string          { return a.name }
func (a *alias) Parent() Namespace     { return a.parent }
func (a *alias) setParent(p Namespace) { a.parent = p }

type dataObject struct {
	name   string
	parent Namespace
	data   interface{}
}

func (d *dataObject) Name() string          { return d.name }
func (d *dataObject) Parent() Namespace     { return d.parent }
func (d *dataObject) setParent(p Namespace) { d.parent = p }

type fieldAccessType uint8

const (
	fieldAccessTypeAny fieldAccessType = iota
	fieldAccessTypeByte
	fieldAccessTypeWord
	fieldAccessTypeDword
	fieldAccessTypeQword
)

type fieldUpdateRule uint8

const (
	fieldUpdateRulePreserve fieldUpdateRule = iota
	fieldUpdateRuleWriteAsOnes
	fieldUpdateRuleWriteAsZeros
)

type fieldAccessAttrib uint8

const (
	fieldAccessAttribQuick            fieldAccessAttrib = 0x02
	fieldAccessAttribSendReceive                        = 0x04
	fieldAccessAttribByte                               = 0x06
	fieldAccessAttribWord                               = 0x08
	fieldAccessAttribBlock                              = 0x0a
	fieldAccessAttribBytes                              = 0x0b // byteCount contains the number of bytes
	fieldAccessAttribProcessCall                        = 0x0c
	fieldAccessAttribBlockProcessCall                   = 0x0d
	fieldAccessAttribRawBytes                           = 0x0e // byteCount contains the number of bytes
	fieldAccessAttribRawProcessBytes                    = 0x0f // byteCount contains the number of bytes
)

type fieldUnit struct {
	name string

	bitOffset uint32
	bitWidth  uint32

	lock       bool
	updateRule fieldUpdateRule

	// accessAttrib is valid if accessType is BufferAcc
	// for the SMB or GPIO OpRegions.
	accessAttrib fieldAccessAttrib
	accessType   fieldAccessType

	// byteCount is valid when accessAttrib is one of:
	// Bytes, RawBytes or RawProcessBytes
	byteCount uint8

	region *opRegion
}

func (f *fieldUnit) Name() string      { return f.name }
func (*fieldUnit) Parent() Namespace   { return nil }
func (*fieldUnit) setParent(Namespace) {}

type regionSpace uint8

const (
	regionSpaceSystemMemory regionSpace = iota
	regionSpaceSystemIO
	regionSpacePCIConfig
	regionSpaceEmbeddedControl
	regionSpaceSMBus
	regionSpacePCIBarTarget
	regionSpaceIPMI
)

type opRegion struct {
	name   string
	parent Namespace
	space  regionSpace
	offset uint64
	length uint64
}

func (o *opRegion) Name() string          { return o.name }
func (o *opRegion) Parent() Namespace     { return o.parent }
func (o *opRegion) setParent(p Namespace) { o.parent = p }

// fnOpcode is the base for the various method-related opcodes.
type fnOpcode struct{}

func (*fnOpcode) Name() string        { return "" }
func (*fnOpcode) Parent() Namespace   { return nil }
func (*fnOpcode) setParent(Namespace) {}

type fnLocalArg struct {
	fnOpcode

	arg uint8
}

type fnArg struct {
	fnOpcode

	arg uint8
}

type fnDbgObj struct {
	fnOpcode
}

type fnNilObj struct {
	fnOpcode
}

type fnStore struct {
	fnOpcode

	dst Object
	val interface{}
}

type fnReturn struct {
	fnOpcode

	val interface{}
}

type fnSizeof struct {
	fnOpcode

	val interface{}
}

type fnAdd struct {
	fnOpcode

	operands [2]interface{}
	dst      Object
}

type fnSub struct {
	fnOpcode

	operands [2]interface{}
	dst      Object
}

type fnInc struct {
	fnOpcode

	operand Object
}

type fnDec struct {
	fnOpcode

	operand Object
}

type fnCall struct {
	fnOpcode

	target *Method
	args   []interface{}
}

type fnBuffer struct {
	fnOpcode

	size interface{}
	data []byte
}

type fnIfElse struct {
	scope

	predicate interface{}
}

type fnCompareOp uint8

const (
	fnCompareOpEqual fnCompareOp = iota
	fnCompareOpNotEqual
	fnCompareOpLess
	fnCompareOpLessThanOrEqual
	fnCompareOpGreater
	fnCompareOpGreaterThanOrEqual
)

type fnCompare struct {
	fnOpcode

	operator fnCompareOp
	operands [2]interface{}
}

type fnNot struct {
	fnOpcode
	operand interface{}
}

type fnWhile struct {
	scope

	predicate interface{}
}

type fnIndex struct {
	fnOpcode

	src    interface{}
	offset interface{}
	dst    Object
}
