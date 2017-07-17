package aml

type Object interface {
	Name() string
	Parent() Namespace
	setParent(Namespace)
}

type Namespace interface {
	Object

	Children() []Object
	Append(Object) bool
	removeLast() Object
}

type Method struct {
	// Methods are scoped items
	scope

	argCount   uint8
	serialized bool
	syncLevel  uint8
}

/*
type IRQMode uint8

const (
	IRQModeLevelTriggered IRQMode = iota
	IRQModeEdgeTriggered
)

type IRQPolarity uint8

const (
	IRQPolarityActiveHigh IRQPolarity = iota
	IRQPolarityActiveLow
)

type IRQSharing uint8

const (
	IRQSharingExclusive IRQSharing = iota
	IRQSharingShared
)

type IRQWake uint8

const (
	IRQWakeNotCapable IRQWake = iota
	IRQWakeCapable
)

type IRQResource struct {
	Number   uint8
	Mode     IRQMode
	Polarity IRQPolarity
	Sharing  IRQSharing
	Wake     IRQWake
}

type DMASpeed uint8

const (
	DMASpeedCompatMode DMASpeed = iota
	DMASpeedTypeA
	DMASpeedTypeB
	DMASpeedTypeF
)

type DMABusStatus uint8

const (
	DMABusStatusMaster DMABusStatus = iota
	DMABusStatusNotMaster
)

type DMATransferPref uint8

const (
	DMATransferPrefOnly8 DMATransferPref = iota
	DMATransferPref8And16
	DMATransferPrefOnly16
)

type DMAResource struct {
	Channel      uint8
	Speed        DMASpeed
	BusStatus    DMABusStatus
	TransferPref DMATransferPref
}

type IOPortDecodeType uint8

const (
	IOPortDecodeType16 IOPortDecodeType = iota
	IOPortDecodeType10
)

type IOPortGranularity uint8

const (
	IOPortGranularityUnknown IOPortGranularity = iota
	IOPortGranularityByte
	IOPortGranularityWord
	IOPortGranularityDword
	IOPortGranularityQword
)

type IOPortResource struct {
	DecodeType           IOPortDecodeType
	MinBaseAddrAlignment uint8
	MinBaseAddr          uint16
	MaxBaseAddr          uint16
	PortRange            uint8

	// Fixed indicates that this is a fixed (non-movable) IO range. In this
	// case MinBaseAddr == MaxBaseAddr.
	Fixed bool
}

type MemRangePerm uint8

const (
	MemRangePermRO MemRangePerm = iota
	MemRangePermRW
)

type MemRangeResource struct {
	Permissions MemRangePerm

	BaseAddr uint64
	Length   uint64
}

type ResourceTemplate struct {
	IRQ      []*IRQResource
	DMA      []*DMAResource
	IOPort   []*IOPortResource
	MemRange []*MemRangeResource
}*/
