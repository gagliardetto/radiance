package sbf

type AlignedMemory struct {
	maxLen         int
	alignOffset    int
	mem            []byte
	zeroUpToMaxLen bool
}
