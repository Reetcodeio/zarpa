package item

// Job is work for a scanner worker: either a ready buffer (Item.Content set)
// or a file to read (File set), described by the Template item.
type Job struct {
	Template Item
	File     string
	Read     ReadOptions
}

// Default read limits.
const (
	DefaultMaxFile  = 5 << 20   // 5 MB read whole
	TranscriptMax   = 512 << 20 // AI transcripts are streamed up to 512 MB
	TranscriptChunk = 4 << 20
)
