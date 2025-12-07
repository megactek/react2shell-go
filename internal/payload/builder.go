package payload

type Payload struct {
	Body        string
	ContentType string
}

type Builder interface {
	Build() Payload
}

