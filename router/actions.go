package router

type Action uint8

var (
	ActionDirect  Action = 0
	ActionDefault Action = 1
	ActionReject  Action = 2
)
