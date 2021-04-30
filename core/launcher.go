package core

type InstanceBuilder struct {
	args []string
}

func (l *InstanceBuilder) AddArg(arg string) {
	l.args = append(l.args, arg)
}

func (l *InstanceBuilder) AddArgs(args []string) {
	l.args = append(l.args, args...)
}

func (l *InstanceBuilder) Create() (Instance, error) {
	return createInstance(l.args)
}
