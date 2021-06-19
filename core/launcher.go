package core

type Launcher struct {
	args []string
}

func (l *Launcher) AddArg(arg string) {
	l.args = append(l.args, arg)
}

func (l *Launcher) AddArgs(args []string) {
	l.args = append(l.args, args...)
}

func (l *Launcher) Run() error {
	i, err := newInstance(l.args)
	if err != nil {
		return err
	}
	i.Run()
	return nil
}

func (l *Launcher) RunDetached() error {
	i, err := newInstance(l.args)
	if err != nil {
		return err
	}
	go i.Run()
	return nil
}
