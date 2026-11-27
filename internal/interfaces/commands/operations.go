package commands

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
)

// Kinds are the operator commands of design section 07, one for each kind of operation on a whole
// principal (Identity ADR 0007).
var Kinds = []string{"disable", "enable", "erase"}

// Operation is what an operator gives an operator command: the principal, the reason and the
// operator's own name. A command only records the operation; the jobs of the running instances carry
// it out (design section 07).
type Operation struct {
	Kind      string
	Principal string
	Reason    string
	Operator  string
}

// ParseOperation reads the command line args of the operator command kind, and returns the
// configuration file that it names and the operation. It refuses a command line that lacks one of
// them, and writes the usage to out.
func ParseOperation(kind string, args []string, out io.Writer) (configPath string, operation Operation, err error) {
	flags := flag.NewFlagSet("identity "+kind, flag.ContinueOnError)
	flags.SetOutput(out)
	path := flags.String("config", "", "the configuration file that Ansible renders")
	principal := flags.String("principal", "", "the identifier of the principal")
	reason := flags.String("reason", "", "why the operator "+kind+"s the principal")
	operator := flags.String("operator", "", "the operator's name")
	if err := flags.Parse(args); err != nil {
		return "", Operation{}, err
	}
	if flags.NArg() > 0 {
		return "", Operation{}, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	var missing []string
	for _, required := range []struct{ name, value string }{
		{"-config", *path}, {"-principal", *principal}, {"-reason", *reason}, {"-operator", *operator},
	} {
		if required.value == "" {
			missing = append(missing, required.name)
		}
	}
	if len(missing) > 0 {
		err := errors.New("identity " + kind + " requires " + strings.Join(missing, ", "))
		fmt.Fprintln(out, err)
		flags.Usage()
		return "", Operation{}, err
	}
	return *path, Operation{Kind: kind, Principal: *principal, Reason: *reason, Operator: *operator}, nil
}
