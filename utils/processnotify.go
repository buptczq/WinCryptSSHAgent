package utils

import (
	"fmt"
	"github.com/bi-zone/wmi"
)

const (
	PROCESS_CREATE = iota
	PROCESS_DELETE
	PROCESS_MODIFY
	PROCESS_ERROR
)

const processEventQuery = `
SELECT * FROM __InstanceOperationEvent
WITHIN 1
WHERE
TargetInstance ISA 'Win32_Process'
AND TargetInstance.Name='%s'`

type ProcessEvent struct {
	Type        int
	Error       error
	TimeStamp   uint64
	ProcessId   uint32
	Name        string
	CommandLine string
}

type wmiProcessEvent struct {
	TimeStamp uint64 `wmi:"TIME_CREATED"`
	System    struct {
		Class string
	} `wmi:"Path_"`
	Instance win32Process `wmi:"TargetInstance"`
}

type win32Process struct {
	ProcessId   uint32
	Name        string
	CommandLine string
}

type ProcessNotify struct {
	q      *wmi.NotificationQuery
	events chan wmiProcessEvent
	ch     chan<- *ProcessEvent
}

func NewProcessNotify(name string, ch chan<- *ProcessEvent) (*ProcessNotify, error) {
	events := make(chan wmiProcessEvent)
	q, err := wmi.NewNotificationQuery(events, fmt.Sprintf(processEventQuery, name))
	if err != nil {
		return nil, err
	}
	return &ProcessNotify{
		q:      q,
		events: events,
		ch:     ch,
	}, nil
}

func (s *ProcessNotify) Start() {
	done := make(chan error, 1)

	go func() {
		done <- s.q.StartNotifications()
	}()

	go s.dispatch(done)
}

func (s *ProcessNotify) Stop() {
	s.q.Stop()
}

func (s *ProcessNotify) dispatch(done chan error) {
	for {
		select {
		case ev := <-s.events:
			event := &ProcessEvent{
				TimeStamp:   ev.TimeStamp,
				ProcessId:   ev.Instance.ProcessId,
				Name:        ev.Instance.Name,
				CommandLine: ev.Instance.CommandLine,
			}
			switch ev.System.Class {
			case "__InstanceCreationEvent":
				event.Type = PROCESS_CREATE
			case "__InstanceDeletionEvent":
				event.Type = PROCESS_DELETE
			default:
				event.Type = PROCESS_MODIFY
			}
			s.ch <- event
		case err := <-done:
			event := &ProcessEvent{
				Type:  PROCESS_ERROR,
				Error: err,
			}
			s.ch <- event
			return
		}
	}

}
