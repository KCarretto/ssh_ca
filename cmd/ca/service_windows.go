// +build windows

package main

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
)

var elog debug.Log
var started bool

func logRequests(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elog.Info(80, fmt.Sprintf("[HTTP] %s from %s", r.RequestURI, r.RemoteAddr))
		fn.ServeHTTP(w, r)
	}
}

func (m *Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}
	fasttick := time.Tick(500 * time.Millisecond)
	slowtick := time.Tick(2 * time.Second)
	tick := fasttick

	server := &http.Server{
		Addr:    ":8080",
		Handler: logRequests(m.HTTP()),
	}
	var wg sync.WaitGroup

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		select {
		case <-tick:
			if !started {
				started = true
				wg.Add(1)
				go func() {
					defer wg.Done()
					if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
						elog.Error(1, fmt.Sprintf("HTTP server failed: %s", err.Error()))
					}
				}()
			}

		case c := <-r:
			switch c.Cmd {
			case svc.Interrogate:
				changes <- c.CurrentStatus
				// Testing deadlock from https://code.google.com/p/winsvc/issues/detail?id=4
				time.Sleep(100 * time.Millisecond)
				changes <- c.CurrentStatus
			case svc.Stop, svc.Shutdown:
				break loop
			case svc.Pause:
				changes <- svc.Status{State: svc.Paused, Accepts: cmdsAccepted}
				tick = slowtick
				elog.Warning(1, fmt.Sprintf("%s Service Paused (NOTE: This service still functions while paused)", svcName))
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				tick = fasttick
				elog.Info(1, fmt.Sprintf("%s Service Resumed", svcName))
			default:
				elog.Error(1, fmt.Sprintf("unexpected control request #%d", c))
			}
		}
	}
	changes <- svc.Status{State: svc.StopPending}
	server.Shutdown(context.Background())
	wg.Wait()
	return
}

func runService(name string, isDebug bool) {
	var err error
	if isDebug {
		elog = debug.New(name)
	} else {
		elog, err = eventlog.Open(name)
		if err != nil {
			return
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s Service", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	caSvc := &Service{
		Log: func(msg string) { elog.Info(22, msg) },
	}
	caSvc.loadKey()
	caSvc.loadPassword()

	err = run(name, caSvc)
	if err != nil {
		elog.Error(1, fmt.Sprintf("%s Service Failed: %v", name, err))
		return
	}
	elog.Info(1, fmt.Sprintf("Stopped %s Service", name))
}
