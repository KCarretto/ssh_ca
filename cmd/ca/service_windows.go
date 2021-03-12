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

func logRequests(fn http.Handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		elog.Info(
			LogEventHTTPRequest,
			fmt.Sprintf("[HTTP] %s from %s", r.RequestURI, r.RemoteAddr),
		)
		fn.ServeHTTP(w, r)
	}
}

func (m *Service) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown | svc.AcceptPauseAndContinue
	changes <- svc.Status{State: svc.StartPending}

	server := &http.Server{
		Addr:    ":8080",
		Handler: logRequests(m.HTTP()),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		elog.Info(LogEventGeneral, "HTTP Server Listening on :8080")
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			elog.Error(LogEventGeneral, fmt.Sprintf("HTTP server failed: %s", err.Error()))
		}
	}()

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
loop:
	for {
		select {
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
				elog.Warning(LogEventServiceSignal, fmt.Sprintf("%s Service Paused (NOTE: This service still functions while paused)", svcName))
			case svc.Continue:
				changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
				elog.Info(LogEventServiceSignal, fmt.Sprintf("%s Service Resumed", svcName))
			default:
				elog.Error(LogEventServiceSignal, fmt.Sprintf("unexpected control request #%d", c))
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

	elog.Info(LogEventServiceSignal, fmt.Sprintf("Starting %s Service", name))
	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	caSvc := &Service{
		Log: func(msg string) { elog.Info(LogEventStateChange, msg) },
	}
	if err := caSvc.loadKey(); err != nil {
		elog.Error(LogEventGeneral, fmt.Sprintf("[FATAL] Failed to load CA key (consider restoring from a backup or delete the file on disk and restart the service to rotate the CA key): %v", err))
		panic(err)
	}
	if err := caSvc.loadPassword(); err != nil {
		elog.Error(LogEventGeneral, fmt.Sprintf("Failed to load CA service password: %v", err))
	}

	err = run(name, caSvc)
	if err != nil {
		elog.Error(LogEventGeneral, fmt.Sprintf("%s Service Failed: %v", name, err))
		return
	}
	elog.Info(LogEventServiceSignal, fmt.Sprintf("Stopped %s Service", name))
}
