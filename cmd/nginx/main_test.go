/*
Copyright 2017 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/fake"

	"k8s.io/ingress-nginx/internal/ingress/controller"
	"k8s.io/ingress-nginx/internal/nginx"
)

func TestCreateApiserverClient(t *testing.T) {
	_, err := createApiserverClient("", "", "")
	if err == nil {
		t.Fatal("Expected an error creating REST client without an API server URL or kubeconfig file.")
	}
}

func init() {
	// the default value of nginx.TemplatePath assumes the template exists in
	// the root filesystem and not in the rootfs directory
	path, err := filepath.Abs(filepath.Join("../../rootfs/", nginx.TemplatePath))
	if err == nil {
		nginx.TemplatePath = path
	}
}

func TestHandleSigterm(t *testing.T) {
	const (
		podName   = "test"
		namespace = "test"
	)

	clientSet := fake.NewSimpleClientset()

	createConfigMap(clientSet, namespace, t)

	pod := corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
		},
	}

	_, err := clientSet.CoreV1().Pods(namespace).Create(context.TODO(), &pod, metav1.CreateOptions{})
	if err != nil {
		t.Fatalf("error creating pod %v: %v", pod, err)
	}

	resetForTesting(func() { t.Fatal("bad parse") })

	os.Setenv("POD_NAME", podName)
	os.Setenv("POD_NAMESPACE", namespace)

	oldArgs := os.Args

	defer func() {
		os.Setenv("POD_NAME", "")
		os.Setenv("POD_NAMESPACE", "")
		os.Args = oldArgs
	}()

	os.Args = []string{"cmd", "--default-backend-service", "ingress-nginx/default-backend-http", "--http-port", "0", "--https-port", "0"}
	_, conf, err := parseFlags()
	if err != nil {
		t.Errorf("Unexpected error creating NGINX controller: %v", err)
	}
	conf.Client = clientSet

	ngx := controller.NewNGINXController(conf, nil)

	go handleSigterm(ngx, func(code int) {
		if code != 1 {
			t.Errorf("Expected exit code 1 but %d received", code)
		}
	})

	time.Sleep(1 * time.Second)

	t.Logf("Sending SIGTERM to PID %d", syscall.Getpid())
	err = syscall.Kill(syscall.Getpid(), syscall.SIGTERM)
	if err != nil {
		t.Error("Unexpected error sending SIGTERM signal.")
	}
}

func startKidProcess() (int, error) {
	cmd := exec.Command("sleep", "5m")
	err := cmd.Start()
	return cmd.Process.Pid, err
}

func TestHandleSigchld(t *testing.T) {
	go handleSigchld()

	const children_count = 5
	var pids []int
	for i := 0; i < children_count; i++ {
		pid, err := startKidProcess()
		if err != nil {
			t.Error("Cannot start children command: ", err)
			return
		}
		pids = append(pids, pid)
	}
	t.Logf("Children PIDS: %v", pids)
	time.Sleep(1 * time.Second)

	for _, pid := range pids {
		err := syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			t.Error("Unexpected error sending SIGKILL signal.")
		} else {
			t.Logf("%d killed", pid)
		}
	}

	checkZombie := time.Tick(1 * time.Second)
	timeoutTimer := time.NewTimer(5 * time.Second)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			t.Error("Timeout!. Zombie process still there")
			return
		case <-checkZombie:
			deadChildren := 0
			for _, pid := range pids {
				if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); os.IsNotExist(err) {
					deadChildren += 1
					t.Logf("Process %d die", pid)
				}
			}
			if len(pids) == deadChildren {
				t.Log("All Processes cleaned")
				return
			}
		}
	}
}

func TestHandleSigchldWithMonitoredChildren(t *testing.T) {
	go handleSigchld()

	const children_count = 5
	var pids []int
	pid, err := startKidProcess()
	if err != nil {
		t.Error("Cannot start children command: ", err)
		return
	}
	pids = append(pids, pid)

	monitoredCmdIsRunning := true
	monitoredCmd := exec.Command("sleep", "5m")
	err = monitoredCmd.Start()
	if err != nil {
		t.Error("Cannot start monitoed children command: ", err)
		return
	}
	go func() {
		monitoredCmd.Wait()
		monitoredCmdIsRunning = false
	}()

	pid, err = startKidProcess()
	if err != nil {
		t.Error("Cannot start children command: ", err)
		return
	}
	pids = append(pids, pid)

	for _, pid := range pids {
		err := syscall.Kill(pid, syscall.SIGKILL)
		if err != nil {
			t.Error("Unexpected error sending SIGKILL signal.")
		} else {
			t.Logf("%d killed", pid)
		}
	}

	checkZombie := time.Tick(1 * time.Second)
	timeoutTimer := time.NewTimer(5 * time.Second)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-timeoutTimer.C:
			t.Error("Timeout!. Zombie process still there")
			return
		case <-checkZombie:
			deadChildren := 0
			for _, pid := range pids {
				if _, err := os.Stat("/proc/" + strconv.Itoa(pid)); os.IsNotExist(err) {
					deadChildren += 1
					t.Logf("Process %d die", pid)
				}
			}
			if len(pids) == deadChildren && monitoredCmdIsRunning {
				t.Log("All Processes cleaned and the monitored process is running fine")
				return
			}
		}
	}
}

func createConfigMap(clientSet kubernetes.Interface, ns string, t *testing.T) string {
	t.Helper()

	configMap := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:     "config",
			SelfLink: fmt.Sprintf("/api/v1/namespaces/%s/configmaps/config", ns),
		},
	}

	cm, err := clientSet.CoreV1().ConfigMaps(ns).Create(context.TODO(), configMap, metav1.CreateOptions{})
	if err != nil {
		t.Errorf("error creating the configuration map: %v", err)
	}

	return cm.Name
}
