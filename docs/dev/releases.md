# Releases

This doc explains how to build, test and release ingress controllers.

## Building

All ingress controllers are build through a Makefile. Depending on your
requirements you can build a raw server binary, a local container image,
or push an image to a remote repository.

Build a raw server binary
```console
$ make controller
```

Build a local container image
```console
$ make container
```

Push the container image to a remote repository
```console
$ make push TAG=0.0 PREFIX=$USER/ingress-controller
```

## Dependencies

The build should use dependencies in the `ingress/vendor` directory.
Occasionally, you might need to update the dependencies.

```console
$ godep version
godep v74 (linux/amd64/go1.6.1)
$ go version
go version go1.6.1 linux/amd64
```

This will automatically save godeps to `vendor/`
```console
$ godep save ./...
```

If you have an older version of `godep`
```console
$ go get github.com/tools/godep
$ cd $GOPATH/src/github.com/tools/godep
$ go build -o godep *.go
```

If you have an older version of `go`
```console
$ GO15VENDOREXPERIMENT=1 godep save ./...
```

To update a particular dependency, eg: Kubernetes
```console
cd $GOPATH/src/github.com/kubernetes/ingress
godep restore
go get -u github.com/kubernetes/kubernetes
cd $GOPATH/src/github.com/kubernetes/kubernetes
godep restore
cd $GOPATH/src/github/kubernetes/ingress
rm -rf Godeps
godep save ./...
git [add/remove] as needed
git commit
```

## Testing

To run unittets, enter each directory in `controllers/`
```console
$ cd $GOPATH/src/k8s.io/ingress/controllers/gce
$ go test ./...
```

If you have access to a Kubernetes cluster, you can also run e2e tests
```console
$ cd $GOPATH/src/k8s.io/kubernetes
$ ./hack/ginkgo-e2e.sh --ginkgo.focus=Ingress.* --delete-namespace-on-failure=false
```

TODO: add instructions on running integration tests, or e2e against
local-up/minikube.

## Releasing

All Makefiles will produce a release binary, as shown above. To publish this
to a wider Kubernetes user base, push the image to a container registry, like
[gcr.io](https://cloud.google.com/container-registry/). All release images are hosted under `gcr.io/google_containers` and
tagged according to a [semver](http://semver.org/) scheme.

An example release might look like:
```
$ make push TAG=0.8.0 PREFIX=gcr.io/google_containers/glbc
```

In addition to publishing an image, please update the [release](https://help.github.com/articles/creating-releases/)
page with a short description of the major changes that correspond to a given
tag, and the source code at the commit hash corresponding to the release.


